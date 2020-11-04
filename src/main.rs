extern crate actix_web;
extern crate clap;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate mysql;
extern crate time;
extern crate tokio;
extern crate uuid;
extern crate linereader;
extern crate tempdir;
extern crate regex;

use actix_web::http::StatusCode;
use std::collections::HashMap;
use std::string::String;

use actix_web::{App, HttpServer, middleware, Responder, web, FromRequest, HttpRequest, HttpResponse, Error};

use crate::actix_web::dev::Service;
use actix_web::dev::{HttpResponseBuilder};
use std::path::{PathBuf};
use std::fs;
use walkdir::WalkDir;
use std::str::FromStr;

use crate::errors::{MainError, RepoError, DockerErrorContext};

use tempdir::TempDir;
use git2::Repository;

use std::process::{Command, Output};
use crate::exec::SpawnOk;
use crate::exec::Wait;
use linereader::LineReader;

use std::sync::RwLock;
use git2::build::CheckoutBuilder;

use futures::future::{ok, err, Ready};

use regex::Regex;
use mysql::Pool;
use crate::mysql::prelude::Queryable;

mod errors;
mod exec;
mod log;

static mut SERVE_TYPE: Option<ServeType> = None;
static mut TARGET_DIR: Option<PathBuf> = None;

lazy_static! {
    static ref BLOBS: RwLock<HashMap<String, BlobInfo>> = RwLock::new(HashMap::new());
}

#[derive(Clone, Deserialize)]
pub struct FetchInfo {
    #[allow(dead_code)]
    pub name: String,
    pub reference: String
}

#[derive(Clone)]
struct BlobInfo {
    content_type: String,
    path: PathBuf,
}

enum ServeType {
    Database(Pool),
    Repo(String),
    Path(PathBuf),
}

enum Delivery {
    Repo(Repository),
    Path(PathBuf),
}

struct Registry {
    #[allow(dead_code)]
    name: String,
    delivery: Delivery,
}

use crate::errors::{DockerError};

impl ServeType {
    fn to_registry(host: &str) -> Result<Registry, DockerError> {
        lazy_static! {
            static ref RE: Regex = Regex::new("([a-zA-Z0-9-]{3,64})\\.wharfix\\.dev(:[0-9]+)?").unwrap();
        }

        let serve_type = unsafe {
            SERVE_TYPE.as_ref().ok_or(DockerError::snafu("serve type unwrap error, this shouldn't happen :("))
        }?;
        let name = RE.captures(host).and_then(|c| c.get(1)).ok_or(DockerError::repository_name_malformed())?.as_str();

        Ok(match serve_type {
              ServeType::Database(pool) => {
                  let mut conn = pool.get_conn().or_else(|e| Err(DockerError::unknown("failed to get database connection", e)))?;
                  let res = conn.exec_first("SELECT repourl FROM registry WHERE name = :name AND enabled = true AND destroyed IS NULL", params! { name }).or_else(|e| Err(DockerError::unknown("database query error", e)))?;
                  let repo_url = res.ok_or(DockerError::repository_unknown())?;
                  Registry { name: name.to_string(), delivery: Delivery::Repo(repo_open(name, &repo_url).or_else(|e| Err(DockerError::unknown("failed to open repository", e)))?) }
              },
              ServeType::Repo(repo_url) => Registry { name: name.to_string(), delivery: Delivery::Repo(repo_open(name, repo_url).or_else(|e| Err(DockerError::unknown("failed to open repository", e)))?) },
              ServeType::Path(path) => Registry { name: name.to_string(), delivery: Delivery::Path(path.clone()) }
        })
    }
}

impl FromRequest for Registry {
    type Error = DockerError;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let host = req.headers().get("HOST").and_then(|hv| hv.to_str().ok()).unwrap_or("");
        match ServeType::to_registry(host) {
            Ok(r) => ok(r),
            Err(e) => err(e)
        }
    }
}


fn main() {

    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("path")
        .long("path")
        .help("Path to directory of static docker image specs")
        .takes_value(true)
        .required_unless_one(&["repo", "dbconnfile"]))
    .arg(clap::Arg::with_name("repo")
        .long("repo")
        .help("URL to git repository")
        .takes_value(true)
        .required_unless_one(&["path", "dbconnfile"]))
    .arg(clap::Arg::with_name("dbconnfile")
        .long("dbconnfile")
        .help("Path to file from which to read db connection details")
        .takes_value(true)
        .required_unless_one(&["path", "repo"]))
    .arg(clap::Arg::with_name("target")
        .long("target")
        .help("Target path in which to checkout repos")
        .default_value("/tmp/wharfix")
        .required(false))
    .arg(clap::Arg::with_name("address")
        .long("address")
        .help("Listen address to open on <port>")
        .default_value("0.0.0.0")
        .required(false))
    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on <address>")
        .default_value("8088")
        .required(true));

    if let Err(e) = || -> Result<(), MainError> {

        let m = args.get_matches();
        let listen_address = m.value_of("address").unwrap().to_string();
        let listen_port: u16 = m.value_of("port")
            .ok_or(MainError::ArgParse("Missing cmdline arg 'port'"))?.parse()
            .or(Err(MainError::ArgParse("cmdline arg 'port' doesn't look like a port number")))?;

        let target_dir = PathBuf::from_str(m.value_of("target").unwrap()).unwrap();
        fs::create_dir(&target_dir).or_else(|e| -> Result<(), std::io::Error> {
            match e.kind() {
                std::io::ErrorKind::AlreadyExists => Ok(()),
                e => panic!(format!("couldn't create target dir: {:?}, error: {:?}", target_dir, e))
            }
        }).unwrap();

        let serve_type = Some(match m {
           m if m.is_present("path") => ServeType::Path(fs::canonicalize(PathBuf::from_str(m.value_of("path").unwrap()).unwrap().as_path())
               .or(Err(MainError::ArgParse("cmdline arg 'path' doesn't look like an actual path")))?),
           m if m.is_present("repo") => ServeType::Repo(m.value_of("repo").unwrap().to_string()),
           m if m.is_present("dbconnfile") => ServeType::Database(db_connect(PathBuf::from_str(m.value_of("dbconnfile").unwrap()).unwrap())),
           _ => panic!("clap should ensure this never happens")
        });

        unsafe {
            TARGET_DIR = Some(fs::canonicalize(target_dir).unwrap());
            SERVE_TYPE = serve_type;
        }

        listen(listen_address, listen_port)
            .or_else(|e| Err(MainError::ListenBind(e)))

    }() {
        log::error("startup error", &e);
    }
}

fn db_connect(creds_file: PathBuf) -> Pool {
    Pool::new(fs::read_to_string(&creds_file).unwrap()).unwrap()
}

fn get_serve_root<'l>(registry: &Registry, info: &FetchInfo, tmp_dir: &'l TempDir) -> Result<PathBuf, RepoError> {
    use git2::{FetchPrune, FetchOptions};

    Ok(match &registry.delivery {
        Delivery::Repo(r) => {
            let refs: &[&str] = &[];
            let mut fo = FetchOptions::new();
            fo.prune(FetchPrune::On);
            r.find_remote("origin")?.fetch(refs, Some(&mut fo), None)?;
            repo_checkout(&r, &info.reference, tmp_dir)?;
            tmp_dir.path().to_path_buf()
        },
        Delivery::Path(p) => p.clone()
    })

}

#[actix_rt::main]
async fn listen(listen_address: String, listen_port: u16) -> std::io::Result<()>{
    log::info(&format!("start listening on port: {}", listen_port));

    HttpServer::new(|| {
        App::new()
            .wrap_fn(|req, srv| {
                log::new_request();
                let host = req.headers().get("HOST").and_then(|hv| hv.to_str().ok()).unwrap_or("");
                log::data("request", &json!({ "endpoint": format!("{}", req.path()), "host": host }));
                srv.call(req)
            })
            .wrap(middleware::Compress::default())
            .route("/v2", web::get().to(version))
            .route("/v2/{name}/manifests/{reference}", web::get().to(manifest))
            .route("/v2/{name}/blobs/{reference}", web::get().to(blob))
    })
        .bind(format!("{listen_address}:{listen_port}", listen_address=listen_address, listen_port=listen_port))?
        .run()
        .await
}

async fn version(_registry: Registry) -> impl Responder {
    HttpResponseBuilder::new(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .finish()
}

struct WharfixManifest(String);

impl Responder for WharfixManifest {
    type Error = Error;
    type Future = Ready<Result<HttpResponse, Error>>;

    fn respond_to(self, _req: &HttpRequest) -> Self::Future {
        use futures::future::ready;

        ready(Ok(HttpResponse::Ok()
            .header("Docker-Distribution-API-Version", "registry/2.0")
            .content_type("application/vnd.docker.distribution.manifest.v2+json")
            .body(&self.0)))
    }
}

async fn manifest(registry: Registry, info: web::Path<FetchInfo>) -> Result<WharfixManifest, DockerError> {

    match nix_build(&registry, &info).await {
        Ok(path) => {
            let fq: PathBuf = path.join("manifest.json");
            match fs::read_to_string(&fq) {
                Ok(manifest) => {
                        blob_discovery(&path.join("blobs"));
                        Ok(WharfixManifest(manifest))
                },
                Err(e) => {
                    log::error(&format!("failed to read manifest for image: {name}, {reference}", name=info.name, reference=info.reference), &e);
                    Err(e.manifest_context())
                }
            }
        },
        Err(e) => Err(e.manifest_context())
    }
}

struct WharfixBlob {
    blob: Vec<u8>,
    content_type: String
}

impl Responder for WharfixBlob {
    type Error = Error;
    type Future = Ready<Result<HttpResponse, Error>>;

    fn respond_to(self, _req: &HttpRequest) -> Self::Future {
        use futures::future::ready;

        ready(Ok(HttpResponse::Ok()
            .header("Docker-Distribution-API-Version", "registry/2.0")
            .content_type(self.content_type.as_str())
            .body(self.blob)))
    }
}


async fn blob(info: web::Path<FetchInfo>) -> Result<WharfixBlob, DockerError> {
    let blob_info = {
        match BLOBS.read().unwrap().get(&info.reference) {
            Some(blob_info) => Some(blob_info.clone()),
            None => None
        }
    };

    match blob_info {
        Some(blob_info) => {
            match fs::read(&blob_info.path) {
                Ok(blob) => Ok(WharfixBlob{
                    content_type: blob_info.content_type.clone(),
                    blob
                }),
                Err(e) => {
                    log::error(&format!("failed to read blob: {digest}", digest=&info.reference), &e);
                    Err(e.blob_context())
                }
            }
        },
        None => {
            Err(DockerError::blob_unknown(&info.reference))
        }
    }


}

fn blob_discovery(path: &PathBuf) {
    for entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()).filter(|e| e.path() != path.as_path()) {
        if let Some(file_name) = entry.file_name().to_str() {
            let parts: Vec<&str> = file_name.split('.').collect();
            BLOBS.write().unwrap().insert(format!("sha256:{digest}", digest=parts[0]), BlobInfo{
                content_type: String::from(match parts[1] {
                    "tar" => "application/vnd.docker.image.rootfs.diff.tar",
                    "json" => "application/vnd.docker.container.image.v1+json",
                    _ => "application/octet-stream",
                }),
                path: entry.path().to_path_buf()
            });
        }
    }
}

async fn nix_build<'l>(registry: &Registry, info: &FetchInfo) -> Result<PathBuf, RepoError> {
    use tempfile::NamedTempFile;
    use std::io::Write;

    let tmp_dir = TempDir::new("wharfix").or_else(|e| Err(RepoError::IO(Box::new(e)))).unwrap();
    let path = get_serve_root(&registry, &info, &tmp_dir)?;
    let fq: PathBuf = path.join("default.nix");

    let mut drv_file = NamedTempFile::new().unwrap();
    drv_file.write_all(include_bytes!("../drv.nix")).unwrap();

    let mut cmd = Command::new("nix-build");
    let mut child = cmd
        .arg("--no-out-link")
        .arg("--arg")
        .arg("indexFile")
        .arg(&fq.to_str().unwrap())
        .arg(&drv_file.path())
        .arg("-A")
        .arg(&info.name)
        .spawn_ok()?;

    let out: Output = child.wait_for_output()?;
    let mut line_bytes = vec!();
    let mut reader = LineReader::new(&out.stdout[..]);
    while let Some(line) = reader.next_line() {
        line_bytes = line.expect("read error").to_vec();
    }

    let stringed = String::from_utf8(line_bytes).unwrap();
    Ok(PathBuf::from_str(stringed.trim_end()).unwrap())
}

fn repo_open(name: &str, url: &String) -> Result<Repository, RepoError> {
    use git2::build::RepoBuilder;

    let root_dir = unsafe { TARGET_DIR.as_ref().unwrap() };
    let clone_target = root_dir.join(pathname_generator(name, url));

    Ok(if clone_target.exists() {
        Repository::open_bare(&clone_target).or_else(|e| Err(RepoError::Git(e.code())))
    } else {
        log::info(&format!("registry, url: {}, {} - does not have an active clone, cloning into: {:?}", &name, &url, &clone_target));
        let mut rb = RepoBuilder::new();
        rb.bare(true);
        rb.clone(url, &clone_target).or_else(|e| Err(RepoError::Git(e.code())))
    }?)
}

fn pathname_generator<'l>(name: &str, url: &str) -> String {
    use crypto::sha2::Sha256;
    use crypto::digest::Digest;

    let mut hasher = Sha256::new();
    hasher.input_str(format!("{}{}", name, url).as_str());
    format!("{}-{}", hasher.result_str(), name)
}

fn repo_checkout(repo: &Repository, reference: &String, tmp_dir: &TempDir) -> Result<(), RepoError> {
    let tmp_path = tmp_dir.path();

    let mut cb = CheckoutBuilder::new();
    cb.force();
    cb.update_index(false);
    cb.target_dir(tmp_path);

    let obj = repo.revparse_single(reference.as_str()).or_else(|_| {
        let rev = format!("refs/remotes/origin/{reference}",reference=&reference);
        repo.revparse_single(rev.as_str()).or_else(|e| Err(RepoError::Git(e.code())))
    })?;
    repo.checkout_tree(&obj, Some(&mut cb)).or_else(|e| Err(RepoError::Git(e.code())))?;
    Ok(())
}
