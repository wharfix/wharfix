extern crate actix_web;
extern crate clap;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
extern crate time;
extern crate tokio;
extern crate uuid;
extern crate linereader;
extern crate tempdir;


use actix_web::http::StatusCode;
use std::collections::HashMap;
use std::string::String;

use actix_web::{App, HttpServer, middleware, Responder, web};

use crate::actix_web::dev::Service;
use actix_web::dev::{HttpResponseBuilder};
use std::path::{PathBuf};
use std::fs;
use walkdir::WalkDir;
use std::str::FromStr;

use crate::errors::{MainError, RepoError};

use tempdir::TempDir;
use git2::Repository;

use std::process::{Command, Output};
use crate::exec::{SpawnOk, CommandWrapped};
use crate::exec::Wait;
use std::io::BufRead;
use linereader::LineReader;

use std::sync::RwLock;
use git2::build::CheckoutBuilder;
use std::path::Path;

mod errors;
mod exec;
mod log;

static mut SERVE_TYPE: Option<ServeType> = None;

lazy_static! {
    static ref BLOBS: RwLock<HashMap<String, BlobInfo>> = RwLock::new(HashMap::new());
}

#[derive(Deserialize)]
struct FetchInfo {
    #[allow(dead_code)]
    name: String,
    reference: String
}

#[derive(Clone)]
struct BlobInfo {
    content_type: String,
    path: PathBuf,
}

enum ServeType {
    Repo(Repository),
    Path(PathBuf),
}

fn main() {

    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("path")
        .long("path")
        .help("Path to directory of static docker image specs")
        .takes_value(true)
        .required_unless("repo"))
    .arg(clap::Arg::with_name("repo")
        .long("repo")
        .help("URL to git repository")
        .takes_value(true)
        .required_unless("path"))
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

        let tmp_dir = TempDir::new("wharfix").or_else(|e| Err(RepoError::IO(Box::new(e)))).unwrap();
        let serve_type = Some(match m {
           m if m.is_present("path") => ServeType::Path(fs::canonicalize(PathBuf::from_str(m.value_of("path").unwrap()).unwrap().as_path())
               .or(Err(MainError::ArgParse("cmdline arg 'path' doesn't look like an actual path")))?),
           m if m.is_present("repo") => ServeType::Repo(repo_clone(m.value_of("repo").unwrap(), &tmp_dir)
               .or_else(|e| Err(MainError::RepoClone(e)))?),
           _ => panic!("clap should ensure this never happens")
        });

        unsafe {
            SERVE_TYPE = serve_type;
        }

        listen(listen_address, listen_port)
            .or_else(|e| Err(MainError::ListenBind(e)))

    }() {
        log::error("startup error", &e);
    }
}

fn get_serve_root<'l>(info: &FetchInfo, tmp_dir: &'l TempDir) -> Result<PathBuf, RepoError> {
    use git2::{FetchPrune, FetchOptions};

    unsafe {
        Ok(match SERVE_TYPE.as_ref().unwrap() { // will never be None
            ServeType::Path(p) => p.clone(),
            ServeType::Repo(r) => {
                let refs: &[&str] = &[];
                let mut fo = FetchOptions::new();
                fo.prune(FetchPrune::On);
                r.find_remote("origin").unwrap().fetch(refs, Some(&mut fo), None);
                repo_checkout(&r, &info.reference, tmp_dir)?;
                tmp_dir.path().to_path_buf()
            }
        })
    }
}

#[actix_rt::main]
async fn listen(listen_address: String, listen_port: u16) -> std::io::Result<()>{
    log::info(&format!("start listening on port: {}", listen_port));

    HttpServer::new(|| {
        App::new()
            .wrap_fn(|req, srv| {
                log::new_request();
                log::data("request", &json!({ "endpoint": format!("{}", req.path()) }));
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

async fn version() -> impl Responder {
    HttpResponseBuilder::new(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .finish()
}

async fn manifest(info: web::Path<FetchInfo>) -> impl Responder {
    let not_found = HttpResponseBuilder::new(StatusCode::NOT_FOUND).header("Docker-Distribution-API-Version", "registry/2.0").finish();
    let internal_error = HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR).header("Docker-Distribution-API-Version", "registry/2.0").finish();

    match nix_build(&info).await {
        Ok(path) => {
            let fq: PathBuf = path.join("manifest.json");
            match fs::read_to_string(&fq) {
                Ok(manifest) => {
                        blob_discovery(&path.join("blobs"));
                        HttpResponseBuilder::new(StatusCode::OK)
                                .header("Docker-Distribution-API-Version", "registry/2.0")
                                .header("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
                                .body(&manifest)
                },
                Err(e) => {
                    log::error(&format!("failed to read manifest for image: {name}, {reference}", name=info.name, reference=info.reference), &e);
                    return internal_error;
                }
            }
        },
        Err(RepoError::Git(git2::ErrorCode::NotFound)) => {
            log::info(&format!("git ref: {reference} not found for image: {name}", name=info.name, reference=info.reference));
            return not_found;
        },
        Err(e) => {
            log::error(&format!("unknown error for image: {name}, {reference}", name=info.name, reference=info.reference), &e);
            return internal_error;
        }
    }
}

async fn blob(info: web::Path<FetchInfo>) -> impl Responder {
    let blob_info = {
        match BLOBS.read().unwrap().get(&info.reference) {
            Some(blob_info) => Some(blob_info.clone()),
            None => None
        }
    };

    match blob_info {
        Some(blob_info) => {
            match fs::read(&blob_info.path) {
                Ok(blob) => {
                    HttpResponseBuilder::new(StatusCode::OK)
                        .header("Docker-Distribution-API-Version", "registry/2.0")
                        .header("Content-Type", blob_info.content_type.as_str())
                        .body(blob)
                },
                Err(e) => {
                    log::error(&format!("failed to read blob: {digest}", digest=&info.reference), &e);
                    HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR).header("Docker-Distribution-API-Version", "registry/2.0").finish()
                }
            }
        },
        None => {
            HttpResponseBuilder::new(StatusCode::NOT_FOUND)
                .header("Docker-Distribution-API-Version", "registry/2.0")
                .finish()
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

async fn nix_build<'l>(info: &FetchInfo) -> Result<PathBuf, RepoError> {
    use tempfile::NamedTempFile;
    use std::io::{self, Write};

    let tmp_dir = TempDir::new("wharfix").or_else(|e| Err(RepoError::IO(Box::new(e)))).unwrap();
    let path = get_serve_root(&info, &tmp_dir)?;
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

fn repo_clone(url: &str, tmp_dir: &TempDir) -> Result<Repository, RepoError> {
    Ok(Repository::clone(url, tmp_dir).or_else(|e| Err(RepoError::Git(e.code())))?)
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
