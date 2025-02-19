use actix_web::http::StatusCode;
use std::collections::HashMap;
use std::string::String;

use actix_web::{
    middleware, web, App, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder,
};

use actix_web::body::BoxBody;
use actix_web::dev::Service;
use actix_web::HttpResponseBuilder;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

use crate::errors::{DockerErrorContext, MainError, RepoError};

use git2::Cred;
use git2::FetchOptions;
use git2::FetchPrune;
use git2::RemoteCallbacks;
use git2::Repository;
use tempdir::TempDir;

use async_process::Stdio;
use async_process::{Command, Output};
use linereader::LineReader;

use git2::build::CheckoutBuilder;
use std::sync::RwLock;

use futures::future::{err, ok, Ready};

use regex::Regex;

use std::ffi::OsStr;
use tempfile::NamedTempFile;

extern crate log;
extern crate pretty_env_logger;

use lazy_static::lazy_static;
use serde::Deserialize;
use serde_json::json;

use async_stream::stream;
use get_chunk::iterator::FileIter;
use std::fs::File;

#[cfg(feature = "mysql")]
use mysql::{params, prelude::Queryable, Pool};

mod cli;
mod errors;

use std::sync::OnceLock;

static ADD_NIX_GCROOTS: OnceLock<bool> = OnceLock::new();
static INDEX_FILE_IS_BUILDABLE: OnceLock<bool> = OnceLock::new();
static SERVE_TYPE: OnceLock<Option<ServeType>> = OnceLock::new();
static TARGET_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static BLOB_CACHE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static SUBSTITUTERS: OnceLock<Option<String>> = OnceLock::new();
static INDEX_FILE_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
static SSH_PRIVATE_KEY: OnceLock<Option<PathBuf>> = OnceLock::new();

const CONTENT_TYPE_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const CONTENT_TYPE_DIFFTAR: &str = "application/vnd.docker.image.rootfs.diff.tar";
const CONTENT_TYPE_CONTAINER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const CONTENT_TYPE_UNKNOWN: &str = "application/octet-stream";

const FD_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

lazy_static! {
    static ref BLOBS: RwLock<HashMap<String, BlobInfo>> = RwLock::new(HashMap::new());
}

#[derive(Clone, Deserialize)]
pub struct FetchInfo {
    #[allow(dead_code)]
    pub name: String,
    pub reference: String,
}

#[derive(Clone)]
struct BlobInfo {
    name: String,
    content_type: String,
    path: PathBuf,
}

enum ServeType {
    #[cfg(feature = "mysql")]
    Database(Pool),
    Repo(String),
    Path(PathBuf),
    Derivation(String),
}

enum ManifestDelivery {
    Repo(Repository),
    Path(PathBuf),
    Derivation(String),
}

enum BlobDelivery {
    Memory,
    Persistent(PathBuf),
}

struct Registry {
    #[allow(dead_code)]
    name: String,
    manifest_delivery: ManifestDelivery,
    blob_delivery: BlobDelivery,
}

impl Registry {
    async fn prepare(&self, temp_dir: &Path, info: &FetchInfo) -> Result<PathBuf, RepoError> {
        self.manifest_delivery.prepare(temp_dir, info).await
    }
    async fn index(&self, serve_root: &Path, info: &FetchInfo) -> Result<(), RepoError> {
        self.manifest_delivery.index(serve_root, info).await
    }
    async fn manifest(&self, serve_root: &Path, info: &FetchInfo) -> Result<PathBuf, DockerError> {
        self.manifest_delivery.manifest(serve_root, info).await
    }
    async fn blob(&self, info: &FetchInfo) -> Result<BlobInfo, DockerError> {
        self.blob_delivery.blob(info)
    }
    async fn blob_discovery(&self, path: &Path) {
        self.blob_delivery.discover(path).await;
    }
    async fn store_blob(&self, info: BlobInfo, is_gc_rootable: bool) {
        self.blob_delivery.store_blob(info, is_gc_rootable).await;
    }
}

impl ManifestDelivery {
    async fn prepare(&self, tmp_dir: &Path, info: &FetchInfo) -> Result<PathBuf, RepoError> {
        match self {
            Self::Repo(r) => {
                let refs: &[&str] = &[];
                let mut fo = fetch_options();
                fo.prune(FetchPrune::On);
                r.find_remote("origin")?.fetch(refs, Some(&mut fo), None)?;
                repo_checkout(&r, &info.reference, &tmp_dir)?;
                Ok(tmp_dir.to_path_buf())
            }
            Self::Path(p) => Ok(p.clone()),
            Self::Derivation(output) => {
                lazy_static! {
                    static ref RE: Regex = Regex::new("^[a-z0-9._-]{32,128}$").unwrap();
                }
                let derivation_file = PathBuf::from(format!("/nix/store/{}.drv", &info.reference));
                if !RE.is_match(&info.reference) {
                    Err(RepoError::ImageNotFound)
                } else if !derivation_file.exists()
                    || !nix_derivation_info(&derivation_file)
                        .await
                        .has_output(&output)
                {
                    Err(RepoError::ImageNotFound)
                } else {
                    Ok(derivation_file)
                }
            }
        }
    }
    async fn index(&self, serve_root: &Path, info: &FetchInfo) -> Result<(), RepoError> {
        match self {
            ManifestDelivery::Repo(_) | ManifestDelivery::Path(_) => {
                let fq: PathBuf = serve_root.join(
                    INDEX_FILE_PATH
                        .get()
                        .unwrap()
                        .as_ref()
                        .map(|i| i.to_str().unwrap())
                        .unwrap(),
                );
                log::info!("looking for indexfile at {:?}", &fq);

                let mut cmd = Command::new("nix-instantiate");
                let child = cmd
                    .arg("--eval")
                    .arg("-E")
                    .arg(format!(
                        "builtins.hasAttr \"{}\" (import {} {})",
                        &info.name,
                        &fq.to_str().unwrap(),
                        "{}"
                    ))
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();

                let out: Output = child.output().await.unwrap();
                let mut line_bytes = vec![];
                let mut reader = LineReader::new(&out.stdout[..]);
                while let Some(line) = reader.next_line() {
                    line_bytes = line.expect("read error").to_vec();
                }

                if String::from_utf8(line_bytes).unwrap().trim() == "false" {
                    Err(RepoError::IndexAttributeNotFound)?
                };
                Ok(())
            }
            ManifestDelivery::Derivation(_) => Ok(()),
        }
    }
    async fn manifest(&self, serve_root: &Path, info: &FetchInfo) -> Result<PathBuf, DockerError> {
        use std::io::Write;

        let mut cmd = Command::new("nix-build");
        cmd.arg("--no-out-link");
        if SUBSTITUTERS.get().unwrap().is_some() {
            cmd.arg("--option");
            cmd.arg("substituters");
            cmd.arg(SUBSTITUTERS.get().unwrap().as_ref().unwrap());
        }

        let mut drv_file = NamedTempFile::new().unwrap();
        let child = match self {
            Self::Repo(_) | ManifestDelivery::Path(_) => {
                let fq: PathBuf = serve_root.join(
                    INDEX_FILE_PATH
                        .get()
                        .unwrap()
                        .as_ref()
                        .map(|i| i.to_str().unwrap())
                        .unwrap(),
                );
                if *INDEX_FILE_IS_BUILDABLE.get().unwrap() {
                    cmd.arg(&fq.to_str().unwrap()).arg("-A").arg(&info.name)
                } else {
                    drv_file.write_all(include_bytes!("../drv.nix")).unwrap();
                    cmd.arg("--arg")
                        .arg("indexFile")
                        .arg(&fq.to_str().unwrap())
                        .arg(&drv_file.path())
                        .arg("-A")
                        .arg(&info.name)
                }
            }
            Self::Derivation(output) => cmd.arg(&serve_root).arg("-A").arg(&output),
        }
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

        let out: Output = child.output().await.unwrap();
        let mut line_bytes = vec![];
        let mut reader = LineReader::new(out.stdout.as_slice());
        while let Some(line) = reader.next_line() {
            line_bytes = line.expect("read error").to_vec();
        }

        let stringed = String::from_utf8(line_bytes).unwrap();
        Ok(PathBuf::from_str(stringed.trim_end()).unwrap())
    }
}

async fn nix_add_root(gc_root_path: &Path, store_path: &Path) -> Result<(), RepoError> {
    let mut cmd = Command::new("nix-store");
    cmd.arg("--add-root")
        .arg(gc_root_path)
        .arg("--indirect")
        .arg("-r")
        .arg(store_path);

    let exit_status = cmd.spawn()?.status().await?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(errors::RepoError::Exec(exit_status))
    }
}

fn get_bucket_prefix(name: &str) -> &str {
    let parts: Vec<&str> = name.split(':').collect();
    let subject = if parts.len() > 1 { parts[1] } else { parts[0] };
    subject.get(0..2).unwrap()
}

impl BlobDelivery {
    async fn store_blob(&self, info: BlobInfo, is_gc_rootable: bool) {
        use std::io::ErrorKind;
        use std::os::unix::fs;

        match self {
            BlobDelivery::Memory => {
                BLOBS.write().unwrap().insert(info.name.clone(), info);
            }
            BlobDelivery::Persistent(dir) => {
                let bucket_prefix = get_bucket_prefix(&info.name);
                let bucket_dir = dir.join(&bucket_prefix);
                std::fs::create_dir_all(&bucket_dir).unwrap();
                let cache_path = bucket_dir.join(&info.name);
                match fs::symlink(&info.path, &cache_path) {
                    Ok(_) => {}
                    Err(e) => {
                        if e.kind() != ErrorKind::AlreadyExists {
                            log::error!("error caching: {}, {:#?}", &info.name, &e);
                        }
                    }
                }
                if is_gc_rootable && *ADD_NIX_GCROOTS.get().unwrap() {
                    nix_add_root(&cache_path, &info.path)
                        .await
                        .or_else(|e| {
                            log::error!("error caching: {}, {:#?}", &info.name, &e);
                            Err(e)
                        })
                        .unwrap();
                }
            }
        }
    }

    async fn discover(&self, path: &Path) {
        // traverse blob path to discover new blobs
        for entry in WalkDir::new(&path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path() != path)
        {
            let file_name = PathBuf::from(entry.file_name());
            let parts: Vec<&str> = file_name.to_str().unwrap().split('.').collect();
            let name = format!("sha256:{digest}", digest = parts[0]);
            self.store_blob(
                BlobInfo {
                    name,
                    content_type: file_name_to_content_type(&file_name).to_string(),
                    path: entry.path().to_path_buf(),
                },
                false,
            )
            .await;
        }
    }
    fn blob(&self, info: &FetchInfo) -> Result<BlobInfo, DockerError> {
        match self {
            Self::Memory => match BLOBS.read().unwrap().get(&info.reference) {
                Some(blob_info) => Ok(blob_info.clone()),
                None => Err(DockerError::blob_unknown(&info.reference)),
            },
            Self::Persistent(path) => {
                let bucket_prefix = get_bucket_prefix(&info.reference);
                let bucket_dir = path.join(&bucket_prefix);

                let bucket_full_path = path.join(&bucket_dir).join(&info.reference);
                let legacy_full_path = path.join(&info.reference);

                let canonical_path = match fs::canonicalize(&bucket_full_path) {
                    Ok(p) => Ok(p),
                    Err(_) => fs::canonicalize(&legacy_full_path), // fallback to non-bucketed path
                }
                .map_err(|e| e.blob_context(&info))?;

                Ok(BlobInfo {
                    name: info.reference.to_string(),
                    content_type: file_name_to_content_type(&canonical_path),
                    path: canonical_path,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
struct Derivation {
    file: HashMap<String, DerivationInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct DerivationInfo {
    outputs: HashMap<String, serde_json::Value>,
}

impl Derivation {
    fn has_output(&self, output: &str) -> bool {
        self.file
            .values()
            .next()
            .map(|f| f.outputs.get(output).is_some())
            .unwrap_or(false)
    }
}

async fn nix_derivation_info(derivation_file: &Path) -> Derivation {
    let mut cmd = Command::new("nix");
    cmd.arg("show-derivation").arg(derivation_file);
    cmd.stdout(Stdio::piped());
    let child = cmd.spawn().unwrap();
    let bytes = child.output().await.unwrap().stdout;
    let out: Derivation = serde_json::from_slice(&bytes).unwrap();
    out
}

use crate::errors::DockerError;

impl ServeType {
    fn to_registry(host: &str) -> Result<Registry, DockerError> {
        let serve_type = SERVE_TYPE
            .get()
            .unwrap()
            .as_ref()
            .ok_or(DockerError::snafu(
                "serve type unwrap error, this shouldn't happen :(",
            ))?;
        let name = host;

        let blob_delivery = BLOB_CACHE_DIR
            .get()
            .unwrap()
            .as_ref()
            .map(|dir| BlobDelivery::Persistent(dir.clone()))
            .unwrap_or(BlobDelivery::Memory);

        Ok(match serve_type {
            #[cfg(feature = "mysql")]
            ServeType::Database(pool) => {
                lazy_static! {
                    static ref RE: Regex =
                        Regex::new("([a-zA-Z0-9-]{3,64})\\.wharfix\\.dev(:[0-9]+)?").unwrap();
                }
                let name = RE
                    .captures(host)
                    .and_then(|c| c.get(1))
                    .ok_or(DockerError::repository_name_malformed())?
                    .as_str();

                let mut conn = pool.get_conn().or_else(|e| {
                    Err(DockerError::unknown("failed to get database connection", e))
                })?;
                let res = conn.exec_first("SELECT repourl FROM registry WHERE name = :name AND enabled = true AND destroyed IS NULL", params! { name }).or_else(|e| Err(DockerError::unknown("database query error", e)))?;
                let repo_url = res.ok_or(DockerError::repository_unknown())?;
                Registry {
                    name: name.to_string(),
                    blob_delivery,
                    manifest_delivery: ManifestDelivery::Repo(
                        repo_open(name, &repo_url).or_else(|e| {
                            Err(DockerError::unknown("failed to open repository", e))
                        })?,
                    ),
                }
            }
            ServeType::Repo(repo_url) => Registry {
                name: name.to_string(),
                blob_delivery,
                manifest_delivery: ManifestDelivery::Repo(
                    repo_open(name, repo_url)
                        .or_else(|e| Err(DockerError::unknown("failed to open repository", e)))?,
                ),
            },
            ServeType::Path(path) => Registry {
                name: name.to_string(),
                blob_delivery,
                manifest_delivery: ManifestDelivery::Path(path.clone()),
            },
            ServeType::Derivation(output) => Registry {
                name: name.to_string(),
                blob_delivery,
                manifest_delivery: ManifestDelivery::Derivation(output.to_owned()),
            },
        })
    }
}

impl FromRequest for Registry {
    type Error = DockerError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let host = req
            .headers()
            .get("HOST")
            .and_then(|hv| hv.to_str().ok())
            .unwrap_or("");
        match ServeType::to_registry(host) {
            Ok(r) => ok(r),
            Err(e) => err(e),
        }
    }
}

fn main() {
    pretty_env_logger::init();

    if let Err(e) = || -> Result<(), MainError> {
        let m = cli::build_cli().get_matches();
        let listen_address = m.get_one::<String>("address").unwrap().to_string();
        let listen_port: u16 = m
            .get_one::<String>("port")
            .ok_or(MainError::ArgParse("Missing cmdline arg 'port'"))?
            .parse()
            .or(Err(MainError::ArgParse(
                "cmdline arg 'port' doesn't look like a port number",
            )))?;

        let target_dir = PathBuf::from_str(m.get_one::<String>("target").unwrap()).unwrap();
        fs::create_dir(&target_dir)
            .or_else(|e| -> Result<(), std::io::Error> {
                match e.kind() {
                    std::io::ErrorKind::AlreadyExists => Ok(()),
                    e => panic!(
                        "{}",
                        &format!(
                            "couldn't create target dir: {:?}, error: {:?}",
                            target_dir, e
                        )
                    ),
                }
            })
            .unwrap();

        let serve_type = Some(match &m {
            m if m.contains_id("path") => ServeType::Path(
                fs::canonicalize(
                    PathBuf::from_str(m.get_one::<String>("path").unwrap())
                        .unwrap()
                        .as_path(),
                )
                .or(Err(MainError::ArgParse(
                    "cmdline arg 'path' doesn't look like an actual path",
                )))?,
            ),
            m if m.contains_id("repo") => {
                ServeType::Repo(m.get_one::<String>("repo").unwrap().to_string())
            }
            #[cfg(feature = "mysql")]
            m if m.contains_id("dbconnfile") => ServeType::Database(db_connect(
                PathBuf::from_str(m.get_one::<String>("dbconnfile").unwrap()).unwrap(),
            )),
            m if m.contains_id("derivationoutput") => {
                ServeType::Derivation(m.get_one::<String>("derivationoutput").unwrap().to_string())
            }
            _ => panic!("clap should ensure this never happens"),
        });

        let blob_cache_dir = {
            if m.contains_id("blobcachedir") {
                Some(fs::canonicalize(m.get_one::<String>("blobcachedir").unwrap()).unwrap())
            } else {
                None
            }
        };

        let fo = m
            .get_one::<String>("sshprivatekey")
            .map(|p| PathBuf::from(p));

        ADD_NIX_GCROOTS.get_or_init(|| m.get_flag("addnixgcroots"));
        INDEX_FILE_IS_BUILDABLE.get_or_init(|| m.get_flag("indexfileisbuildable"));
        SERVE_TYPE.get_or_init(|| serve_type);
        TARGET_DIR.get_or_init(|| Some(fs::canonicalize(target_dir).unwrap()));
        BLOB_CACHE_DIR.get_or_init(|| blob_cache_dir);
        SUBSTITUTERS.get_or_init(|| m.get_one::<String>("substituters").map(|s| s.to_string()));
        INDEX_FILE_PATH
            .get_or_init(|| Some(PathBuf::from(m.get_one::<String>("indexfilepath").unwrap())));
        SSH_PRIVATE_KEY.get_or_init(|| fo);

        listen(listen_address, listen_port).or_else(|e| Err(MainError::ListenBind(e)))
    }() {
        log::error!("startup error: {:#?}", &e);
    }
}

async fn open_file_limit() -> usize {
    tokio::task::spawn_blocking(|| {
        unsafe { libc::getdtablesize() }
            .try_into()
            .expect("getdtablesize(): failed to fetch RLIMIT_NOFILE")
    })
    .await
    .expect("spawn_blocking: failed to get file limit")
}

async fn get_open_fds_count() -> usize {
    tokio::task::spawn_blocking(|| std::fs::read_dir("/proc/self/fd").unwrap().count())
        .await
        .unwrap()
}

#[cfg(feature = "mysql")]
fn db_connect(creds_file: PathBuf) -> Pool {
    Pool::new(mysql::Opts::from_url(&fs::read_to_string(&creds_file).unwrap()).unwrap()).unwrap()
}

#[actix_rt::main]
async fn listen(listen_address: String, listen_port: u16) -> std::io::Result<()> {
    log::info!("start listening on port: {}", listen_port);

    let max_file_descriptors = open_file_limit().await;
    let manifest_url = "/v2/{name}/manifests/{reference}";
    let blob_url = "/v2/{name}/blobs/{reference}";

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FD_CHECK_INTERVAL).await;
            let current_fds = get_open_fds_count().await;
            log::info!("number of open filedescriptors: {current_fds}");
            if current_fds > max_file_descriptors {
                eprintln!("CRITICAL: Too many open file descriptors: {}", current_fds);
                std::process::exit(1);
            }
        }
    });

    HttpServer::new(move || {
        App::new()
            .wrap_fn(|req, srv| {
                let host = req
                    .headers()
                    .get("HOST")
                    .and_then(|hv| hv.to_str().ok())
                    .unwrap_or("");

                log::info!(
                    "request: {}",
                    &json!({ "endpoint": format!("{}", req.path()), "host": host })
                );

                srv.call(req)
            })
            .wrap(middleware::Compress::default())
            .route("/v2", web::get().to(version))
            .route(manifest_url, web::head().to(manifest))
            .route(manifest_url, web::get().to(manifest))
            .route(blob_url, web::head().to(blob))
            .route(blob_url, web::get().to(blob))
    })
    .bind(format!(
        "{listen_address}:{listen_port}",
        listen_address = listen_address,
        listen_port = listen_port
    ))?
    .run()
    .await
}

async fn version(_registry: Registry) -> impl Responder {
    HttpResponseBuilder::new(StatusCode::OK)
        .append_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .finish()
}

struct WharfixManifest {
    body: String,
    digest: String,
    #[allow(dead_code)]
    path: PathBuf,
}

impl WharfixManifest {
    fn new(body: String, path: PathBuf) -> Self {
        let digest = format!("sha256:{digest}", digest = sha256_digest_str(&body));

        //TODO: verify that above matches with drv embedded digest of manifest

        Self { body, path, digest }
    }
    fn body(self) -> String {
        self.body
    }
    fn content_type(&self) -> &str {
        CONTENT_TYPE_MANIFEST
    }
    fn digest(&self) -> &str {
        self.digest.as_str()
    }
}

impl Responder for WharfixManifest {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let mut builder = HttpResponse::Ok();
        let builder = builder
            .append_header(("Docker-Distribution-API-Version", "registry/2.0"))
            .append_header(("Docker-Content-Digest", self.digest()))
            .content_type(self.content_type());

        // Very difficult to find and kinda undocumented, but Actix will auto-set the content-length based on the response body
        // .. and it's not possible to manually set the content-length, but at least Actix is sane enough to _not_ return the actual
        // response body when the request type is HEAD.
        builder.body(self.body()).into()
    }
}

async fn manifest(
    registry: Registry,
    info: web::Path<FetchInfo>,
) -> Result<WharfixManifest, DockerError> {
    //try to look up existing manifest blob
    let existing_blob = registry
        .blob(&info)
        .await
        .map(|blob_info| blob_info.path.to_path_buf());

    let path = match existing_blob {
        Ok(path) => Ok(path),
        Err(_) => {
            //no dice, try evaling+building
            let tmp_dir = TempDir::new("wharfix")
                .or_else(|e| Err(RepoError::IO(Box::new(e))))
                .unwrap();
            let serve_root = registry
                .prepare(tmp_dir.path(), &info)
                .await
                .map_err(|e| e.manifest_context(&info))?;
            registry
                .index(&serve_root, &info)
                .await
                .map_err(|e| e.manifest_context(&info))?;
            registry.manifest(&serve_root, &info).await
        }
    };

    match path {
        Ok(path) => {
            // in most cases, the looked up path will point to the root of a store-path (directory)
            // but in the case of pull-by-digest (i.e. @sha256:9659c3fbe84bb15369b5b4ef719872b2cfc329f60bdcb24f6a3da56fa6cbdc4d),
            // the cached blob will point directly to the manifest file which corresponds to the digest.
            let fq = match path.is_dir() {
                true => path.join("manifest.json"),
                false => path.clone(),
            };
            log::info!("serving manifest from path: {:?}", &fq);

            match fs::read_to_string(&fq) {
                Ok(manifest_str) => {
                    registry.blob_discovery(&path.join("blobs")).await;
                    match path.file_name() {
                        Some(path_base_name) => {
                            registry
                                .store_blob(
                                    BlobInfo {
                                        name: path_base_name.to_str().unwrap().to_owned(),
                                        content_type: CONTENT_TYPE_MANIFEST.to_owned(),
                                        path: path.clone(),
                                    },
                                    true,
                                )
                                .await;
                        }
                        None => {}
                    }
                    Ok(WharfixManifest::new(manifest_str, fq))
                }
                Err(e) => {
                    log::error!(
                        "failed to read manifest for image: {name}, {reference}",
                        name = info.name,
                        reference = info.reference
                    );

                    Err(e.manifest_context(&info))
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Struct containing docker image layers
struct WharfixBlob {
    // FileIter reads from the filesystem in chunks, in order to avoid
    // exhausting memory
    blob: FileIter<File>,
    content_type: String,
}

impl Responder for WharfixBlob {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let content_type = String::from(self.content_type.as_str());

        // Turns the FileIter from a Result<Vec<u8>, _> into a
        // Result<Bytes, Error> which is what HttpResponse.streaming() expects.
        let body = stream! {
            for byte in self.blob {
                match byte {
                    Ok(byte) => yield Ok(web::Bytes::from(byte)),
                    Err(error) => yield Err(error)
                }
            }
        };

        HttpResponse::Ok()
            .append_header(("Docker-Distribution-API-Version", "registry/2.0"))
            .content_type(content_type)
            .streaming(body)
    }
}

async fn blob(registry: Registry, info: web::Path<FetchInfo>) -> Result<WharfixBlob, DockerError> {
    match registry.blob(&info).await {
        Ok(blob_info) => {
            let blob_path = blob_info.path.display().to_string();
            Ok(WharfixBlob {
                content_type: blob_info.content_type.clone(),
                blob: FileIter::new(blob_path.clone())
                    .expect(&format!("Failed to open {blob_path}.")),
            })
        }
        Err(e) => {
            log::error!("failed to read blob: {digest}", digest = &info.reference);

            Err(e)
        }
    }
}

fn file_name_to_content_type(file_name: &Path) -> String {
    let extension = file_name
        .extension()
        .unwrap_or(OsStr::new(""))
        .to_str()
        .unwrap_or("");
    match extension {
        "difftar" => CONTENT_TYPE_DIFFTAR,
        "configjson" => CONTENT_TYPE_CONTAINER_CONFIG,
        "manifestjson" => CONTENT_TYPE_MANIFEST,
        _ => CONTENT_TYPE_UNKNOWN,
    }
    .to_string()
}

fn repo_open(name: &str, url: &String) -> Result<Repository, RepoError> {
    use git2::RepositoryInitOptions;

    let root_dir = TARGET_DIR.get().unwrap().as_ref().unwrap();
    let clone_target = root_dir.join(pathname_generator(name, url));

    Ok(if clone_target.exists() {
        Repository::open_bare(&clone_target).or_else(|e| Err(RepoError::Git(e)))
    } else {
        log::info!(
            "registry, url: {}, {} - does not have an active clone, cloning into: {:?}",
            &name,
            &url,
            &clone_target
        );

        let mut init_opts = RepositoryInitOptions::new();
        init_opts.bare(true);
        init_opts.no_reinit(true);
        init_opts.origin_url(url);
        Repository::init_opts(&clone_target, &init_opts).or_else(|e| Err(RepoError::Git(e)))
    }?)
}

fn pathname_generator<'l>(name: &str, url: &str) -> String {
    let hash = sha256_digest_str(&format!("{}{}", name, url).as_str());
    format!("{}-{}", hash, name)
}

fn repo_checkout(repo: &Repository, reference: &String, tmp_path: &Path) -> Result<(), RepoError> {
    let mut cb = CheckoutBuilder::new();
    cb.force();
    cb.update_index(false);
    cb.target_dir(tmp_path);

    let obj = repo.revparse_single(reference.as_str()).or_else(|_| {
        let rev = format!("refs/remotes/origin/{reference}", reference = &reference);
        repo.revparse_single(rev.as_str())
            .or_else(|e| Err(RepoError::Git(e)))
    })?;
    repo.checkout_tree(&obj, Some(&mut cb))
        .or_else(|e| Err(RepoError::Git(e)))?;
    Ok(())
}

fn fetch_options<'l>() -> FetchOptions<'l> {
    let mut fo = FetchOptions::new();

    match SSH_PRIVATE_KEY.get().unwrap().as_ref() {
        Some(key) => {
            let mut callbacks = RemoteCallbacks::new();
            callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                Cred::ssh_key(
                    username_from_url.unwrap(),
                    None,
                    std::path::Path::new(&key.to_owned()),
                    None,
                )
            });
            fo.remote_callbacks(callbacks);
            fo
        }
        None => fo,
    }
}

fn sha256_digest_str(input: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    format!("{:x}", hash)
}
