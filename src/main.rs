extern crate actix_web;
extern crate clap;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
extern crate time;
extern crate tokio;
extern crate uuid;
extern crate linereader;

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

use crate::errors::MainError;

mod errors;
mod exec;
mod log;

static mut SERVE_ROOT: Option<PathBuf> = None;

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


fn main() {

    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("serve")
        .long("serve")
        .help("Path to directory of docker image specs")
        .takes_value(true)
        .required(true))
    .arg(clap::Arg::with_name("address")
        .long("address")
        .help("Listen address to open on <port>")
        .takes_value(true)
        .required(false))
    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on <address>")
        .takes_value(true)
        .required(true));

    if let Err(e) = || -> Result<(), MainError> {

        let m = args.get_matches();
        let listen_address = m.value_of("address")
            .unwrap_or("0.0.0.0").to_string();
        let listen_port: u16 = m.value_of("port")
            .ok_or(MainError::ArgParseError("Missing cmdline arg 'port'"))?.parse()
            .or(Err(MainError::ArgParseError("cmdline arg 'port' doesn't look like a port number")))?;
        unsafe {
            SERVE_ROOT = Some(PathBuf::from_str(m.value_of("serve")
                .ok_or(MainError::ArgParseError("Missing cmdline arg 'serve'"))?)
                .or(Err(MainError::ArgParseError("cmdline arg 'serve' doesn't look like a valid path")))?);
        }

        listen(listen_address, listen_port)
            .or_else(|e| Err(MainError::ListenBindError(e)))

    }() {
        log::error("startup error", &e);
    }
}

fn get_serve_root() -> &'static PathBuf {
    unsafe {
        &SERVE_ROOT.as_ref().unwrap() // will never be None
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
    let path = get_serve_root();
    let fq: PathBuf = path.join("tags").join(&info.reference).join("manifest.json");

    if fq.exists() {
        match fs::read_to_string(&fq) {
            Ok(manifest) => HttpResponseBuilder::new(StatusCode::OK)
                        .header("Docker-Distribution-API-Version", "registry/2.0")
                        .header("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
                        .body(&manifest),
            Err(e) => {
                log::error(&format!("failed to read manifest for image: {name}, {reference}", name=info.name, reference=info.reference), &e);
                HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR).header("Docker-Distribution-API-Version", "registry/2.0").finish()
            }
        }
    } else {
        HttpResponseBuilder::new(StatusCode::NOT_FOUND).header("Docker-Distribution-API-Version", "registry/2.0").finish()
    }
}

async fn blob(info: web::Path<FetchInfo>) -> impl Responder {
    lazy_static! {
        static ref BLOBS: HashMap<String, BlobInfo> = {
            let search_path = get_serve_root().join("blobs");
            blob_discovery(&search_path)
        };
    }
    let blob_info = {
        match BLOBS.get(&info.reference) {
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

fn blob_discovery(path: &PathBuf) -> HashMap<String, BlobInfo> {
    let mut blobs = HashMap::new();
    for entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()).filter(|e| e.path() != path.as_path()) {
        if let Some(file_name) = entry.file_name().to_str() {
            let parts: Vec<&str> = file_name.split('.').collect();
            blobs.insert(format!("sha256:{digest}", digest=parts[0]), BlobInfo{
                content_type: String::from(match parts[1] {
                    "tar" => "application/vnd.docker.image.rootfs.diff.tar",
                    "json" => "application/vnd.docker.container.image.v1+json",
                    _ => "application/octet-stream",
                }),
                path: entry.path().to_path_buf()
            });
        }
    }
    blobs
}
