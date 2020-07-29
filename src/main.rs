extern crate actix_web;
extern crate clap;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
extern crate time;
extern crate tokio;
extern crate uuid;
extern crate linereader;

use std::sync::{Mutex, RwLock};
use actix_web::http::StatusCode;
use std::collections::HashMap;
use std::fmt::Debug;
use std::string::String;

use actix_web::{App, HttpServer, middleware, Responder, web, HttpRequest};

use crate::actix_web::dev::Service;
use actix_web::dev::{HttpResponseBuilder};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use actix_web::web::Bytes;
use std::process::{Command, Output};
use crate::exec::{SpawnOk, CommandWrapped};
use crate::exec::Wait;
use std::io::BufRead;
use linereader::LineReader;
use std::fs;
use walkdir::WalkDir;
use std::str::FromStr;
use futures::StreamExt;


mod exec;
mod log;

static mut SERVE_ROOT: String = String::new();

#[derive(Deserialize)]
struct FetchInfo {
    name: String,
    reference: String
}

#[derive(Clone)]
struct BlobInfo {
    content_type: String,
    path: PathBuf,
}

#[actix_rt::main]
async fn main() {

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
        .required(true))
    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on <address>")
        .takes_value(true)
        .required(true));

    let m = args.get_matches();
    let listen_address: &str = m.value_of("address").unwrap();
    let listen_port: u16 = m.value_of("port").unwrap().parse().unwrap();
    unsafe {
        SERVE_ROOT = m.value_of("serve").unwrap().to_owned();
    }

    listen(listen_address, listen_port).await.unwrap()
}

fn get_serve_root() -> &'static String {
    unsafe {
        &SERVE_ROOT
    }
}

async fn listen(listen_address: &str, listen_port: u16) -> std::io::Result<()>{
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
        .bind(format!("{listen_address}:{listen_port}", listen_address=listen_address, listen_port=listen_port)).unwrap()
        .run()
        .await
}

async fn version() -> impl Responder {
    HttpResponseBuilder::new(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .finish()
}

async fn manifest(info: web::Path<FetchInfo>) -> impl Responder {
    let path = PathBuf::from_str(get_serve_root().as_str()).unwrap();
    let fq: PathBuf = path.join("tags").join(&info.reference).join("manifest.json");

    if fq.exists() {
        HttpResponseBuilder::new(StatusCode::OK)
            .header("Docker-Distribution-API-Version", "registry/2.0")
            .header("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
            .body(&fs::read_to_string(&fq).unwrap())
    } else {
        HttpResponseBuilder::new(StatusCode::NOT_FOUND).header("Docker-Distribution-API-Version", "registry/2.0").finish()
    }
}

async fn blob(info: web::Path<FetchInfo>) -> impl Responder {
    lazy_static! {
        static ref BLOBS: HashMap<String, BlobInfo> = {
            let search_path = PathBuf::from_str(get_serve_root().as_str()).unwrap().join("blobs");
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
            HttpResponseBuilder::new(StatusCode::OK)
                .header("Docker-Distribution-API-Version", "registry/2.0")
                .header("Content-Type", blob_info.content_type.as_str())
                .body(fs::read(&blob_info.path).unwrap())
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
        let file_name = entry.file_name().to_str().unwrap();
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
    blobs
}


enum ImageBuildError {
    NOT_FOUND,
    OTHER
}