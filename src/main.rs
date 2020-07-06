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

use actix_web::{App, HttpServer, Responder, web};

use crate::actix_web::dev::Service;
use actix_web::dev::{HttpResponseBuilder};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use actix_web::web::Bytes;
use std::process::{Command, Output};
use crate::exec::{SpawnOk, CommandWrapped};
use crate::exec::Wait;
use std::io::BufRead;
use linereader::LineReader;
use std::fs;


mod exec;
mod log;
/*
lazy_static! {
    static ref STATE: RwLock<HashMap<String, Mutex<EndpointState>>> = RwLock::new(HashMap::new());
}
*/

#[derive(Deserialize)]
struct FetchInfo {
    name: String,
    reference: String
}

#[actix_rt::main]
async fn main() {

    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("specs")
        .long("specs")
        .help("Path to directory of docker image specs")
        .takes_value(true)
        .required(true))
    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on 0.0.0.0")
        .takes_value(true)
        .required(true));

    let m = args.get_matches();
    let listen_port: u16 = m.value_of("port").unwrap().parse().unwrap();

    listen(listen_port).await.unwrap()
}

async fn listen(listen_port: u16) -> std::io::Result<()>{
    log::info(&format!("start listening on port: {}", listen_port));

    HttpServer::new(|| {
        App::new()
            .wrap_fn(|req, srv| {
                log::new_request();
                log::data("request", &json!({ "endpoint": format!("{}", req.path()) }));
                srv.call(req)
            })
            //.route("/v2", web::get().to(version))
            .route("/v2/{name}/manifests/{reference}", web::get().to(manifest))
            //.route("/v2/{name}/blobs/{reference}", web::get().to(blob))
    })
        .bind(format!("0.0.0.0:{listen_port}", listen_port=listen_port)).unwrap()
        .run()
        .await
}

async fn manifest(info: web::Path<FetchInfo>) -> impl Responder {
    let path = nix_build(&info.name).await.unwrap();
    let fq = format!("{}/manifest.json", &path);

    HttpResponseBuilder::new(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .header("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
        .body(&fs::read_to_string(&fq).unwrap())

    /*let lock = STATE.read().unwrap();
    match lock.get(&info.service) {
        Some(c) => {
            let mut state = c.lock().unwrap();
            HttpResponseBuilder::new((*state).handle()).body(format!("{}", (*state).requests))
        },
        None => HttpResponseBuilder::new(StatusCode::NOT_FOUND).finish()
    }*/
}

async fn nix_build(name: &String) -> Result<String, exec::ExecErrorInfo> {
    let mut cmd = Command::new("nix-build");
    let mut child = cmd
        .arg("--arg")
        .arg("specFile")
        .arg(&format!("./examples/{name}.nix", name=name))
        .arg("drv.nix")
        .spawn_ok()?;

    let out: Output = child.wait_for_output()?;
    let mut line_bytes = vec!();
    let mut reader = LineReader::new(&out.stdout[..]);
    while let Some(line) = reader.next_line() {
        line_bytes = line.expect("read error").to_vec();
    }

    let stringed = String::from_utf8(line_bytes.to_vec()).unwrap();
    Ok(String::from(stringed.trim_end()))
}

enum ImageBuildError {
    NOT_FOUND,
    OTHER
}