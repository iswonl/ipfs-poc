use actix_cors::Cors;
use actix_web;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, http::uri::Scheme};
use ipfs_api::{IpfsApi, IpfsClient, TryFromUri, Form};
use std::io::Cursor;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use pqcrypto_traits::sign::*;
use pqcrypto_dilithium::dilithium2::*;
use std::env;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref VALIDATOR_KEYPAIR: Mutex<(String, String)> = {
        let (pk, sk) = keypair();
        let sk_str = base64::encode(sk.as_bytes());
        let pk_str = base64::encode(pk.as_bytes());
        Mutex::new((pk_str, sk_str))
    };    
}

lazy_static! {
    pub static ref BACKEND_HOST: String = env::var("BACKEND_HOST").expect("Missing BACKEND_HOST env variable");
    pub static ref BACKEND_PORT: u16 = env::var("BACKEND_PORT").expect("Missing BACKEND_PORT env variable").parse().unwrap();
    pub static ref IPFS_HOST: String = env::var("IPFS_HOST").expect("Missing IPFS_HOST env variable");
    pub static ref IPFS_PORT: u16 = env::var("IPFS_PORT").expect("Missing IPFS_PORT env variable").parse().unwrap();
}

#[derive(Serialize, Deserialize)]
pub struct SignData {
    msg: String,
}

#[derive(Serialize, Deserialize)]
pub struct StoreData {
    msg: String,
    signature: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct StoreDataResponse {
    msg: String,
    signature: String,
    public_key: String,
    hash: Vec<String>,
}

fn val_sign(message: &str) -> (String, String) {
    let (p, s) = VALIDATOR_KEYPAIR.lock().unwrap().clone();
    let b = base64::decode(s.as_str()).unwrap();
    let sk =  pqcrypto_dilithium::dilithium2::SecretKey::from_bytes(&b).unwrap();
    let signature = base64::encode(sign(message.as_bytes(), &sk).as_bytes());
    (p, signature)
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/sign")]
async fn signmsg(sign_data: web::Json<SignData>) -> Result<HttpResponse, actix_web::Error> {

    if sign_data.msg.len() == 0 {
        return Err(actix_web::error::ErrorBadRequest("missing msg"));
    }

    let _signature = val_sign(sign_data.msg.as_str());

    let client = IpfsClient::from_host_and_port(Scheme::HTTP, IPFS_HOST.as_str(), *IPFS_PORT).unwrap();
    
    let mut form = Form::default();
    form.add_reader_file("/tmp/msg", Cursor::new(sign_data.msg.clone()), "data/msg");
    form.add_reader_file("/tmp/signature", Cursor::new(_signature.1.clone()), "data/signature");
    form.add_reader_file("/tmp/public_key", Cursor::new(_signature.0.clone()), "data/public_key");

    let hash = match client.add_with_form(form, ipfs_api::request::Add::builder().wrap_with_directory(true).build()).await {
        Ok(res) => res.iter().map(|r| r.hash.clone()).collect::<Vec<String>>(),
        Err(e) => { eprintln!("error adding file: {}", e); vec!["".to_string()]}
    };

    let response = StoreDataResponse {
        msg: sign_data.msg.clone(),
        signature: _signature.1.clone(),
        public_key: _signature.0.clone(),
        hash: hash.clone()
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .service(hello)
            .service(signmsg)
    })
    .bind((BACKEND_HOST.as_str(), *BACKEND_PORT))?
    .run()
    .await
}