use crate::db::{get_aliases_from_pubkey, get_indexer_tip, IndexerTipStateSerializable};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{AddrParseError, SocketAddrV4};
// This struct represents state
#[derive(Debug)]
pub enum ApiError {
    NetError(AddrParseError),
    IoError(std::io::Error),
}

impl From<AddrParseError> for ApiError {
    fn from(err: AddrParseError) -> Self {
        ApiError::NetError(err)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        ApiError::IoError(err)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::NetError(e) => write!(f, "Network error: {}", e),
            ApiError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ApiError {}
#[derive(Serialize, Deserialize)]
struct ApiJsonError {
    message: String,
}
#[get("/indexer-state")]
async fn indexer_state() -> impl Responder {
    match get_indexer_tip() {
        Ok(result) => {
            let tip_state: IndexerTipStateSerializable = result.into();
            HttpResponse::Ok().json(tip_state)
        }
        Err(e) => {
            let error = ApiJsonError {
                message: e.to_string(),
            };
            HttpResponse::InternalServerError().json(error)
        }
    }
}

#[derive(Deserialize)]
pub struct PubkeyRequest {
    pub pubkey: String, // hex-encoded
}
#[post("/aliases/single-pubkey")]
async fn get_aliases(pubkey_req: web::Json<PubkeyRequest>) -> impl Responder {
    let pubkey_hex = &pubkey_req.pubkey;

    // Try to decode hex into bytes
    let pubkey_bytes = match hex::decode(pubkey_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return HttpResponse::BadRequest().json(ApiJsonError {
                message: format!("Invalid hex in pubkey: {}", e),
            });
        }
    };

    // Get aliases
    match get_aliases_from_pubkey(&pubkey_bytes) {
        Some(alias_response) => HttpResponse::Ok().json(alias_response),
        None => HttpResponse::NotFound().json(ApiJsonError {
            message: "No alias mapping found".to_string(),
        }),
    }
}

pub async fn start_api_server(ip: &str, port: &u16) -> Result<(), ApiError> {
    let server = HttpServer::new(|| App::new().service(indexer_state).service(get_aliases))
        .bind(SocketAddrV4::new(ip.parse()?, *port))?;

    println!("API server started successfully on {}:{}", ip, port);

    server.run().await.map_err(ApiError::from)
}
