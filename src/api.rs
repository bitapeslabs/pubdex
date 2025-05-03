use crate::db::{get_indexer_tip, IndexerTipStateSerializable};
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
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
pub async fn start_api_server(ip: &str, port: &u16) -> Result<(), ApiError> {
    let server = HttpServer::new(|| App::new().service(indexer_state))
        .bind(SocketAddrV4::new(ip.parse()?, *port))?;

    println!("API server started successfully on {}:{}", ip, port);

    server.run().await.map_err(ApiError::from)
}
