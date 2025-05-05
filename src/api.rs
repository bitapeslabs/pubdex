use crate::db::{
    get_aliases_from_address, get_aliases_from_pubkey, get_indexer_tip, DBHandle,
    IndexerTipStateSerializable,
};
use crate::state;
use actix_web::{get, post, web, web::Data, App, HttpResponse, HttpServer, Responder};
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
// This struct represents state
struct AppState<'a> {
    db_handle: DBHandle<'a>,
}

impl std::error::Error for ApiError {}
#[derive(Serialize, Deserialize)]
struct ApiJsonError {
    message: String,
}
#[get("/indexer-state")]
async fn indexer_state<'a>(data: web::Data<AppState<'a>>) -> impl Responder {
    match get_indexer_tip(&data.db_handle) {
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
pub struct PubkeyAliasRequest {
    pub pubkey: String, // hex-encoded
}
#[post("/aliases/single-pubkey")]
async fn get_aliases_pubkey(req: web::Json<PubkeyAliasRequest>) -> impl Responder {
    let pubkey_hex = &req.pubkey;

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
    HttpResponse::Ok().json(get_aliases_from_pubkey(&pubkey_bytes))
}

#[derive(Deserialize)]
pub struct AddressAliasRequest {
    pub address: String, // hex-encoded
}
#[post("/aliases/address")]
async fn get_aliases_address<'a>(
    data: web::Data<AppState<'a>>,
    req: web::Json<AddressAliasRequest>,
) -> impl Responder {
    let address = &req.address;

    // Try to decode hex into bytes
    match get_aliases_from_address(&data.db_handle, address) {
        Some(alias_response) => HttpResponse::Ok().json(alias_response),
        None => {
            return HttpResponse::BadRequest().json(ApiJsonError {
                message: format!("No aliases found for address: {}", address),
            });
        }
    }
}

pub async fn start_api_server(ip: &str, port: &u16) -> Result<(), ApiError> {
    let db = state::get();

    let server = HttpServer::new(|| {
        App::new()
            .app_data(Data::new(AppState {
                db_handle: DBHandle::Direct(db),
            }))
            .service(indexer_state)
            .service(get_aliases_pubkey)
            .service(get_aliases_address)
    })
    .bind(SocketAddrV4::new(ip.parse()?, *port))?;

    println!("API server started successfully on {}:{}", ip, port);

    server.run().await.map_err(ApiError::from)
}
