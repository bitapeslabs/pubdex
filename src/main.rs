pub mod api;
pub mod chain;
pub mod config;
pub mod db;
pub mod indexer;
pub mod state;

use api::{start_api_server, ApiError};
use colored::Colorize;
use config::get_config;
use db::{create_database, DBError};
use indexer::{run_indexer, IndexerRuntimeConfig};
use std::fmt;
use std::fmt::Debug;
use std::panic;

use std::sync::Arc;

#[derive(Debug)]
enum PubdexError {
    ApiError(ApiError),
    DBError(DBError),
}

impl From<DBError> for PubdexError {
    fn from(err: DBError) -> Self {
        PubdexError::DBError(err)
    }
}

impl From<ApiError> for PubdexError {
    fn from(err: ApiError) -> Self {
        PubdexError::ApiError(err)
    }
}

impl fmt::Display for PubdexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            PubdexError::ApiError(err) => write!(formatter, "Api Error: {}", err),
            PubdexError::DBError(err) => write!(formatter, "DB Error: {}", err),
        }
    }
}

impl std::error::Error for PubdexError {}

#[actix_web::main] // Actix+Tokio single‑thread runtime
async fn main() -> Result<(), PubdexError> {
    println!(
        "{}{}{}{}",
        "PUBDEX".cyan(),
        "\nCreated by @mork1e",
        "\n\nGithub: https://github.com/bitapeslabs/pubdex".yellow(),
        "\n\nLoading db...".cyan().bold()
    );
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    let config = get_config();

    let db = Arc::new(create_database(&config.rocksdb.path)?);
    state::init(db.clone());

    println!("{}", "Starting indexer...".cyan().bold());
    let _indexer_handle = tokio::task::spawn_blocking(move || {
        // tokio::runtime::Handle::current().block_on(run_indexer(...))
        run_indexer(IndexerRuntimeConfig {
            rpc: &config.bitcoin_rpc,
            indexer: &config.indexer,
        });
    });

    println!("{}", "Starting api server...".cyan().bold());
    start_api_server(&config.api.ip, &config.api.port).await?;
    Ok(())
}
