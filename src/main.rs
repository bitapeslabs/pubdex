pub mod api;
pub mod config;
pub mod db;
pub mod indexer;
pub mod state;

use api::start_api_server;
use colored::Colorize;
use db::create_database;
use indexer::run_indexer;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug)]
enum PubdexError {
    StdIoError(std::io::Error),
    RocksDb(rocksdb::Error),
}

impl From<rocksdb::Error> for PubdexError {
    fn from(err: rocksdb::Error) -> Self {
        PubdexError::RocksDb(err)
    }
}

impl From<std::io::Error> for PubdexError {
    fn from(err: std::io::Error) -> Self {
        PubdexError::StdIoError(err)
    }
}
#[actix_web::main] // Actix+Tokio single‑thread runtime
async fn main() -> Result<(), PubdexError> {
    println!(
        "{}{}{}{}",
        "PUBDEX".cyan(),
        "\nCreated by @mork1e",
        "\n\nGithub: https://github.com/bitapeslabs/pubdex".yellow(),
        "\n\nLoading db...".cyan().bold()
    );

    let db = Arc::new(create_database("./tmp")?);
    state::init(db.clone()); // 👈 initializes the global DB

    let db_indexer = db.clone();

    println!("{}", "Starting indexer...".cyan().bold());
    let _indexer_handle = tokio::task::spawn_blocking(move || {
        // tokio::runtime::Handle::current().block_on(run_indexer(...))
        run_indexer(db_indexer);
    });

    println!("{}", "Starting api server...".cyan().bold());
    start_api_server().await?;
    Ok(())
}
