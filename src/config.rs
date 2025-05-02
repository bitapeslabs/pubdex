use clap::Parser;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct RocksDBConfig {
    path: String,
}
#[derive(Deserialize)]

struct ApiConfig {
    ip: String,
    port: u16,
}
#[derive(Deserialize)]

struct Config {
    rocksdb: RocksDBConfig,
    api: ApiConfig,
}
#[derive(Parser)]
struct Cli {
    /// The pattern to look for
    config: String,
}

pub fn get_config() -> () {
    let args = Cli::parse();
    println!("Using config file: {}", args.config);
}
