use clap::Parser;
use colored::Colorize;
use serde::Deserialize;
use std::{fs, str};
use toml;

#[derive(Deserialize)]
pub struct RocksDBConfig {
    pub path: String,
}

#[derive(Deserialize)]
pub struct BitcoinRpcConfig {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
}

impl Default for BitcoinRpcConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:8332".to_string(),
            rpc_user: "admin".to_string(),
            rpc_password: "admin".to_string(),
        }
    }
}

#[derive(Deserialize)]

pub struct ApiConfig {
    pub ip: String,
    pub port: u16,
}

#[derive(Deserialize)]
pub struct IndexerConfig {
    pub mem_alloc_pubkey_hset: usize,
    pub log_interval: u32,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            mem_alloc_pubkey_hset: 1028,
            log_interval: 10,
        }
    }
}

#[derive(Deserialize)]

pub struct Config {
    pub rocksdb: RocksDBConfig,
    pub api: ApiConfig,
    pub bitcoin_rpc: BitcoinRpcConfig,
    pub indexer: IndexerConfig,
}
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]

pub struct CliArgs {
    /// The pattern to look for
    #[arg(short, long)]
    config: String,
}

pub fn get_config() -> Config {
    let args = CliArgs::parse();

    let config: String = match fs::read(args.config) {
        Ok(data) => String::from_utf8_lossy(&data).into_owned(),
        Err(err) => {
            //This should panic
            eprintln!("{}: {}", "Err: Failed to get config file".red().bold(), err);
            panic!()
        }
    };

    toml::from_str(&config).unwrap_or_else(|err| {
        eprintln!("{}: {}", "Err: Failed to get config file".red().bold(), err);
        panic!()
    })
}
