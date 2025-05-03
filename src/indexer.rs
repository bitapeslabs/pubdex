use crate::chain;
use crate::config::BitcoinRpcConfig;
use crate::db;
use bitcoincore_rpc::{Auth, Client, RpcApi, Error as BitcoinRpcError, jsonrpc};
use colored::Colorize;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use ctrlc;
use bitcoin::Address;
//[u8]("block_tip") -> u32
//[u8, 33](utxo id) -> [u8, unsized] address bytes (str) (!! utxos are deleted after being used)
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]




#[derive(Debug)]
pub enum IndexerError {
    BitcoinRpcError(BitcoinRpcError),
}

impl From<BitcoinRpcError> for IndexerError {
    fn from(err: BitcoinRpcError) -> Self {
        IndexerError::BitcoinRpcError(err)
    }
}

impl fmt::Display for IndexerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            IndexerError::BitcoinRpcError(err) => write!(formatter, "Bitcoin RPC Error: {}", err),
        }
    }
}

impl std::error::Error for IndexerError {}


pub struct RetryClient {
    client: Client,
    shutdown: Arc<AtomicBool>
}

const RETRY_INTERVAL: u64 = 1000;
const RETRY_ATTEMPTS: u16 = 500;


fn _retry_warn(cmd: &str, attempt: &u16) -> () {
    eprintln!("{}: {} -  ({}/{} attempts) (retrying in {}ms...)", "RPC Call Failed: ".yellow().bold(), cmd, attempt, RETRY_ATTEMPTS, RETRY_INTERVAL);
}

impl RpcApi for RetryClient {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T, BitcoinRpcError> {
        for attempt in 0..RETRY_ATTEMPTS {
            if self.shutdown.load(Ordering::SeqCst) {
                eprintln!("{}", "Interrupted by user. Exiting.".red().bold());
                std::process::exit(1);
            }

            match self.client.call(cmd, args) {
                Ok(ret) => return Ok(ret),
                Err(BitcoinRpcError::JsonRpc(jsonrpc::error::Error::Rpc(ref rpcerr)))
                    if rpcerr.code == -28 =>
                {
                    _retry_warn(cmd, &attempt);
                    ::std::thread::sleep(::std::time::Duration::from_millis(RETRY_INTERVAL));
                    continue;
                },
                Err(BitcoinRpcError::JsonRpc(jsonrpc::error::Error::Transport(_))) => {
                    _retry_warn(cmd,&attempt);
                    ::std::thread::sleep(::std::time::Duration::from_millis(RETRY_INTERVAL));
                    continue;
                },
                Err(e) => return Err(e)
            }
        }
        eprintln!("{}", "Indexer Error: Maximum amount of retries for RPC reached! Exiting".red().bold());
        panic!();
    }
}


pub struct IndexerState {
    chain_height: u32,
    indexer_height: u32
}

pub fn get_indexer_state(rpc_client: &RetryClient) -> IndexerState{

    //db errors should always panic
    let indexer_height = db::get_indexer_tip().unwrap_or_else(|err| {
        eprintln!("{}: {}", "DB Error: Failed to get block tip".red().bold(), err);
        panic!()
    });

    let chain_height = RpcApi::get_block_count(rpc_client);

    match chain_height {
        Ok(height) => {
            let safe_chain_height: u32 = height.try_into().unwrap_or_else(|err| {

                //This should never happen on Bitcoin mainnet, or atleast not for another 1000 years lol
                eprintln!("{}: {}", "Indexer State Error: unable to convert u64 to u32 (pubdex only supports chains with block heights <=u32::MAX)".red().bold(), err);
                panic!();
    
            });

            IndexerState { chain_height: safe_chain_height, indexer_height }
        }

        Err(err) => {
            eprintln!("{}: {}", "RPC Parse Error: ".red().bold(), err);
            panic!();
        }
    }
}



pub fn run_indexer(rpc_config: &BitcoinRpcConfig) {

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();

    ctrlc::set_handler(move || {
        shutdown_signal.store(true, Ordering::SeqCst);
        eprintln!("{}", "\nCTRL+C received. Shutting down...".yellow().bold());
    }).expect("Error setting Ctrl-C handler");

    let rpc_client = RetryClient { client: Client::new(
        &rpc_config.rpc_url,
        Auth::UserPass(
            rpc_config.rpc_user.to_string(),
            rpc_config.rpc_password.to_string(),
        )
    )
    .unwrap_or_else(|err| {
        eprintln!(
            "{}: {}",
            "Failed to connect to Bitcoin RPC".red().bold(),
            err
        );
        panic!()
    }), shutdown };


    loop {

        let indexer_state = get_indexer_state(&rpc_client);

        println!(
            "{}: {}/{}",
            "[INDEXER] Indexing @ state: ".cyan(),
            indexer_state.indexer_height,
            indexer_state.chain_height
        );

        for height in 832000..indexer_state.chain_height {
            let block_hash = RpcApi::get_block_hash(&rpc_client, height.into()).unwrap_or_else(|err|{
                eprintln!("{}: {}", "An error ocurred getting block hash",err);
                panic!()
            });

            let block = RpcApi::get_block(&rpc_client, &block_hash).unwrap_or_else(|err| {
                eprintln!("{}: {}", "An error ocurred getting block hash",err);
                panic!()
            });
            
            println!("{}: # {}", "[INDEXER] Processing block".blue().bold(), height);

            for transaction in block.txdata {

                for vout in transaction.output{
                    let address = match Address::from_script(&vout.script_pubkey, chain::ENABLED_NETWORK) {
                        Ok(address) => address,
                        Err(_) => continue
                    };
                    println!("{}: {}", "Found address", address.to_string());

                }
            }


        }
    
    }

}
