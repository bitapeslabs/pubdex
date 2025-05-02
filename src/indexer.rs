use crate::config::BitcoinRpcConfig;
use crate::db;
use bitcoincore_rpc::{Auth, Client, RpcApi, Error as BitcoinRpcError};
use colored::Colorize;

//[u8]("block_tip") -> u32
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]



struct IndexerState {
    chain_height: u32,
    indexer_height: u32
}

pub fn get_indexer_state(rpc: Client) -> Result<IndexerState, BitcoinRpcError>{

    //db errors should always panic
    let indexer_height = db::get_indexer_tip().unwrap_or_else(|err| {
        eprintln!("{}: {}", "DB Error: Failed to get block tip".red().bold(), err);
        panic!()
    });

    let chain_height = rpc.get_block_count();

    match chain_height {
        Ok(height) => {
            let safe_chain_height: u32 = height.try_into().unwrap_or_else(|err| {

                //This should never happen on Bitcoin mainnet, or atleast not for another 1000 years lol
                eprintln!("{}: {}", "Indexer State Error: unable to convert u64 to u32 (pubdex only supports chains with block heights <=u32::MAX)".red().bold(), err);
                panic!();
    
            });

            Ok(IndexerState { chain_height: safe_chain_height, indexer_height })
        }

        Err(err) => Err(err)
    }
}


pub fn run_indexer(rpc_config: &BitcoinRpcConfig) {
    let rpc = Client::new(
        &rpc_config.rpc_url,
        Auth::UserPass(
            rpc_config.rpc_user.to_string(),
            rpc_config.rpc_password.to_string(),
        ),
    )
    .unwrap_or_else(|err| {
        eprintln!(
            "{}: {}",
            "Failed to connect to Bitcoin RPC".red().bold(),
            err
        );
        panic!()
    });

    
    let indexer_state = get_indexer_state(rpc)


    println!(
        "{}: {}",
        "[INDEXER] Starting indexer @ blocktip".cyan(),
        block_tip
    );
}
