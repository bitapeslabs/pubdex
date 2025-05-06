use crate::config::{BitcoinRpcConfig, IndexerConfig};
use crate::db::{
    self, get_utxo_db_key, BatchManager, DBError, DBHandle, IndexerTipState, StoredBlockHash,
    WriteBatchWithCache,
};
use crate::state;
use bitcoincore_rpc::{jsonrpc, Auth, Client, Error as BitcoinRpcError, RpcApi};
use colored::Colorize;
use std::num::TryFromIntError;

use crate::blockchain::{utils::get_pub_key, utils::try_peek_pubkey};
use crate::utils::{grp_hashset::GrpHashset, grp_hashset::GrpHashsetCacheMethods, logger::Logger};
use bitcoin::{BlockHash, OutPoint, ScriptBuf, TxIn};
use ctrlc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;

//[u8]("block_tip") -> u32
//[u8, 33](utxo id) -> [u8, unsized] address bytes (str) (!! utxos are deleted after being used)
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("Bitcoin RPC Error: {0}")]
    BitcoinRpcError(#[from] BitcoinRpcError),

    #[error("Secp256k1 eror: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("Uint coercion error: {0}")]
    TryFromIntError(#[from] TryFromIntError),

    #[error("DB Error: {0}")]
    DBError(#[from] DBError),

    #[error("RocksDB Error: {0}")]
    RocksDB(#[from] rocksdb::Error),
}

impl IndexerError {
    pub fn from<T: Into<String>>(err: T) -> Self {
        IndexerError::RuntimeError(err.into())
    }
}

pub struct RetryClient {
    client: Client,
    shutdown: Arc<AtomicBool>,
}

const RETRY_INTERVAL: u64 = 1000;
const RETRY_ATTEMPTS: u16 = 500;

fn _retry_warn(cmd: &str, attempt: &u16) -> () {
    Logger::warn(&format!(
        "{}: {} -  ({}/{} attempts) (retrying in {}ms...)",
        "RPC Call Failed: ", cmd, attempt, RETRY_ATTEMPTS, RETRY_INTERVAL
    ));
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
                }
                Err(BitcoinRpcError::JsonRpc(jsonrpc::error::Error::Transport(_))) => {
                    _retry_warn(cmd, &attempt);
                    ::std::thread::sleep(::std::time::Duration::from_millis(RETRY_INTERVAL));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Logger::error_panic("Indexer Error: Maximum amount of retries for RPC reached! Exiting");
    }
}

pub struct IndexerState {
    chain_height: u32,
    indexer_height: u32,
    indexer_tip_hash: BlockHash, // ← ADD THIS
}

pub fn get_indexer_state(
    db_handle: &DBHandle,
    rpc_client: &RetryClient,
) -> Result<IndexerState, IndexerError> {
    //db errors should always panic
    let tip_state = db::get_indexer_tip(db_handle)?;

    let chain_height = RpcApi::get_block_count(rpc_client)?;

    let safe_chain_height: u32 = chain_height.try_into()?;

    Ok(IndexerState {
        chain_height: safe_chain_height,
        indexer_height: tip_state.indexer_height,
        indexer_tip_hash: tip_state.indexer_tip_hash.0,
    })
}

pub struct IndexerRuntimeConfig<'a> {
    pub rpc: &'a BitcoinRpcConfig,
    pub indexer: &'a IndexerConfig,
}
pub static LOOP_INTERVAL: u64 = 1000;
pub static PUBKEY_SIZE: usize = 33;

pub fn run_indexer<'a>(config: IndexerRuntimeConfig<'a>) -> Result<(), IndexerError> {
    //Setup instances owned by the main indexer loop
    let mut logger = Logger::new();
    let db = state::get();
    let direct_db_handle = DBHandle::Direct(&db);
    let shutdown_signal_ctrl = Arc::new(AtomicBool::new(false));
    let shutdown = shutdown_signal_ctrl.clone();
    /*
        Cache size is a rough estimate of how much memory was granted to us by the user to use to expand the pubkey_cache, which prevents rerunning
        cryptogtaphic functions for pubkeys or scripts already seen.
    */

    let cache_size: usize = ((config.indexer.mem_alloc_pubkey_hset * 1_000_000) / PUBKEY_SIZE) * 2;
    Logger::info(&format!(
        "{}: {}mb",
        "Using a max_alloc for pubkey_hset of", config.indexer.mem_alloc_pubkey_hset
    ));

    let mut pubkey_cache = GrpHashset::new(cache_size);

    //Capture ctrl-c and shutdown the main thread
    ctrlc::set_handler(move || {
        shutdown_signal_ctrl.store(true, Ordering::SeqCst);
        eprintln!("{}", "\nCTRL+C received. Shutting down...".yellow().bold());
    })
    .expect("Error setting Ctrl-C handler");

    //Creates a new retry client, which wraps a client and tries any rpc call indefinitely until a max allowed amount.
    let rpc_client = RetryClient {
        client: Client::new(
            &config.rpc.rpc_url,
            Auth::UserPass(
                config.rpc.rpc_user.to_string(),
                config.rpc.rpc_password.to_string(),
            ),
        )?,
        shutdown,
    };

    let indexer_state = get_indexer_state(&direct_db_handle, &rpc_client)?;

    //Used for reorg detection
    let expected_parent = indexer_state.indexer_tip_hash.to_string();
    let actual_parent =
        RpcApi::get_block_hash(&rpc_client, indexer_state.indexer_height.into())?.to_string();

    if expected_parent != actual_parent {
        Logger::error_panic(&format!(
            "{}, expected parent: {}, got: {}",
            "Reorg detected! Local DB is out of sync with node."
                .red()
                .bold(),
            expected_parent,
            actual_parent
        ))
    }

    //Main indexer loop starts here
    loop {
        let indexer_state = get_indexer_state(&direct_db_handle, &rpc_client)?;

        Logger::info(&format!(
            "{}: {}/{}",
            "[INDEXER] Indexing @ state: ".cyan(),
            indexer_state.indexer_height,
            indexer_state.chain_height
        ));

        logger.start_timer("total_elapsed_time");

        let mut log_iter: u32 = 0;

        for height in indexer_state.indexer_height..indexer_state.chain_height {
            //batch is managed by the indexer loop and propagated down
            let batch = WriteBatchWithCache::new();
            let mut db_handle: DBHandle = DBHandle::Staged(batch);

            logger.start_timer("rpc");

            let block_hash = RpcApi::get_block_hash(&rpc_client, height.into())?;

            let block = RpcApi::get_block(&rpc_client, &block_hash)?;

            logger.stop_timer("rpc");

            logger.start_timer("save_utxo_mappings");

            for transaction in &block.txdata {
                // save new utxos
                for vout_index in 0..transaction.output.len() {
                    let vout = &transaction.output[vout_index];

                    let outpoint: OutPoint = OutPoint {
                        txid: transaction.compute_txid(),
                        vout: vout_index.try_into()?,
                    };

                    db::save_utxo_script_mapping(&mut db_handle, outpoint, &vout.script_pubkey)?;
                    logger.incement_counter("saved_utxos", &1);
                }
            }

            logger.stop_timer("save_utxos_mappings");

            logger.start_timer("get_used_utxos_for_block");

            let vins: Vec<&TxIn> = (&block.txdata)
                .iter()
                .map(|tx| &tx.input)
                .flatten()
                .collect();
            let mut utxo_address_map = db::bulk_get_utxo_script_mappings(&db_handle, &vins);

            logger.stop_timer("get_used_utxos_for_block");

            logger.start_timer("process_vins");

            for vin in vins {
                //The utxo id is represented by txid:vout in the db, as a byte array.
                let outpoint_key = get_utxo_db_key(vin.previous_output);

                //Get the bytes of the funding script we found for this vin
                let Some(fund_script_bytes) = utxo_address_map.get(&outpoint_key).cloned() else {
                    continue;
                };

                let fund_script = ScriptBuf::from_bytes(fund_script_bytes.clone());

                /*
                    This is a fake representation of a pubkey unique to a (fund_script, script_sig and vin.witness) tuple. It
                    is a low cost function to get a unique identifier to use in cache, so we can get it from the grphashset for
                    pubkeys without actually getting the pubkey (which is resource intensive). That way we can check for
                    presence of pubkeys before we actually do anything thats resource intensive
                */
                let seek_pubkey = try_peek_pubkey(&fund_script, &vin.script_sig, &vin.witness)
                    .unwrap_or_default();

                if pubkey_cache.contains(&seek_pubkey) {
                    logger.incement_counter("cache_hits", &1);
                    continue;
                };

                let pubkey = match get_pub_key(&fund_script_bytes, &vin.script_sig, &vin.witness) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        logger.incement_counter("failed_deserializations", &1);
                        Logger::error(&format!("Failed to deserialize pubkey: {}", err));
                        continue;
                    }
                };

                pubkey_cache.insert(if seek_pubkey.len() != 0 {
                    &seek_pubkey
                } else {
                    &pubkey
                });

                db::save_decoded_script_mapping(&mut db_handle, &pubkey, &outpoint_key)?;

                utxo_address_map.remove(&outpoint_key);
                logger.incement_counter("pmap_mappings", &4);
            }

            logger.incement_counter("transactions_processed", &block.txdata.len());
            logger.stop_timer("process_vins");

            db::save_new_indexer_tip(
                &mut db_handle,
                &IndexerTipState {
                    indexer_height: height,
                    indexer_tip_hash: StoredBlockHash(block_hash),
                },
            )?;

            logger.start_timer("write_all");

            let Some(inner_batch) = db_handle.into_inner() else {
                return Err(IndexerError::from(
                    "Failed to get inner batch from db_handle",
                ));
            };

            db.write(inner_batch)?;

            logger.stop_timer("write_all");
            log_iter += 1;

            if log_iter >= config.indexer.log_interval {
                Logger::success(&format!(
                    "{}: #{} -> {}",
                    "[INDEXER] Processed blocks",
                    height - config.indexer.log_interval,
                    height,
                ));
                logger.stop_timer("total_elapsed_time");
                logger.consume();
                log_iter = 0;
            }
        }
        Logger::success(&format!(
            "{}{}{}",
            "\n[INDEXER] Block chunk finished processing, waiting ",
            LOOP_INTERVAL,
            "ms before checking for new state"
        ));
        ::std::thread::sleep(::std::time::Duration::from_millis(LOOP_INTERVAL));
    }
}
