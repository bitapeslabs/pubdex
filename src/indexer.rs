use crate::config::{BitcoinRpcConfig, IndexerConfig};
use crate::db::{self, get_utxo_db_key, BatchManager, DBHandle, IndexerTipState, StoredBlockHash, WriteBatchWithCache};
use crate::state;
use bitcoin::hashes::Hash;
use bitcoin::key::Parity;
use bitcoin::{secp256k1, Witness};
use bitcoincore_rpc::{Auth, Client, RpcApi, Error as BitcoinRpcError, jsonrpc};
use colored::Colorize;
use core::panic;
use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use ctrlc;
use bitcoin::{XOnlyPublicKey, BlockHash, OutPoint, ScriptBuf, TxIn, script::Instruction, secp256k1::hashes::hash160};
use rand::{self, Rng};
//[u8]("block_tip") -> u32
//[u8, 33](utxo id) -> [u8, unsized] address bytes (str) (!! utxos are deleted after being used)
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]




#[derive(Debug)]
pub enum IndexerError {
    BitcoinRpcError(BitcoinRpcError),
    Secp256k1Error(secp256k1::Error)
}



impl From<BitcoinRpcError> for IndexerError {
    fn from(err: BitcoinRpcError) -> Self {
        IndexerError::BitcoinRpcError(err)
    }
}

impl From<secp256k1::Error> for IndexerError {
    fn from(err: secp256k1::Error) -> Self {
        IndexerError::Secp256k1Error(err)
    }
}

impl fmt::Display for IndexerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            IndexerError::BitcoinRpcError(err) => write!(formatter, "Bitcoin RPC Error: {}", err),
            IndexerError::Secp256k1Error(err) => write!(formatter, "Secp256k1 Error: {}", err),

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
    indexer_height: u32,
    indexer_tip_hash: BlockHash, // ← ADD THIS

}

pub fn get_indexer_state(db_handle: &DBHandle, rpc_client: &RetryClient) -> IndexerState{

    //db errors should always panic
    let tip_state = db::get_indexer_tip(db_handle).unwrap_or_else(|err| {
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

            IndexerState { chain_height: safe_chain_height, indexer_height: tip_state.indexer_height, indexer_tip_hash: tip_state.indexer_tip_hash.0  }
        }

        Err(err) => {
            eprintln!("{}: {}", "RPC Parse Error: ".red().bold(), err);
            panic!();
        }
    }
}
#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum IndexerAddressType {
    P2TR = 1,
    P2WPKH = 2,
    P2SHP2WPKH = 3,
    P2PKH = 4,

}
impl TryFrom<u8> for IndexerAddressType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(IndexerAddressType::P2TR),
            2 => Ok(IndexerAddressType::P2SHP2WPKH),
            3 => Ok(IndexerAddressType::P2PKH),
            _ => Err(()),
        }
    }
}

//Growable randomly popped Hashmap
pub struct GrpHashset{
    pub vec: Vec<Vec<u8>>,
    pub hashset: HashSet<Vec<u8>>,
    pub count: usize,
    pub max_size: usize,
    pub rng: rand::rngs::ThreadRng

}

trait GrpHashsetCacheMethods {
    
    fn new(max_size: usize) -> GrpHashset;
    fn contains(&self, key: &[u8]) -> bool;
    fn get(&self, key: &[u8]) -> Option<&Vec<u8>>;
    fn insert(&mut self, key: &[u8]) -> bool;
}

impl GrpHashsetCacheMethods for GrpHashset {

    fn new(max_size: usize) -> Self {
        GrpHashset{
            vec: vec![],
            hashset: HashSet::new(),
            count: 0,
            max_size,
            rng: rand::rng()
        } 
    }

    fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.hashset.get(key)
    }

    fn contains(&self, value: &[u8]) -> bool {
         HashSet::contains(&self.hashset, value)
    }

    fn insert(&mut self, value: &[u8]) -> bool {
        
        self.count += 1;
        let result = HashSet::insert(&mut self.hashset, value.to_vec());
        self.vec.push(value.to_vec());
        if self.count >= self.max_size {
            let index_to_delete: usize = self.rng.random_range(0..self.max_size);

            let item_to_delete = self.vec
            .get(index_to_delete)
            .expect("Random generator caused overflow at GrpHashmap::insert")
            .clone();

            self.vec.remove(index_to_delete);
            HashSet::remove(&mut self.hashset, &item_to_delete);
        }
        result
    }

}


pub struct DecodedScript {
    pub pubkey: Vec<u8>,
}


pub trait CompressKey {
    fn compress_if_necessary(&mut self) -> Result<(), secp256k1::Error>;
}


impl CompressKey for DecodedScript {
   fn compress_if_necessary(&mut self) -> Result<(), secp256k1::Error> {
        if self.pubkey.len() == 65 {
            self.pubkey = secp256k1::PublicKey::from_slice(&self.pubkey)?.serialize().to_vec()
        }
        Ok(())

    }
}


pub fn get_pub_key(
    fund_script_bytes: &Vec<u8>,
    spend_script: &ScriptBuf,
    witness: &Witness,
) -> Option<DecodedScript> {
    let fund_script = ScriptBuf::from_bytes(fund_script_bytes.clone());

    // ── Taproot (P2TR) ───────────────────────────────────────────────
    if fund_script.is_p2tr() && fund_script.len() == 34 {
        let xonly_bytes = &fund_script.as_bytes()[2..34];
        if let Ok(xonly) = XOnlyPublicKey::from_slice(xonly_bytes) {
            return Some(
                DecodedScript { pubkey: xonly.public_key(Parity::Even).serialize().to_vec() });
        }
    }

    // ── Native SegWit v0 P2WPKH ─────────────────────────────────────
    if fund_script.is_p2wpkh() {
        if witness.len() >= 2 {
            let pk_bytes = &witness[1];
            // sanity‑check: hash160(pubkey) must match program
            let h160 = hash160::Hash::hash(pk_bytes);
            if fund_script.as_bytes()[2..22] == h160[..] {
                return Some(DecodedScript { pubkey: pk_bytes.to_vec() });
            }
        }
    }

    // ── Legacy P2PKH ────────────────────────────────────────────────
    if fund_script.is_p2pkh() {
        let mut pushes = spend_script.instructions().filter_map(|i| {
            if let Ok(Instruction::PushBytes(b)) = i { Some(b) } else { None }
        });

        pushes.next(); // skip signature

        if let Some(pk_bytes) = pushes.next() {
            if (pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03))
               || (pk_bytes.len() == 65 && pk_bytes[0] == 0x04)
            {
                return Some(DecodedScript { pubkey: pk_bytes.as_bytes().to_vec() });
            }
        }
    }

    // ── P2SH ▸ P2WPKH (nested SegWit) ──────────────────────────────
    if fund_script.is_p2sh() {
        // redeem‑script = last push in scriptSig
        let redeem_script_bytes = spend_script.instructions().filter_map(|i| match i {
            Ok(Instruction::PushBytes(b)) => Some(b),
            _ => None,
        }).last();

        if let Some(redeem) = redeem_script_bytes {
            let redeem_script = ScriptBuf::from_bytes(redeem.as_bytes().to_vec());
            if redeem_script.is_p2wpkh() && witness.len() >= 2 {
                let pk_bytes = &witness[1];
                // cross‑check hash160
                let h160 = hash160::Hash::hash(pk_bytes);
                if redeem_script.as_bytes()[2..22] == h160[..] {
                    return Some(DecodedScript { pubkey: pk_bytes.to_vec() });
                }
            }
        }
    }

    if fund_script.is_p2pk() {
        // First instruction must be <pubkey>
        let mut iter = fund_script.instructions();
    
        if let Some(Ok(Instruction::PushBytes(pk_bytes))) = iter.next() {
    
            return Some(DecodedScript {
                pubkey: pk_bytes.as_bytes().to_vec()
            });
        }
    }


    None
}

pub fn try_peek_pubkey<'a>(
    fund_script: &'a ScriptBuf,
    spend_script: &'a ScriptBuf,
    witness: &'a Witness,
) -> Option<&'a [u8]> {
    // P2TR: bytes 2..34
    if fund_script.is_p2tr() && fund_script.len() == 34 {
        return Some(&fund_script.as_bytes()[2..34]);
    }

    // P2WPKH or P2SH-P2WPKH: witness[1]
    if fund_script.is_p2wpkh() || fund_script.is_p2sh() {
        if witness.len() >= 2 {
            return Some(&witness[1]);
        }
    }

    // P2PKH: script_sig second push
    if fund_script.is_p2pkh() {
        let mut pushes = spend_script.instructions().filter_map(|i| {
            if let Ok(Instruction::PushBytes(b)) = i { Some(b) } else { None }
        });

        pushes.next(); // skip sig
        return pushes.next().map(|b| b.as_bytes());
    }

    None
}


pub static LOOP_INTERVAL: u64 = 1000;

pub struct IndexerRuntimeConfig<'a> {
    pub rpc: &'a BitcoinRpcConfig,
    pub indexer: &'a IndexerConfig
} 

pub static PUBKEY_SIZE: usize = 33;

pub fn run_indexer<'a>(config: IndexerRuntimeConfig<'a>) {
    let db = state::get();
    let direct_db_handle = DBHandle::Direct(&db);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();


    let cache_size: usize = ((config.indexer.mem_alloc_pubkey_hset* 1_000_000) / PUBKEY_SIZE)*2;
    let mut pubkey_cache = GrpHashset::new(cache_size);

    println!("{}: {}mb", "Using a max_alloc for pubkey_hset of".green().bold(), config.indexer.mem_alloc_pubkey_hset);

    ctrlc::set_handler(move || {
        shutdown_signal.store(true, Ordering::SeqCst);
        eprintln!("{}", "\nCTRL+C received. Shutting down...".yellow().bold());
    }).expect("Error setting Ctrl-C handler");

    let rpc_client = RetryClient { client: Client::new(
        &config.rpc.rpc_url,
        Auth::UserPass(
            config.rpc.rpc_user.to_string(),
            config.rpc.rpc_password.to_string(),
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


    let indexer_state = get_indexer_state(&direct_db_handle, &rpc_client);

    let expected_parent = indexer_state.indexer_tip_hash.to_string();
    let actual_parent = RpcApi::get_block_hash(&rpc_client, indexer_state.indexer_height.into()).unwrap_or_else(|err|{
        eprintln!("{}: {}", "An error ocurred getting block hash",err);
        panic!()
    }).to_string();

    if expected_parent != actual_parent {
        eprintln!("{}, expected parent: {}, got: {}", "Reorg detected! Local DB is out of sync with node.".red().bold(), expected_parent, actual_parent);
        panic!();
    }


    loop {

        let indexer_state = get_indexer_state(&direct_db_handle, &rpc_client);

        println!(
            "{}: {}/{}",
            "[INDEXER] Indexing @ state: ".cyan(),
            indexer_state.indexer_height,
            indexer_state.chain_height
        );

        let mut log_iter: u32 = 0;
        let mut total_ms_utx: u128 = 0;
        let mut total_ms_pmap: u128 = 0;
        let mut total_ms_write: u128 = 0;
        let mut total_tx_amount: usize = 0;
        let mut total_cache_hits: usize = 0;
        let mut total_utxo_mappings: usize = 0;
        let mut total_ms_rpc: u128 = 0;
        let mut total_ms_sutxo: u128 = 0;
        let mut a_time = std::time::Instant::now(); // Start timer

        for height in indexer_state.indexer_height..indexer_state.chain_height {

            let mut new_utxo_mappings = 0;

            //batch is managed by the indexer loop and propagated down
            let batch = WriteBatchWithCache::new();
            let mut db_handle: DBHandle = DBHandle::Staged(batch);

            let rpc_time = std::time::Instant::now(); // Start timer

            let block_hash = RpcApi::get_block_hash(&rpc_client, height.into()).unwrap_or_else(|err|{
                eprintln!("{}: {}", "An error ocurred getting block hash",err);
                panic!()
            });

            let block = RpcApi::get_block(&rpc_client, &block_hash).unwrap_or_else(|err| {
                eprintln!("{}: {}", "An error ocurred getting block hash",err);
                panic!()
            });

            let rpc_elapsed = rpc_time.elapsed().as_millis();
            
            let t_utx = std::time::Instant::now(); // Start timer

            for transaction in &block.txdata {
                // save new utxos
                for vout_index in 0..transaction.output.len() {
                    let vout = &transaction.output[vout_index];
            
                    let outpoint: OutPoint = OutPoint {
                        txid: transaction.compute_txid(),
                        vout: vout_index
                            .try_into()
                            .expect(&"failed to parse vout index into u32".red().bold()),
                    };
                    

                    new_utxo_mappings += 1;
            
                    match db::save_utxo_script_mapping(&mut db_handle, outpoint, &vout.script_pubkey) {
                        Ok(()) => continue,
                        Err(err) => {
                            eprintln!(
                                "{}: {}",
                                "An error occurred saving utxo".red().bold(),
                                err
                            );
                            panic!()
                        }
                    };
                }
            }
            
            let ms_utx = t_utx.elapsed().as_millis();

            let sutxo_time = std::time::Instant::now(); // Start timer
            //save mappings
            let vins: Vec<&TxIn> = (&block.txdata).iter().map(|tx|&tx.input).flatten().collect();
            let mut utxo_address_map = db::bulk_get_utxo_script_mappings(&db_handle, &vins);
            let mut new_pmap_mappings = 0;
            let sutxo_elapsed = sutxo_time.elapsed().as_millis();


            let t_pmap = std::time::Instant::now(); // Start timer
            let mut cache_hits:usize = 0;
            for vin in vins {
                let outpoint_key = get_utxo_db_key(vin.previous_output);
            
                let fund_script_bytes = match utxo_address_map.get(&outpoint_key) {
                    Some(script) => script.to_owned(),
                    None => continue,
                };
            
                let fund_script = ScriptBuf::from_bytes(fund_script_bytes.clone());
                let seek_pubkey = try_peek_pubkey(&fund_script, &vin.script_sig, &vin.witness).unwrap_or_default();
                if pubkey_cache.contains(&seek_pubkey) { 
                    cache_hits += 1;
                    continue; 
                };

                let mut decoded_script = match get_pub_key(&fund_script_bytes, &vin.script_sig, &vin.witness) {
                    Some(decoded_script) => decoded_script,
                    None => continue,
                };

                let _ = decoded_script.compress_if_necessary();
                
                pubkey_cache.insert(if seek_pubkey.len() != 0 { &seek_pubkey } else { &decoded_script.pubkey });

                if let Err(err) = db::save_decoded_script_mapping(
                    &mut db_handle,
                    &decoded_script.pubkey,
                    &outpoint_key,
                ) {
                    eprintln!(
                        "{}: {}",
                        "Failed to save decoded script mapping".red().bold(),
                        err
                    );
                    panic!();
                }
            
                utxo_address_map.remove(&fund_script_bytes);

                new_pmap_mappings += 4;
            }
            
            let ms_pmap = t_pmap.elapsed().as_millis();




            let Ok(_) = db::save_new_indexer_tip(&mut db_handle, &IndexerTipState { indexer_height: height, indexer_tip_hash: StoredBlockHash(block_hash) }) else {
                
                
                    eprintln!("{}", "An error ocurred while saving indexer height".red().bold());
                    panic!()
                
            };
            let w_time = std::time::Instant::now(); // Start timer

            let inner_batch: rocksdb::WriteBatchWithTransaction<false> = db_handle.into_inner().expect("Tried reading inner from db direct instance");

            if let Err(err) = db.write(inner_batch){
                eprintln!("{}: {}", "Failed to write inner batch".red().bold(), err);
                panic!();
            }
            let w_elapsed = w_time.elapsed().as_millis();

            log_iter += 1;

            total_ms_utx += ms_utx;
            total_ms_pmap += ms_pmap;
            total_tx_amount += block.txdata.len();
            total_ms_write += w_elapsed;
            total_cache_hits += cache_hits;
            total_utxo_mappings += new_utxo_mappings;
            total_ms_rpc += rpc_elapsed;
            total_ms_sutxo += sutxo_elapsed;

            if log_iter >= config.indexer.log_interval{
                let elapsed = a_time.elapsed().as_millis();
                a_time = std::time::Instant::now();

                println!(
                    "{} processed UTXOs: {} outputs in {} ms",
                    "[INDEXER]".blue().bold(),
                    total_utxo_mappings.to_string().cyan(),
                    total_ms_utx.to_string().yellow()
                );

                println!(
                    "{} processed VIN mappings: {} entries in {} ms. Cache hits -> {}",
                    "[INDEXER]".blue().bold(),
                    new_pmap_mappings.to_string().cyan(),
                    total_ms_pmap.to_string().yellow(),
                    total_cache_hits.to_string().green().bold()
                );
                
                println!(
                    "{} Cumulative write time (ms): {}",
                    "[INDEXER]".blue().bold(),
                    total_ms_write.to_string().yellow(),

                );

                println!(
                    "{} Cumulative RPC time (ms): {}",
                    "[INDEXER]".blue().bold(),
                    total_ms_rpc.to_string().cyan(),

                );

                println!(
                    "{} Cumulative SUTXO save time (ms): {}",
                    "[INDEXER]".blue().bold(),
                    total_ms_sutxo.to_string().yellow(),

                );

                println!("{}: #{} -> {}, with {} transactions. Total time: {}ms", "[INDEXER] Processed blocks".blue().bold(), (height - config.indexer.log_interval).to_string().yellow(), height.to_string().green().bold(), &total_tx_amount, elapsed.to_string().yellow().bold());
                println!("{}: {}", "Pubkey Hashset size -> ".yellow().bold(), &pubkey_cache.count);
                log_iter = 0;
                total_ms_pmap = 0;
                total_ms_utx = 0;
                total_tx_amount = 0;
                total_ms_write = 0;
                total_cache_hits = 0;
                total_utxo_mappings = 0;
                total_ms_rpc = 0;
                total_ms_sutxo = 0;
            }

        }
        println!(
            "{}{}{}",
            "[INDEXER] Block chunk finished processing, waiting ".yellow(),
            LOOP_INTERVAL.to_string().yellow(),
            "ms before checking for new state".yellow()
        );
        ::std::thread::sleep(::std::time::Duration::from_millis(LOOP_INTERVAL));


    }

}
