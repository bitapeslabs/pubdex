use crate::config::BitcoinRpcConfig;
use crate::db::{self, get_utxo_db_key, IndexerTipState, StoredBlockHash};
use bitcoin::hashes::Hash;
use bitcoin::key::Parity;
use bitcoin::{secp256k1, Witness};
use bitcoincore_rpc::{Auth, Client, RpcApi, Error as BitcoinRpcError, jsonrpc};
use colored::Colorize;
use core::panic;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use ctrlc;
use bitcoin::{XOnlyPublicKey, BlockHash, OutPoint, ScriptBuf, TxIn, script::Instruction, secp256k1::hashes::hash160};
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

pub fn get_indexer_state(rpc_client: &RetryClient) -> IndexerState{

    //db errors should always panic
    let tip_state = db::get_indexer_tip().unwrap_or_else(|err| {
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



pub struct DecodedScript {
    pub pubkey: Vec<u8>,
    pub address_type: IndexerAddressType
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
                DecodedScript { pubkey: xonly.public_key(Parity::Even).serialize().to_vec(), address_type: IndexerAddressType::P2TR });
        }
    }

    // ── Native SegWit v0 P2WPKH ─────────────────────────────────────
    if fund_script.is_p2wpkh() {
        if witness.len() >= 2 {
            let pk_bytes = &witness[1];
            // sanity‑check: hash160(pubkey) must match program
            let h160 = hash160::Hash::hash(pk_bytes);
            if fund_script.as_bytes()[2..22] == h160[..] {
                return Some(DecodedScript { pubkey: pk_bytes.to_vec(), address_type: IndexerAddressType::P2SHP2WPKH });
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
                return Some(DecodedScript { pubkey: pk_bytes.as_bytes().to_vec(), address_type: IndexerAddressType::P2PKH });
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
                    return Some(DecodedScript { pubkey: pk_bytes.to_vec(), address_type: IndexerAddressType::P2SHP2WPKH });
                }
            }
        }
    }


    None
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

    let indexer_state = get_indexer_state(&rpc_client);

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

        let indexer_state = get_indexer_state(&rpc_client);

        println!(
            "{}: {}/{}",
            "[INDEXER] Indexing @ state: ".cyan(),
            indexer_state.indexer_height,
            indexer_state.chain_height
        );


        for height in indexer_state.indexer_height..indexer_state.chain_height {

            let mut new_utxo_mappings = 0;

            
            let block_hash = RpcApi::get_block_hash(&rpc_client, height.into()).unwrap_or_else(|err|{
                eprintln!("{}: {}", "An error ocurred getting block hash",err);
                panic!()
            });

            let block = RpcApi::get_block(&rpc_client, &block_hash).unwrap_or_else(|err| {
                eprintln!("{}: {}", "An error ocurred getting block hash",err);
                panic!()
            });
            
            for transaction in &block.txdata {


                //save new utxos
                for vout_index in 0..transaction.output.len(){
                    let vout = &transaction.output[vout_index];

                    let outpoint: OutPoint = OutPoint { 
                        txid: transaction.compute_txid(), 
                        vout: vout_index.try_into().expect(&"failed to parse vout index into u32".red().bold()) 
                    };

                    new_utxo_mappings += 1;

                    match db::save_utxo_script_mapping(outpoint, &vout.script_pubkey) {
                        Ok(()) => continue,
                        Err(err) => {
                            eprintln!("{}: {}", "An error ocurred saving utxo".red().bold(),err);
                            panic!()
                        }
                    };

                }
                
            }


            //save mappings
            let vins: Vec<&TxIn> = (&block.txdata).iter().map(|tx|&tx.input).flatten().collect();
            let utxo_address_map = db::bulk_get_utxo_script_mappings(&vins);
            let mut new_pmap_mappings = 0;


            for vin in vins {
                let outpoint_key = get_utxo_db_key(vin.previous_output);

                let fund_script_bytes = match utxo_address_map.get(&outpoint_key){
                    Some(script) => script,
                    None => continue
                };

                
                let decoded_script = match get_pub_key(fund_script_bytes, &vin.script_sig, &vin.witness) {
                    Some(decoded_script) => decoded_script,
                    None => continue,
                };
                

                if let Err(err) = db::save_decoded_script_mapping(&decoded_script.pubkey, &outpoint_key) {
                    eprintln!("{}: {}", "Failed to save decoded script mapping".red().bold(), err);
                    panic!();
                }
                
                new_pmap_mappings += 4;
            };

            println!("{}: #{}, with {} transactions. New pmap/amap values: {} - New utxo_map values: {}", "[INDEXER] Processed block".blue().bold(), height, &block.txdata.len(), new_pmap_mappings, new_utxo_mappings);


            match db::save_new_indexer_tip(&IndexerTipState { indexer_height: height, indexer_tip_hash: StoredBlockHash(block_hash) }) {
                Ok(()) => continue,
                Err(err) => {
                    eprintln!("{}: {}", "An error ocurred while saving indexer height".red().bold(),err);
                    panic!()
                }
            };



        }
    
    }

}
