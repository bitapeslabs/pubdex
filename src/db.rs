use crate::blockchain::errors::BlockchainError;
use crate::blockchain::{
    utils::get_address_mapping_from_pubkey, utils::AddressMapping, utils::UTXO,
};
use crate::chain::GENESIS_HASH;
use crate::state;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, ScriptBuf, TxIn};
use colored::Colorize;
use rocksdb::{Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::collections::HashMap;

use std::str::FromStr;
use std::sync::Arc;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DBError {
    #[error("Error: {0}")]
    Error(String),

    #[error("Slice conversion error: {0}")]
    SliceConversion(#[from] TryFromSliceError),

    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),

    #[error("Blockchain error: {0}")]
    BlockchainError(#[from] BlockchainError),
}
impl DBError {
    pub fn from<T: Into<String>>(err: T) -> Self {
        DBError::Error(err.into())
    }
}

pub struct StoredBlockHash(pub BlockHash);

impl From<Vec<u8>> for StoredBlockHash {
    fn from(byte_vector: Vec<u8>) -> Self {
        StoredBlockHash(BlockHash::from_byte_array(
            byte_vector
                .try_into()
                .expect(&"Failed to parse block hash into byte array".red().bold()),
        ))
    }
}

impl From<&str> for StoredBlockHash {
    fn from(string: &str) -> Self {
        StoredBlockHash(
            BlockHash::from_str(string).expect(
                &"Failed to parse genesis hash into bitcoin::Blockhash"
                    .red()
                    .bold(),
            ),
        )
    }
}

impl From<IndexerTipState> for IndexerTipStateSerializable {
    fn from(tip_state: IndexerTipState) -> Self {
        IndexerTipStateSerializable {
            indexer_height: tip_state.indexer_height,
            indexer_tip_hash: tip_state.indexer_tip_hash.0.to_string(),
        }
    }
}
pub struct WriteBatchWithCache {
    pub write_batch: WriteBatch,
    pub cache: HashMap<Vec<u8>, Vec<u8>>,
}

pub trait BatchManager {
    fn new() -> Self;

    fn into_inner(self) -> WriteBatch;

    //cache getters never touch the disk
    fn get_from_cache(&self, bytes: &Vec<u8>) -> Option<Vec<u8>>;
    fn multi_get_from_cache(&self, keys: &Vec<Vec<u8>>) -> Vec<Option<Vec<u8>>>;

    //writing to cache will always succeed since its an inmemory hashmap
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>);

    fn delete(&mut self, key: &Vec<u8>);

    //These will first search the cache of the WriteBatch, and, if not found, call the db
    fn get_deep(&self, key: &Vec<u8>) -> Result<Option<Vec<u8>>, rocksdb::Error>;

    fn multi_get_deep(&self, keys: &Vec<Vec<u8>>) -> Vec<Result<Option<Vec<u8>>, rocksdb::Error>>;
}

impl BatchManager for WriteBatchWithCache {
    fn new() -> Self {
        WriteBatchWithCache {
            write_batch: WriteBatch::default(),
            cache: HashMap::new(),
        }
    }

    fn into_inner(self) -> WriteBatch {
        self.write_batch
    }

    fn get_from_cache(&self, key: &Vec<u8>) -> Option<Vec<u8>> {
        self.cache.get(key).map(|result| result.clone())
    }

    fn multi_get_from_cache(&self, keys: &Vec<Vec<u8>>) -> Vec<Option<Vec<u8>>> {
        keys.iter().map(|key| self.get_from_cache(key)).collect()
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.write_batch.put(&key, &value);
        self.cache.insert(key, value);
    }

    fn delete(&mut self, key: &Vec<u8>) {
        self.write_batch.delete(key);
        self.cache.remove(key);
    }

    fn get_deep(&self, key: &Vec<u8>) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        match self.get_from_cache(key) {
            Some(result) => Ok(Some(result)),
            None => {
                let db = state::get();
                db.get(key)
            }
        }
    }

    fn multi_get_deep(&self, keys: &Vec<Vec<u8>>) -> Vec<Result<Option<Vec<u8>>, rocksdb::Error>> {
        let db = state::get();
        let mut results: HashMap<Vec<u8>, Result<Option<Vec<u8>>, rocksdb::Error>> = HashMap::new();
        for (key, option_value) in keys.iter().zip(self.multi_get_from_cache(keys)) {
            if let Some(value) = option_value {
                results.insert(key.clone(), Ok(Some(value)));
            }
        }
        let misses: Vec<&[u8]> = keys
            .iter()
            .filter(|k| !results.contains_key(*k))
            .map(|k| k.as_slice())
            .collect();

        for (i, db_res) in db.multi_get(&misses).into_iter().enumerate() {
            results.insert(misses[i].to_vec(), db_res);
        }
        keys.iter()
            .map(|k| results.remove(k).unwrap_or(Ok(None)))
            .collect()
    }
}

pub enum DBHandle<'a> {
    Direct(&'a Arc<DB>),
    Staged(WriteBatchWithCache),
}

impl<'a> DBHandle<'a> {
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        match self {
            DBHandle::Direct(db) => db.get(key),
            DBHandle::Staged(batch) => batch.get_deep(&key.to_vec()),
        }
    }

    pub fn into_inner(self) -> Option<WriteBatch> {
        match self {
            DBHandle::Direct(_) => None,
            DBHandle::Staged(batch) => Some(batch.into_inner()),
        }
    }

    pub fn multi_get(&self, keys: &Vec<Vec<u8>>) -> Vec<Result<Option<Vec<u8>>, rocksdb::Error>> {
        match self {
            DBHandle::Direct(db) => db.multi_get(keys.iter().map(|k| k.as_slice())),
            DBHandle::Staged(batch) => batch.multi_get_deep(keys),
        }
    }

    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), rocksdb::Error> {
        match self {
            DBHandle::Direct(db) => db.put(&key, &value),
            DBHandle::Staged(batch) => {
                batch.put(key, value);
                Ok(())
            }
        }
    }

    pub fn delete(&mut self, key: Vec<u8>) -> Result<(), rocksdb::Error> {
        match self {
            DBHandle::Direct(db) => db.delete(&key),
            DBHandle::Staged(batch) => {
                batch.delete(&key);
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum AddressDecodeError {
    InvalidUtf8(&'static str),
    MalformedSeparator,
    InvalidAddressType,
}

//Key formatters

pub fn get_key(path: &[u8], key: &[u8]) -> Vec<u8> {
    let mut map_key = Vec::with_capacity(path.len() + key.len());
    map_key.extend_from_slice(path);
    map_key.extend_from_slice(key);
    map_key
}

pub fn get_utxo_db_key_from_bytes(bytes: &[u8]) -> Vec<u8> {
    get_key(b"utxo:", bytes)
}

pub fn get_utxo_db_key(utxo: OutPoint) -> Vec<u8> {
    let bytes: [u8; 36] = (UTXO { outpoint: utxo }).into();

    get_utxo_db_key_from_bytes(&bytes)
}

//address -> publicKey
pub fn get_amap_db_key(address: &String) -> Vec<u8> {
    get_key(b"amap:", address.as_bytes())
}

pub fn get_cnt_pk_key() -> Vec<u8> {
    b"cnt:pk".to_vec()
}

pub fn get_pk_key_from_id_bytes(id: &[u8]) -> Vec<u8> {
    get_key(b"pk:", id)
}

pub fn create_database(path: &str) -> Result<DB, DBError> {
    let mut options = Options::default();
    options.set_error_if_exists(false);
    options.create_if_missing(true);
    options.create_missing_column_families(true);

    // list existing ColumnFamilies in the given path. returns Err when no DB exists.
    let cfs = DB::list_cf(&options, path).unwrap_or(vec![]);
    let pubdex_family_exists = cfs.iter().find(|cf| cf == &"pubdex").is_none();

    // open a DB with specifying ColumnFamilies
    let mut instance = DB::open_cf(&options, path, cfs).unwrap();

    if pubdex_family_exists {
        // create a new ColumnFamily
        let options = Options::default();
        instance.create_cf("pubdex", &options).unwrap();
    }
    Result::Ok(instance)
}

pub struct IndexerTipState {
    pub indexer_height: u32,
    pub indexer_tip_hash: StoredBlockHash,
}
#[derive(Serialize, Deserialize)]
pub struct IndexerTipStateSerializable {
    pub indexer_height: u32,
    pub indexer_tip_hash: String,
}

pub fn get_indexer_tip(db: &DBHandle) -> Result<IndexerTipState, DBError> {
    let indexer_height = match db.get(b"indexer_height") {
        Ok(Some(result)) => {
            let bytes: [u8; 4] = result.as_slice().try_into()?;
            u32::from_le_bytes(bytes)
        }

        Ok(None) => 0,

        Err(e) => {
            eprintln!("{}: {}", "Failed to get block tip".red().bold(), e);
            return Err(e.into());
        }
    };

    let indexer_tip_hash: StoredBlockHash = match db.get(b"indexer_tip_hash") {
        Ok(Some(result)) => result.into(),

        Ok(None) => GENESIS_HASH.into(),

        Err(e) => {
            eprintln!("{}: {}", "Failed to get block tip".red().bold(), e);
            return Err(e.into());
        }
    };

    Ok(IndexerTipState {
        indexer_height,
        indexer_tip_hash,
    })
}

pub fn save_new_indexer_tip(db: &mut DBHandle, new_state: &IndexerTipState) -> Result<(), DBError> {
    db.put(
        b"indexer_height".to_vec(),
        new_state.indexer_height.to_le_bytes().to_vec(),
    )
    .map_err(|e| {
        eprintln!(
            "{}: {}",
            "Failed to save new indexer height".red().bold(),
            e
        );
        DBError::from(e)
    })?;

    db.put(
        b"indexer_tip_hash".to_vec(),
        new_state.indexer_tip_hash.0.to_byte_array().to_vec(),
    )
    .map_err(|e| {
        eprintln!(
            "{}: {}",
            "Failed to save new indexer tip hash".red().bold(),
            e
        );
        DBError::from(e)
    })?;

    Ok(())
}

pub fn save_utxo_script_mapping(
    db: &mut DBHandle,
    utxo: OutPoint,
    script: &ScriptBuf,
) -> Result<(), DBError> {
    let map_key = get_utxo_db_key(utxo);

    match db.put(map_key, script.as_bytes().to_vec()) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("{}: {}", "Failed to save UTXO".red().bold(), e);
            return Err(e.into());
        }
    }
}

// Get all associated utxo -> address mappings for a block in one rocksdb call
pub fn bulk_get_utxo_script_mappings(
    db: &DBHandle,
    vins: &Vec<&TxIn>,
) -> HashMap<Vec<u8>, Vec<u8>> {
    let utxo_keys: Vec<Vec<u8>> = vins
        .iter()
        .map(|vin| get_utxo_db_key(vin.previous_output))
        .collect();

    let mut utxo_script_map = HashMap::with_capacity(utxo_keys.len());
    let db_response: Vec<Result<Option<Vec<u8>>, rocksdb::Error>> = db.multi_get(&utxo_keys);

    for (utxo_key, result) in utxo_keys.iter().zip(db_response) {
        match result {
            Ok(Some(script_bytes)) => {
                utxo_script_map.insert(
                    //Slice the bytes of b"utxo: "
                    utxo_key.to_vec(),
                    script_bytes,
                );
                continue;
            }
            Ok(None) => continue,
            Err(err) => {
                eprintln!(
                    "{}: {}",
                    "Failed to get byte array in utxo_script_mappings from DB: "
                        .red()
                        .bold(),
                    err
                );
                panic!();
            }
        };
    }

    utxo_script_map
}

//pubkey:{pubkey bytes}:{address mapping} ====> address mapping: 0x0a as seperator, first byte is u8 and defines addr type for parser. ex: [u8, [u8,unsized]]0x0a[u8, [u8,unsized]]
//address:{address utf8 bytes}:{pubkey}
pub fn save_decoded_script_mapping(
    db: &mut DBHandle,
    pubkey: &Vec<u8>,
    delete_outpoint: &Vec<u8>, //we free up disk storage by deleting utxo mappings once they are used.
) -> Result<(), DBError> {
    if hex::encode(pubkey).contains("69ab4181eceb28985b9b4e895c13fa5e68d85761b7eee311db5addef76fa8621865134a221bd01f28ec9999ee3e021e60766e9d1f3458c115fb28650605f11c9ac"){
        println!(
            "{}",
            "FOUND NEEDLE HEX!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                .yellow()
                .bold()
        )
    }

    let Ok(address_map) = get_address_mapping_from_pubkey(pubkey) else {
        let utxo_key = get_utxo_db_key_from_bytes(delete_outpoint);
        db.delete(utxo_key)?;
        return Ok(());
    };

    let search_keys: Vec<Vec<u8>> = vec![
        address_map.p2tr,
        address_map.p2pkh,
        address_map.p2shp2wpkh,
        address_map.p2wpkh,
    ]
    .into_iter()
    .flatten()
    .map(|key| get_amap_db_key(&key))
    .collect();

    let db_response = db.multi_get(&search_keys);

    let count_key = get_cnt_pk_key();

    let pubkey_count = db
        .get(&count_key)?
        .map(|bytes| {
            u64::from_le_bytes(bytes.try_into().expect("Expected 8 bytes for pubkey_count"))
        })
        .unwrap_or(0)
        + 1;
    let pubkey_id_key = get_pk_key_from_id_bytes(&pubkey_count.to_le_bytes());

    db.put(pubkey_id_key, pubkey.to_vec())?;
    db.put(count_key, pubkey_count.to_le_bytes().to_vec())?;

    for (search_key, result) in search_keys.iter().zip(db_response) {
        match result {
            Ok(Some(_)) => continue,
            Ok(None) => {
                db.put(search_key.clone(), pubkey_count.to_le_bytes().to_vec())?;
            }
            Err(err) => {
                eprintln!(
                    "{}: {}",
                    "Failed to get byte array in utxo_script_mappings from DB: "
                        .red()
                        .bold(),
                    err
                );
                panic!();
            }
        };
    }

    let utxo_key = get_utxo_db_key_from_bytes(delete_outpoint);

    db.delete(utxo_key)?;

    Ok(())
}
#[derive(Serialize, Deserialize)]
pub struct AliasResponse {
    pub pubkey: String,
    pub aliases: Option<AddressMapping>,
}

//Called by API - calls db directly.
pub fn get_aliases_from_pubkey(pubkey: &Vec<u8>) -> Result<AliasResponse, BlockchainError> {
    let address_mapping = get_address_mapping_from_pubkey(&pubkey)?;
    Ok(AliasResponse {
        pubkey: hex::encode(pubkey),
        aliases: Some(address_mapping),
    })
}

pub fn get_aliases_from_address(db: &DBHandle, address: &String) -> Result<AliasResponse, DBError> {
    let Some(pubkey_id) = db.get(&get_amap_db_key(address)).ok().flatten() else {
        return Err(DBError::from("pubkey_id not found"));
    };

    let Some(pubkey) = db.get(&get_pk_key_from_id_bytes(&pubkey_id)).ok().flatten() else {
        return Err(DBError::from("pubkey not found"));
    };

    get_aliases_from_pubkey(&pubkey).map_err(DBError::BlockchainError)
}
