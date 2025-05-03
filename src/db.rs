use crate::chain::GENESIS_HASH;
use crate::state;
use bitcoin::hashes::Hash;
use bitcoin::{Address, BlockHash, OutPoint};
use colored::Colorize;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::fmt;
use std::str::FromStr;

#[derive(Debug)]
pub enum DBError {
    SliceConversion(TryFromSliceError),
    RocksDB(rocksdb::Error),
}

impl From<TryFromSliceError> for DBError {
    fn from(err: TryFromSliceError) -> Self {
        DBError::SliceConversion(err)
    }
}

impl From<rocksdb::Error> for DBError {
    fn from(err: rocksdb::Error) -> Self {
        DBError::RocksDB(err)
    }
}

impl fmt::Display for DBError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            DBError::SliceConversion(err) => write!(formatter, "Slice Conversion Error: {}", err),
            DBError::RocksDB(err) => write!(formatter, "RocksDB error: {}", err),
        }
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

struct UTXO {
    outpoint: OutPoint,
}

impl From<UTXO> for [u8; 36] {
    fn from(utxo: UTXO) -> Self {
        let txid_bytes = utxo.outpoint.txid.to_byte_array();
        let vout_bytes = utxo.outpoint.vout.to_le_bytes();

        let mut temp = [0u8; 36];
        temp[..32].copy_from_slice(&txid_bytes);
        temp[32..].copy_from_slice(&vout_bytes);
        temp
    }
}

impl std::error::Error for DBError {}

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

pub fn get_indexer_tip() -> Result<IndexerTipState, DBError> {
    let db = state::get();
    let indexer_height = match db.get("indexer_height") {
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

    let indexer_tip_hash: StoredBlockHash = match db.get("indexer_tip_hash") {
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

pub fn save_new_indexer_tip(new_state: &IndexerTipState) -> Result<(), DBError> {
    let db = state::get();

    db.put("indexer_height", new_state.indexer_height.to_le_bytes())
        .map_err(|e| {
            eprintln!(
                "{}: {}",
                "Failed to save new indexer height".red().bold(),
                e
            );
            DBError::from(e)
        })?;

    db.put(
        "indexer_tip_hash",
        new_state.indexer_tip_hash.0.to_byte_array(),
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

pub fn save_utxo_address_mapping(utxo: OutPoint, address: Address) -> Result<(), DBError> {
    let db = state::get();

    let boxed_utxo = UTXO { outpoint: utxo };

    let db_key_slice = b"utxo: ";
    let utxo_key_slice: [u8; 36] = boxed_utxo.into();

    let address_utf8 = address.to_string();
    let address_bytes = address_utf8.as_bytes();

    let mut map_key = Vec::with_capacity(db_key_slice.len() + utxo_key_slice.len());
    map_key.extend_from_slice(db_key_slice);
    map_key.extend_from_slice(&utxo_key_slice);

    match db.put(map_key, address_bytes) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("{}: {}", "Failed to save UTXO".red().bold(), e);
            return Err(e.into());
        }
    }
}
