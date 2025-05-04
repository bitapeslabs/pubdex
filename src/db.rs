use crate::chain::{ENABLED_NETWORK_HRP, ENABLED_NETWORK_KIND, GENESIS_HASH};
use crate::state;
use bitcoin::hashes::Hash;
use bitcoin::{
    secp256k1, Address, BlockHash, CompressedPublicKey, OutPoint, PublicKey, ScriptBuf, TxIn,
    XOnlyPublicKey,
};
use colored::Colorize;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::collections::HashMap;
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

pub struct UTXO {
    pub outpoint: OutPoint,
}
#[derive(Serialize, Deserialize)]
pub struct AddressMapping {
    p2tr: String,
    p2wpkh: String,
    p2shp2wpkh: String,
    p2pkh: String,
}

#[derive(Debug)]
pub enum AddressDecodeError {
    InvalidUtf8(&'static str),
    MalformedSeparator,
    InvalidAddressType,
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

//Key formatters

pub fn get_utxo_db_key_from_bytes(bytes: &Vec<u8>) -> Vec<u8> {
    let db_key_slice = b"utxo: ";

    let mut map_key = Vec::with_capacity(db_key_slice.len() + bytes.len());
    map_key.extend_from_slice(db_key_slice);
    map_key.extend_from_slice(&bytes);
    map_key
}

pub fn get_utxo_db_key(utxo: OutPoint) -> Vec<u8> {
    let bytes: [u8; 36] = (UTXO { outpoint: utxo }).into();

    get_utxo_db_key_from_bytes(&bytes.to_vec())
}

//address -> publicKey
pub fn get_amap_db_key(address: &String) -> Vec<u8> {
    let db_key_slice = b"amap: ";
    let address_bytes = address.as_bytes();

    let mut map_key = Vec::with_capacity(db_key_slice.len() + address_bytes.len());
    map_key.extend_from_slice(db_key_slice);
    map_key.extend_from_slice(&address_bytes);
    map_key
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

pub fn save_utxo_script_mapping(utxo: OutPoint, script: &ScriptBuf) -> Result<(), DBError> {
    let db = state::get();

    let map_key = get_utxo_db_key(utxo);

    match db.put(map_key, script.as_bytes()) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("{}: {}", "Failed to save UTXO".red().bold(), e);
            return Err(e.into());
        }
    }
}

// Get all associated utxo -> address mappings for a block in one rocksdb call
pub fn bulk_get_utxo_script_mappings(vins: &Vec<&TxIn>) -> HashMap<Vec<u8>, Vec<u8>> {
    let db = state::get();

    let utxo_keys: Vec<Vec<u8>> = vins
        .iter()
        .map(|vin| get_utxo_db_key(vin.previous_output))
        .collect();

    let mut utxo_script_map = HashMap::with_capacity(utxo_keys.len());
    let db_response = db.multi_get(&utxo_keys);

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

pub fn create_p2sh_p2wpkh(p2wpkh_address: &Address) -> String {
    let redeem_script = p2wpkh_address.script_pubkey();

    Address::p2sh(&redeem_script, *ENABLED_NETWORK_KIND)
        .expect(&"Failed to get p2sh_p2wpkh from pubkey".red().bold())
        .to_string()
}

pub fn get_address_mapping_from_pubkey(pubkey_bytes: &Vec<u8>) -> Option<AddressMapping> {
    //Were trying to pass in a p2pk, which we cant parse
    if pubkey_bytes.len() != 33 {
        return None;
    }

    let secp = secp256k1::Secp256k1::verification_only();

    // 1. Parse the 33‑byte compressed key (0x02/0x03 prefix).
    let public_key = PublicKey::from_slice(pubkey_bytes).expect(
        &"public_key slice errpr: expected 33‑byte compressed pubkey"
            .red()
            .bold(),
    );

    let compressed_pk: CompressedPublicKey = public_key.try_into().unwrap_or_else(|err| {
        eprintln!(
            "{}: {}",
            "Unexpected failure: compressed already, so try_into() must succeed"
                .red()
                .bold(),
            err
        );
        panic!();
    });

    let xonly = XOnlyPublicKey::from_slice(&pubkey_bytes[1..])
        .expect(&"x only slice error: valid x‑only key".red().bold());

    let p2pkh = Address::p2pkh(&public_key, *ENABLED_NETWORK_KIND).to_string();
    let p2wpkh = Address::p2wpkh(&compressed_pk, *ENABLED_NETWORK_HRP);
    let p2shp2wpkh = create_p2sh_p2wpkh(&p2wpkh);
    let p2tr = Address::p2tr(&secp, xonly, None, *ENABLED_NETWORK_HRP).to_string();

    Some(AddressMapping {
        p2pkh,
        p2wpkh: p2wpkh.to_string(),
        p2shp2wpkh,
        p2tr,
    })
}

//pubkey:{pubkey bytes}:{address mapping} ====> address mapping: 0x0a as seperator, first byte is u8 and defines addr type for parser. ex: [u8, [u8,unsized]]0x0a[u8, [u8,unsized]]
//address:{address utf8 bytes}:{pubkey}
pub fn save_decoded_script_mapping(
    pubkey: &Vec<u8>,
    delete_outpoint: &Vec<u8>, //we free up disk storage by deleting utxo mappings once they are used.
) -> Result<(), DBError> {
    let db = state::get();

    let Some(address_map) = get_address_mapping_from_pubkey(pubkey) else {
        let utxo_key = get_utxo_db_key_from_bytes(delete_outpoint);
        db.delete(utxo_key)?;
        return Ok(());
    };

    let search_keys = vec![
        address_map.p2tr,
        address_map.p2pkh,
        address_map.p2shp2wpkh,
        address_map.p2wpkh,
    ]
    .into_iter()
    .map(|key| get_amap_db_key(&key));

    let db_response = db.multi_get(search_keys.clone());

    for (search_key, result) in search_keys.zip(db_response) {
        match result {
            Ok(Some(_)) => continue,
            Ok(None) => {
                db.put(search_key, &pubkey)?;
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

pub fn get_aliases_from_pubkey(pubkey: &Vec<u8>) -> AliasResponse {
    let address_mapping = get_address_mapping_from_pubkey(pubkey);
    AliasResponse {
        pubkey: hex::encode(pubkey),
        aliases: address_mapping,
    }
}

pub fn get_aliases_from_address(address: &String) -> Option<AliasResponse> {
    let db = state::get();

    match db.get(get_amap_db_key(address)) {
        Ok(Some(pubkey)) => Some(get_aliases_from_pubkey(&pubkey)),
        Ok(None) => None,
        Err(err) => {
            println!(
                "{}: {}",
                "WARN: An error ocurred while getting amap key", err
            );
            None
        }
    }
}
