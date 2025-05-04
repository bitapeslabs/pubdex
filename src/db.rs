use crate::chain::GENESIS_HASH;
use crate::indexer::{DecodedScript, IndexerAddressType};
use crate::state;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, ScriptBuf, TxIn};
use colored::Colorize;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

const SEPARATOR_BYTE: u8 = 0x0A;

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
pub struct DecodedAddressMapping {
    p2tr: Option<String>,
    p2shp2wpkh: Option<String>,
    p2pkh: Option<String>,
    p2pk: Option<String>,
}

#[derive(Debug)]
pub enum AddressDecodeError {
    InvalidUtf8(&'static str),
    MalformedSeparator,
    InvalidAddressType,
}

fn try_utf8(
    buf: Option<Vec<u8>>,
    label: &'static str,
) -> Result<Option<String>, AddressDecodeError> {
    match buf {
        Some(b) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| AddressDecodeError::InvalidUtf8(label)),
        None => Ok(None),
    }
}

impl TryFrom<Vec<u8>> for DecodedAddressMapping {
    type Error = AddressDecodeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut p2tr_buffer: Option<Vec<u8>> = None;
        let mut p2shp2wpkh_buffer: Option<Vec<u8>> = None;
        let mut p2pkh_buffer: Option<Vec<u8>> = None;
        let mut p2pk_buffer: Option<Vec<u8>> = None;

        let mut current_buffer: Option<&mut Vec<u8>> = None;

        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];

            if byte == SEPARATOR_BYTE {
                if i + 1 >= bytes.len() {
                    return Err(AddressDecodeError::MalformedSeparator);
                }

                let Ok(address_type) = bytes[i + 1].try_into() else {
                    return Err(AddressDecodeError::InvalidAddressType);
                };

                match address_type {
                    IndexerAddressType::P2TR => {
                        p2tr_buffer = Some(vec![]);
                        current_buffer = p2tr_buffer.as_mut();
                    }
                    IndexerAddressType::P2SHP2WPKH => {
                        p2shp2wpkh_buffer = Some(vec![]);
                        current_buffer = p2shp2wpkh_buffer.as_mut();
                    }
                    IndexerAddressType::P2PKH => {
                        p2pkh_buffer = Some(vec![]);
                        current_buffer = p2pkh_buffer.as_mut();
                    }
                    IndexerAddressType::P2PK => {
                        p2pk_buffer = Some(vec![]);
                        current_buffer = p2pk_buffer.as_mut();
                    }
                }

                i += 2;
                continue;
            }

            if let Some(buf) = current_buffer.as_mut() {
                buf.push(byte);
            }

            i += 1;
        }

        let p2tr = try_utf8(p2tr_buffer, "p2tr")?;
        let p2shp2wpkh = try_utf8(p2shp2wpkh_buffer, "p2shp2wpkh")?;
        let p2pkh = try_utf8(p2pkh_buffer, "p2pkh")?;
        let p2pk = try_utf8(p2pk_buffer, "p2pk")?;

        Ok(DecodedAddressMapping {
            p2tr,
            p2shp2wpkh,
            p2pkh,
            p2pk,
        })
    }
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

//publicKey -> addressMap key
pub fn get_pmap_db_key(pubkey: &Vec<u8>) -> Vec<u8> {
    let db_key_slice = b"pmap: ";
    let mut map_key = Vec::with_capacity(db_key_slice.len() + pubkey.len());
    map_key.extend_from_slice(db_key_slice);
    map_key.extend_from_slice(&pubkey);
    map_key
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

pub struct AddressMapping {
    pub decoded: DecodedAddressMapping,
    pub bytes: Vec<u8>,
}

pub fn get_address_mapping_from_pubkey(pubkey: &Vec<u8>) -> Option<AddressMapping> {
    let db = state::get();
    let map_key = get_pmap_db_key(pubkey);

    let db_response = match db.get(map_key) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return None.into();
        }
        Err(err) => {
            eprintln!("{}: {}", "Failed to get pmap from DB".red().bold(), err);
            panic!();
        }
    };

    let Ok(decoded) = db_response.clone().try_into() else {
        eprintln!(
            "{}",
            "Failed to get pmap from DB: decode error".red().bold()
        );
        panic!();
    };

    Some(AddressMapping {
        decoded,
        bytes: db_response,
    })
}

//pubkey:{pubkey bytes}:{address mapping} ====> address mapping: 0x0a as seperator, first byte is u8 and defines addr type for parser. ex: [u8, [u8,unsized]]0x0a[u8, [u8,unsized]]
//address:{address utf8 bytes}:{pubkey}
pub fn save_decoded_script_mapping(
    decoded_script: &DecodedScript,
    address: &String,
    delete_outpoint: &Vec<u8>, //we free up disk storage by deleting utxo mappings once they are used.
) -> Result<(), DBError> {
    let db = state::get();

    let address_mapping = get_address_mapping_from_pubkey(&decoded_script.pubkey);

    let is_modify: bool = match &address_mapping {
        Some(address_mapping) => {
            let decoded_mapping = &address_mapping.decoded;

            match &decoded_script.address_type {
                IndexerAddressType::P2PKH => decoded_mapping.p2pkh.is_none(),
                IndexerAddressType::P2SHP2WPKH => decoded_mapping.p2shp2wpkh.is_none(),
                IndexerAddressType::P2TR => decoded_mapping.p2tr.is_none(),
                IndexerAddressType::P2PK => decoded_mapping.p2pk.is_none(),
            }
        }
        None => true,
    };

    let prefix_bytes: &[u8] = address_mapping
        .as_ref()
        .map(|a| a.bytes.as_slice())
        .unwrap_or(&[]);

    if is_modify {
        let mut new_bytes: Vec<u8> =
            vec![SEPARATOR_BYTE, decoded_script.address_type.clone() as u8];
        new_bytes.extend_from_slice(address.as_bytes());

        let pmap_key = get_pmap_db_key(&decoded_script.pubkey);
        let mut new_value = Vec::with_capacity(prefix_bytes.len() + new_bytes.len());
        new_value.extend_from_slice(&prefix_bytes);
        new_value.extend_from_slice(&new_bytes);

        db.put(&pmap_key, &new_value)?;

        let amap_key = get_amap_db_key(address);

        db.put(&amap_key, &decoded_script.pubkey)?;
    }

    let utxo_key = get_utxo_db_key_from_bytes(delete_outpoint);

    db.delete(utxo_key)?;

    Ok(())
}
#[derive(Serialize, Deserialize)]
pub struct AliasResponse {
    pub pubkey: String,
    pub aliases: DecodedAddressMapping,
}

pub fn get_aliases_from_pubkey(pubkey: &Vec<u8>) -> Option<AliasResponse> {
    let decoded_address_mapping = get_address_mapping_from_pubkey(pubkey)?;
    Some(AliasResponse {
        pubkey: hex::encode(pubkey),
        aliases: decoded_address_mapping.decoded,
    })
}
