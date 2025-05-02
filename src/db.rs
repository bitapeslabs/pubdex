use crate::state;
use colored::Colorize;
use rocksdb::{Options, DB};
use std::array::TryFromSliceError;
use std::fmt;

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

pub fn get_indexer_tip() -> Result<u32, DBError> {
    let db = state::get();
    match db.get("block_tip") {
        Ok(Some(result)) => {
            let bytes: [u8; 4] = result.as_slice().try_into()?;
            Ok(u32::from_le_bytes(bytes))
        }

        Ok(None) => Ok(0),

        Err(e) => {
            eprintln!("{}: {}", "Err: Failed to get block tip!".red().bold(), e);
            return Err(e.into());
        }
    }
}
