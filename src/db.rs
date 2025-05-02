use crate::state;
use colored::Colorize;
use rocksdb::{Error, Options, DB};

pub fn create_database(path: &str) -> Result<DB, Error> {
    let mut options = Options::default();
    options.set_error_if_exists(false);
    options.create_if_missing(true);
    options.create_missing_column_families(true);

    // list existing ColumnFamilies in the given path. returns Err when no DB exists.
    let cfs = DB::list_cf(&options, path).unwrap_or(vec![]);
    let my_column_family_exists = cfs.iter().find(|cf| cf == &"my_column_family").is_none();

    // open a DB with specifying ColumnFamilies
    let mut instance = DB::open_cf(&options, path, cfs).unwrap();

    if my_column_family_exists {
        // create a new ColumnFamily
        let options = Options::default();
        instance.create_cf("my_column_family", &options).unwrap();
    }
    Result::Ok(instance)
}
pub fn get_chain_tip() -> Result<u32, Error> {
    let db = state::get();
    let block_tip = match db.get("block_tip") {
        Ok(Some(result)) => {
            let bytes: [u8; 4] = result.as_slice().try_into().unwrap();
            u32::from_le_bytes(bytes)
        }

        Ok(None) => 0,

        Err(e) => {
            eprintln!("{}: {}", "Failed to get block tip!".red().bold(), e);
            panic!()
        }
    };
    Ok(block_tip)
}
