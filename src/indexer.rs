use colored::Colorize;
use rocksdb::DB;
use std::sync::Arc;

//[u8]("block_tip") -> u32
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
//[u8, unsized](address bytes, utf-encoded) -> [u8, 33]

pub fn run_indexer(database: Arc<DB>) {
    let block_tip = match database.get("block_tip") {
        Ok(Some(result)) => {
            let bytes: [u8; 4] = result.as_slice().try_into().unwrap();
            u32::from_le_bytes(bytes)
        }

        Ok(None) => 0,

        Err(_) => {
            eprintln!("{}", "Failed to get block tip!".red().bold());
            return;
        }
    };
    println!("{}", block_tip)
}
