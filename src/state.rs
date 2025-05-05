use once_cell::sync::OnceCell;
use rocksdb::DB;
use std::sync::Arc;

static DB_GLOBAL: OnceCell<Arc<DB>> = OnceCell::new();

pub fn init(db: Arc<DB>) {
    DB_GLOBAL.set(db).expect("DB_GLOBAL already initialized");
}

pub fn get() -> &'static Arc<DB> {
    DB_GLOBAL.get().expect("DB_GLOBAL is not initialized")
}
