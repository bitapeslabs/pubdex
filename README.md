# Pubdex
Lightweight rust lib to create a rocksdb index of address -> pubkey for opnet. 


## rocksdb schema
[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
[u8, 33] -> [u8, unsized](addresses mapped to this pubkey, 0x0A as seperator)
