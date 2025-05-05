# Pubdex

Lightweight rust indexer to create a rocksdb index of bitcoin address -> pubkey and pubkey -> bitcoin address

## Usage

```bash
cargo run --release -- --config ./Indexer.toml
```

## rocksdb schema

```rust
[u8]("indexer_height") -> u32
[u8]("indexer_tip_hash") -> u32
[u8]("cnt:pk") -> u32 (pubkey count)
[b"pk:" + [u8,8]] -> [u8, 33] (pubkey bytes)
[u8, unsized]b"amap"+(address bytes, utf-encoded) -> [u8, 8] (id bytes)
```
