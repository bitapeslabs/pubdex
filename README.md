# Pubdex

Lightweight rust indexer to create a rocksdb index of bitcoin address -> pubkey and pubkey -> bitcoin address

## rocksdb schema

```rust
[u8]("block_tip") -> u32
[u8, 36](utxo id [[u8, 32],u32]) -> [u8, unsized] address bytes (str) (!! utxos are deleted from rocksdb after being used to save space)
[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
[u8, unsized](address bytes, utf-encoded) -> [u8, 33]
```

## api

### 🔍 `GET /pubkey/:address`

Returns the pubkey for a given address.

- **Example:**  
  `GET /pubkey/op123abc456`

- **Response:**

```json
{
  "address": "op123abc456",
  "pubkey": "02de8c7b...f0a3"
}
```

- **404 Response:**

```json
{ "error": "not found" }
```

---

### 🔁 `GET /addresses/:pubkey`

Returns all addresses associated with a given pubkey.

- **Example:**  
  `GET /addresses/02de8c7b...f0a3`

- **Response:**

```json
{
  "pubkey": "02de8c7b...f0a3",
  "addresses": ["op123abc456", "op1xyz..."]
}
```

- **404 Response:**

```json
{ "error": "not found" }
```
