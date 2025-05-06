use bitcoin::address::P2shError;
use bitcoin::key::UncompressedPublicKeyError;
use std::array::TryFromSliceError;
use std::convert::Infallible;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlockchainError {
    #[error("Parsing error: {0}")]
    ParsingError(String),

    #[error("Slice conversion error: {0}")]
    SliceConversion(#[from] TryFromSliceError),

    #[error("Uncompressed pubkey error: {0}")]
    UncompressedPublicKeyError(#[from] UncompressedPublicKeyError),

    #[error("From slice error: {0}")]
    FromSliceError(#[from] bitcoin::key::FromSliceError),

    #[error("Secp25k1 Error: {0}")]
    Secp256k1Error(#[from] bitcoin::secp256k1::Error),

    #[error("P2sh Error: {0}")]
    P2SHError(#[from] P2shError),

    #[error("Infallible: ")]
    Infallible(#[from] Infallible),
}

impl BlockchainError {
    pub fn from<T: Into<String>>(err: T) -> Self {
        BlockchainError::ParsingError(err.into())
    }
}
