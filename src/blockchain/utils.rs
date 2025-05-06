use super::errors::BlockchainError;
use crate::chain::{ENABLED_NETWORK_HRP, ENABLED_NETWORK_KIND};

use bitcoin::{
    hashes::{hash160, Hash},
    script::Instruction,
    secp256k1::{self, Parity},
    Address, CompressedPublicKey, OutPoint, PublicKey, ScriptBuf, Witness, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use std::default::Default;

thread_local! {
    pub static SECP: secp256k1::Secp256k1<secp256k1::VerifyOnly> = secp256k1::Secp256k1::verification_only();
}

pub struct UTXO {
    pub outpoint: OutPoint,
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

#[derive(Serialize, Deserialize, Default)]
pub struct AddressMapping {
    pub p2tr: Option<String>,
    pub p2wpkh: Option<String>,
    pub p2shp2wpkh: Option<String>,
    pub p2pkh: Option<String>,
}

pub fn create_p2sh_p2wpkh(p2wpkh_address: &Address) -> Result<String, BlockchainError> {
    let redeem_script = p2wpkh_address.script_pubkey();

    Ok(Address::p2sh(&redeem_script, *ENABLED_NETWORK_KIND)?.to_string())
}

pub fn get_address_mapping_from_pubkey(
    pubkey_bytes: &Vec<u8>,
) -> Result<AddressMapping, BlockchainError> {
    /*
        Invalid pubkey (legacy pubkeys have 65 bytes, and new pubkeys have 33 bytes).
        Anything other than this is an invalid pubkey and parsing should not be attempted
    */
    if pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65 {
        return Err(BlockchainError::from(
            "Invalid pubkey passed (must be of length 33 to 65",
        ));
    }

    let public_key = PublicKey::from_slice(pubkey_bytes)?;
    let p2pkh = Some(Address::p2pkh(&public_key, *ENABLED_NETWORK_KIND).to_string());

    //Leagacy pubkeys only have a valid p2pkh address
    if pubkey_bytes.len() == 65 {
        return Ok(AddressMapping {
            p2pkh,
            ..Default::default()
        });
    }

    let compressed_pk: CompressedPublicKey = public_key.try_into()?;
    let xonly = XOnlyPublicKey::from_slice(&pubkey_bytes[1..])?;
    let raw_p2wpkh = Address::p2wpkh(&compressed_pk, *ENABLED_NETWORK_HRP);

    let p2wpkh = Some(raw_p2wpkh.to_string());
    let p2shp2wpkh = Some(create_p2sh_p2wpkh(&raw_p2wpkh)?);
    let p2tr =
        Some(SECP.with(|secp| Address::p2tr(secp, xonly, None, *ENABLED_NETWORK_HRP).to_string()));

    Ok(AddressMapping {
        p2pkh,
        p2wpkh,
        p2shp2wpkh,
        p2tr,
    })
}

pub fn try_peek_pubkey<'a>(
    fund_script: &'a ScriptBuf,
    spend_script: &'a ScriptBuf,
    witness: &'a Witness,
) -> Option<&'a [u8]> {
    // P2TR: bytes 2..34
    if fund_script.is_p2tr() && fund_script.len() == 34 {
        return Some(&fund_script.as_bytes()[2..34]);
    }

    // P2WPKH or P2SH-P2WPKH: witness[1]
    if fund_script.is_p2wpkh() || fund_script.is_p2sh() {
        if witness.len() >= 2 {
            return Some(&witness[1]);
        }
    }

    // P2PKH: script_sig second push
    if fund_script.is_p2pkh() {
        let mut pushes = spend_script.instructions().filter_map(|i| {
            if let Ok(Instruction::PushBytes(b)) = i {
                Some(b)
            } else {
                None
            }
        });

        pushes.next(); // skip sig
        return pushes.next().map(|b| b.as_bytes());
    }

    if fund_script.is_p2pk() {
        return fund_script.instructions().find_map(|i| {
            if let Ok(Instruction::PushBytes(bytes)) = i {
                Some(bytes.as_bytes())
            } else {
                None
            }
        });
    }

    None
}

pub fn get_pub_key(
    fund_script_bytes: &Vec<u8>,
    spend_script: &ScriptBuf,
    witness: &Witness,
) -> Result<[u8; 33], BlockchainError> {
    let fund_script = ScriptBuf::from_bytes(fund_script_bytes.clone());

    if fund_script.is_p2tr() && fund_script.len() == 34 {
        let xonly_bytes = &fund_script.as_bytes()[2..34];
        if let Ok(xonly) = XOnlyPublicKey::from_slice(xonly_bytes) {
            return Ok(xonly.public_key(Parity::Even).serialize().into());
        }
    }

    if fund_script.is_p2wpkh() {
        if witness.len() >= 2 {
            let pk_bytes = &witness[1];
            // sanity‑check: hash160(pubkey) must match program
            let h160 = hash160::Hash::hash(pk_bytes.try_into()?);
            if fund_script.as_bytes()[2..22] == h160[..] {
                return Ok(pk_bytes.try_into()?);
            }
        }
    }

    if fund_script.is_p2pkh() {
        let mut pushes = spend_script.instructions().filter_map(|i| {
            if let Ok(Instruction::PushBytes(b)) = i {
                Some(b)
            } else {
                None
            }
        });

        pushes.next();

        if let Some(pk_bytes) = pushes.next() {
            if (pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03))
                || (pk_bytes.len() == 65 && pk_bytes[0] == 0x04)
            {
                return Ok(pk_bytes.as_bytes().try_into()?);
            }
        }
    }

    if fund_script.is_p2sh() {
        // redeem‑script = last push in scriptSig
        let redeem_script_bytes = spend_script
            .instructions()
            .filter_map(|i| match i {
                Ok(Instruction::PushBytes(b)) => Some(b),
                _ => None,
            })
            .last();

        if let Some(redeem) = redeem_script_bytes {
            let redeem_script = ScriptBuf::from_bytes(redeem.as_bytes().to_vec());
            if redeem_script.is_p2wpkh() && witness.len() >= 2 {
                let pk_bytes = &witness[1];
                // cross‑check hash160
                let h160 = hash160::Hash::hash(pk_bytes);
                if redeem_script.as_bytes()[2..22] == h160[..] {
                    return Ok(pk_bytes.try_into()?);
                }
            }
        }
    }

    if fund_script.is_p2pk() {
        // First instruction must be <pubkey>
        let mut iter = fund_script.instructions();

        if let Some(Ok(Instruction::PushBytes(pk_bytes))) = iter.next() {
            return Ok(pk_bytes.as_bytes().try_into()?);
        }
    }

    Err(BlockchainError::from(
        "(pubkey) failed to get pubkey from scripts",
    ))
}

/*
Its better to just not support this -> There exists no non-p2pkh addresses in legacy. Just bloats db


pub struct DecodedScript {
    pub pubkey: Vec<u8>,
}


pub trait CompressKey {
    fn compress_if_necessary(&mut self) -> Result<(), secp256k1::Error>;
}


impl CompressKey for DecodedScript {
   fn compress_if_necessary(&mut self) -> Result<(), secp256k1::Error> {
        if self.pubkey.len() == 65 {
            self.pubkey = secp256k1::PublicKey::from_slice(&self.pubkey)?.serialize().to_vec()
        }
        Ok(())

    }
}
*/
