use bitcoin;

// PUBDEX is chain agnostic, you only need to change chainparams here. (of type bitcoin::params::Params)
pub static ENABLED_NETWORK: &bitcoin::params::Params = &bitcoin::params::MAINNET;
pub static GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
