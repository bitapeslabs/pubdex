use bitcoin;

// PUBDEX is chain agnostic, you only need to change chainparams here. (of type bitcoin::params::Params)
pub static ENABLED_NETWORK: &bitcoin::params::Params = &bitcoin::params::MAINNET;
