use bitcoin;

// PUBDEX is chain agnostic, you only need to change chainparams here. (of type bitcoin::params::Params)
pub static ENABLED_NETWORK: &bitcoin::params::Params = &bitcoin::params::MAINNET;
pub static GENESIS_HASH: &str = "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8";
