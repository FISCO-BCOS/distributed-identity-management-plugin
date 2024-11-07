use class_group::primitives::cl_dl_public_setup::*;

use serde::{Deserialize, Serialize};

use crate::params::PKHex;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxySetupPhaseP2PMsg{
    pub role:String,
    pub pk_hex : PKHex,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSetupPhaseFinishFlag{
    pub sender:u16,
    pub role:String,
}
 