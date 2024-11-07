use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::elliptic::curves::bls12_381::Pair;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::messages::user::sign_msg::SignPhaseStartFlag;
use crate::params::Sigma;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyOpenPhaseOneP2PMsg
{
    pub sender:u16,
    pub user_id:u16,
    pub role:String,
    pub psi_1_gamma_O_i:Point<Bls12_381_1>,
    pub sigma:Sigma,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyOpenPhaseTwoP2PMsg
{
    pub sender:u16,
    pub user_id:u16,
    pub role:String,
    pub Aj_gamma_C_i:Point<Bls12_381_1>
}