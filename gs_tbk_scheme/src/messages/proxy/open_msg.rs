use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::elliptic::curves::bls12_381::Pair;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesOpenPhaseOneBroadcastMsg
{
    pub sender:u16,
    pub user_id:u16,
    pub role:String,
    pub Aj:Point<Bls12_381_1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesOpenPhaseTwoBroadcastMsg
{
    pub sender:u16,
    pub user_id:u16,
    pub role:String,
    pub Aj_gamma_C:Point<Bls12_381_1>
}