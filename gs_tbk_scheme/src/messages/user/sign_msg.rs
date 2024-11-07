use std::collections::HashMap;
use curv::{elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use crate::params::Sigma;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
    // pub m:String, 
    // pub sigma:Sigma
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSignatureInfo
{
    pub user_id:u16,
    pub name:String,
    pub m:String,
    pub signature:Sigma
}