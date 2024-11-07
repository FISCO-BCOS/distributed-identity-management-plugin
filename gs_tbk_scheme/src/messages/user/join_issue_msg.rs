use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use curv::{elliptic::curves::*, BigInt};
use serde::{Deserialize, Serialize};


use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use class_group::primitives::cl_dl_public_setup::*;

use crate::params::PKHex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserJoinIssuePhaseStartFlag
{
    //pub sender:u16,
    pub role:String,
    pub ip:String,
    pub name:String
} 

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserToProxyJoinIssuePhaseTwoP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub address:String, 
    pub name:String,
    pub pk_hex:PKHex,
    pub X: Point<Bls12_381_1>,
    pub X_sim: Point<Bls12_381_1>,
    pub s_x: Scalar<Bls12_381_1>,
    pub c_x: Scalar<Bls12_381_1>,
}

