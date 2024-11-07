use std::collections::HashMap;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{elliptic::curves::{Bls12_381_1,Bls12_381_2, Point,Generator, Scalar}, cryptographic_primitives::hashing::DigestExt};
use curv::BigInt;
use sha2::{Sha256, Digest}; 
use serde::{Deserialize, Serialize};

use class_group::primitives::cl_dl_public_setup::*;
use crate::params::{DKGTag, CiphertextHex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyKeyGenPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyKeyGenPhaseOneBroadcastMsg{
    pub g:Point<Bls12_381_1>,
    pub g_hat:Point<Bls12_381_2>,
    pub f:Point<Bls12_381_1>, 
    pub g_sim:Point<Bls12_381_1>,
    pub g_2:Point<Bls12_381_1>,
    pub h_0:Point<Bls12_381_1>,
    pub h_1:Point<Bls12_381_1>,
    pub h_2:Point<Bls12_381_1>,
    pub participants:Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodeKeyGenPhaseThreeP2PMsg
{
    pub dkgtag:DKGTag,
    pub sender:u16,
    pub role:String,
    pub c_share_sum_hex:CiphertextHex,
    pub vss_scheme_sum:VerifiableSS<Bls12_381_1>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesKeyGenPhasefiveBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub vk_A:Point<Bls12_381_2>,
    pub vk_B:Point<Bls12_381_2>,
    pub g1:Point<Bls12_381_1>,
}