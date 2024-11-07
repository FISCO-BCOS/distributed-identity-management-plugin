use std::collections::HashMap;
use curv::elliptic::curves::{Point, Bls12_381_1,Bls12_381_2, Scalar};
use serde::{Deserialize, Serialize};
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use sha2::Sha256;

use class_group::primitives::cl_dl_public_setup::*;
use crate::params::{DKGTag,CiphertextHex,CLDLProofHex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeKeyGenPhaseOneBroadcastMsg
{
    pub dkgtag:DKGTag,
    pub sender:u16,
    pub role:String,
    pub blind_factor:BigInt,
    pub yi:Point<Bls12_381_1>,
    pub com:BigInt,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareProof
{
    pub c_share_hex:CiphertextHex,
    pub g_share:Point<Bls12_381_1>,
    pub share_proof_hex:CLDLProofHex
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyKeyGenPhaseTwoP2PMsg
{//p to p
    pub dkgtag:DKGTag,
    pub sender:u16,
    pub role:String,
    pub share_proof_map:HashMap<u16,ShareProof>,
    pub vss_scheme:VerifiableSS<Bls12_381_1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkpProof
{
    pub z_gamma_A_i:Scalar<Bls12_381_1>,
    pub z_gamma_B_i:Scalar<Bls12_381_1>,
    pub z_gamma_O_i:Scalar<Bls12_381_1>,
    pub g_gamma_A_i:Point<Bls12_381_1>,
    pub g_gamma_B_i:Point<Bls12_381_1>,
    pub g_gamma_O_i:Point<Bls12_381_1>,
    pub e:Scalar<Bls12_381_1>,
    pub g_t:Point<Bls12_381_1>,
    pub g_hat_t:Point<Bls12_381_2>,
    pub f_t:Point<Bls12_381_1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyKeyGenPhaseFiveP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub zkp_proof:ZkpProof,
    pub vk_A_i: Point<Bls12_381_2>,
    pub vk_B_i: Point<Bls12_381_2>,
    pub g1_i: Point<Bls12_381_1>,
}
