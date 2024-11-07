use curv::elliptic::curves::{Point, Bls12_381_1, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use sha2::Sha256;

use crate::params::DKGTag;
use super::keygen_msg::ShareProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyInfo
{
    pub ui:Scalar<Bls12_381_1>,
    pub xi:Scalar<Bls12_381_1>,
} 

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyInfoWithAddshare
{
    pub ui:Scalar<Bls12_381_1>,
    pub xi:Scalar<Bls12_381_1>,
    pub addshare:Scalar<Bls12_381_1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysInfo
{
    pub gamma_A:KeyInfoWithAddshare,
    pub gamma_B:KeyInfoWithAddshare,
    pub gamma_C:KeyInfo,
    pub gamma_O:KeyInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyKeyRecoverP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub keysinfo:KeysInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyKeyRefreshOneP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub dkgtag:DKGTag,
    pub share_proof_map:HashMap<u16,ShareProof>,
    pub vss_scheme:VerifiableSS<Bls12_381_1>
}

