use curv::elliptic::curves::{Point, Bls12_381_1, Scalar};
use serde::{Deserialize, Serialize};
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use sha2::Sha256;

use crate::params::DKGTag;
use crate::params::CiphertextHex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodeKeyRocoverPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodeKeyRefreshPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
    pub dkgtag:DKGTag
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodeKeyRefreshPhaseTwoP2PMsg
{
    pub dkgtag:DKGTag,
    pub sender:u16,
    pub role:String,
    pub c_share_sum_hex:CiphertextHex,
    pub vss_scheme_sum:VerifiableSS<Bls12_381_1>,
}