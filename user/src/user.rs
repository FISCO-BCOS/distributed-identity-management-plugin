use curv::{elliptic::curves::*, BigInt};
use curv::{elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use gs_tbk_scheme::params::{Gpk,CLKeys,Gsk,EiInfo, CLKeysHex, CLGroupHex};
use class_group::primitives::cl_dl_public_setup::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User
{
    pub id: Option<u16>,
    pub name: String,
    pub role: String,
    pub proxy_addr: String,
    pub listen_addr:String, 
    pub user_addr: String,
    pub clkeys:CLKeys,
    pub group:CLGroup,
    pub usk: Option<Scalar<Bls12_381_1>>,
    pub gpk: Option<Gpk>,
    pub tau: Option<Scalar<Bls12_381_1>>,
    pub gsk: Option<Gsk>,
    pub ei_info:Option<EiInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserConfig
{
    pub id: Option<u16>,
    pub name: String,
    pub role: String,
    pub proxy_addr: String,
    pub listen_addr:String,
    pub user_addr: String,
    pub clkeys_hex:CLKeysHex,
    pub group_hex:CLGroupHex,
    pub usk: Option<Scalar<Bls12_381_1>>,
    pub gpk: Option<Gpk>,
    pub tau: Option<Scalar<Bls12_381_1>>,
    pub gsk: Option<Gsk>,
    pub ei_info:Option<EiInfo>,
}