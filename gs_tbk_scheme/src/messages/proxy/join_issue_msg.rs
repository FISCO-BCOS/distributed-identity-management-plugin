use std::collections::HashMap;

use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use curv::{elliptic::curves::*, BigInt};
use serde::{Deserialize, Serialize};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS,SecretShares};

use crate::{tree::{Tau,TreeNode}, params::{CiphertextHex, PKHex}};
use crate::params::{Gsk,Reg,Gpk,MTAParams,EiInfo,JoinPhaseRevokeSharedMessageType};
use crate::messages::user::sign_msg::UserSignatureInfo;
 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToUserJoinIssuePhaseOneP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub gpk:Gpk 
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesJoinIssuePhaseTwoBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub X: Point<Bls12_381_1>,
    pub X_sim: Point<Bls12_381_1>,
    pub s_x: Scalar<Bls12_381_1>,
    pub c_x: Scalar<Bls12_381_1>,
    pub user_info:UserInfo
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserInfo
{
    pub id:u16,
    pub address:String,
    pub name:String,
    pub pk_hex:PKHex,
    pub X:Point<Bls12_381_1>,
    pub X_sim:Point<Bls12_381_1>,
    pub tau:Tau,
    pub leaf_node:TreeNode,
    pub leaf_node_base_info_map:HashMap<usize,TreeNodeBaseInfo>,
    // ---------
    pub mtaparams:MTAParams,
    pub ei_info:Option<EiInfo>,
    pub user_signature_info:Option<UserSignatureInfo>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeNodeBaseInfo
{
    pub base_j: Point<Bls12_381_1>,
    pub zeta_j: Scalar<Bls12_381_1>,
    pub u_j: Scalar<Bls12_381_1>,
} 

// To Nodes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToUserJoinIssuePhaseTwoP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub base_info_map:HashMap<usize,TreeNodeBaseInfo>
}

// To User
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct A1kCKInfo
{
    pub A_1_k: Point<Bls12_381_1>,
    //pub k : Scalar<Bls12_381_1>,
    pub c_k_hex:CiphertextHex,
    pub xi_j: Scalar<Bls12_381_1>,
    pub zeta_j:Scalar<Bls12_381_1>,
    pub uj:Scalar<Bls12_381_1>,
    pub tau:Tau
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToUserJoinIssuePhaseThreeP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub A_1_k_c_k_map:HashMap<usize,A1kCKInfo>
} 

// To Nodes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesJoinIssuePhaseThreeBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub A_1_k_map: HashMap<usize,Point<Bls12_381_1>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesJoinIssuePhaseFourBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub A_gamma_C_k_map: HashMap<usize,Point<Bls12_381_1>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub A_gamma_C_map: HashMap<usize,Point<Bls12_381_1>>
}

#[derive(Clone, Debug, Serialize, Deserialize)] 
pub struct NodeUserJoinRevokeSharedMessage{
    pub shared_message_map:HashMap<u16,Vec<JoinPhaseRevokeSharedMessageType>>
}
