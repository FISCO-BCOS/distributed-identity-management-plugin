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

use class_group::primitives::cl_dl_public_setup::*;
use crate::params::{CiphertextHex, CLDLProofHex, PKHex};

// Verify client's zk proof and forward to all Nodes
 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtAPhaseOneP2PMsg{
    //pub tree_node_id:usize,
    pub sender:u16,
    pub alice_pk_hex:PKHex,
    pub c_a_hex:CiphertextHex
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtAPhaseTwoP2PMsg{
    //pub tree_node_id:usize,
    pub sender:u16,
    pub c_alpha_hex:CiphertextHex,
    pub c_b_hex:CiphertextHex,
    pub g_b:Point<Bls12_381_1>,
    pub b_proof_hex:CLDLProofHex,
    pub c_beta_hex:CiphertextHex,
    pub g_beta:Point<Bls12_381_1>,
    pub beta_proof_hex:CLDLProofHex,
    pub bob_pk_hex:PKHex,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub mta_pone_p2pmsg_map:HashMap<usize, MtAPhaseOneP2PMsg>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinMTATag{
    pub tag_map:HashMap<u16, bool>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeProxyJoinMTASharedMessage{
    pub shared_message_map:HashMap<u16, Vec<NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub mta_ptwo_p2pmsg_map:HashMap<usize, MtAPhaseTwoP2PMsg>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CkiPishareInfo
{
    pub pi_share:Scalar<Bls12_381_1>,
    //pub ki:Scalar<Bls12_381_1>,//
    //pub gammai:Scalar<Bls12_381_1>,
    pub c_ki_hex:CiphertextHex,
    pub xi_j_i:Scalar<Bls12_381_1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub c_ki_pi_share_map:HashMap<usize, CkiPishareInfo>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyJoinIssuePhaseThreeP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub A_gamma_C_i_k_map:HashMap<usize, Point<Bls12_381_1>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyJoinIssuePhaseFourP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    pub A_gamma_C_k_ki_map:HashMap<usize, Point<Bls12_381_1>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyJoinIssuePhaseFlag
{
    pub sender:u16,
    pub role:String,
    pub user_id:u16,
    //pub flag:bool,
    //pub info:String
}