use std::collections::HashMap;
use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use crate::messages::node::join_issue_msg::{MtAPhaseOneP2PMsg,MtAPhaseTwoP2PMsg};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub mta_pone_p2pmsg_map:HashMap<usize, MtAPhaseOneP2PMsg>,
    pub user_id:u16
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub mta_ptwo_p2pmsg_map:HashMap<usize, MtAPhaseTwoP2PMsg>,
    pub user_id:u16
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeMTATag{
    pub tag_map:HashMap<u16, bool>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeProxyRevokeMTASharedMessage{
    pub shared_message_map:HashMap<u16, Vec<NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KiPishareInfo
{
    pub pi_share:Scalar<Bls12_381_1>,
    pub ki:Scalar<Bls12_381_1>,
    pub xi_j_i:Scalar<Bls12_381_1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub ki_pi_share_map:HashMap<usize, KiPishareInfo>,
    pub user_id:u16
} 

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyRevokePhaseTwoFlag{
    pub sender:u16,
    pub role:String,
    pub user_id:u16
}