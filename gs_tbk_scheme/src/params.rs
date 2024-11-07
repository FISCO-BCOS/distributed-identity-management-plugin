use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use curv::arithmetic::traits::*;
use curv::{elliptic::curves::{Bls12_381_1,Bls12_381_2, Point,Generator, Scalar}, cryptographic_primitives::hashing::DigestExt};
use curv::BigInt;
use crate::tree::Tau;
use class_group::primitives::cl_dl_public_setup::*;
use class_group::BinaryQF;

use crate::messages::user::revoke_msg::RevokePhaseStartFlag;
use crate::messages::user::sign_msg::SignPhaseStartFlag;

use crate::messages::node::join_issue_msg::{NodeToProxyJoinIssuePhaseFlag, NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg};
use crate::messages::node::revoke_msg::{NodeToProxyRevokePhaseTwoFlag, NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg};

use crate::messages::proxy::join_issue_msg::ProxyToNodesJoinIssuePhaseTwoBroadcastMsg;
use crate::messages::proxy::revoke_msg::ProxyToNodesRevokePhaseOneBroadcastMsg;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreasholdParam{
    pub threshold: u16,
    pub share_counts: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLKeys
{
    pub sk:SK, 
    pub pk:PK
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DKGTag
{
    Gamma_A,
    Gamma_B,
    Gamma_O,
    Gamma_C
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gpk
{
    pub f:Point<Bls12_381_1>,
    pub g:Point<Bls12_381_1>,
    pub g_sim:Point<Bls12_381_1>,
    pub g_hat:Point<Bls12_381_2>,
    pub g2:Point<Bls12_381_1>,
    pub h0:Point<Bls12_381_1>,
    pub h1:Point<Bls12_381_1>,
    pub h2:Point<Bls12_381_1>,
    pub vk_A:Option<Point<Bls12_381_2>>,
    pub vk_B:Option<Point<Bls12_381_2>>,
    pub g1:Option<Point<Bls12_381_1>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MTAParam
{
    pub a:Scalar<Bls12_381_1>,// gamma_i+xi_j_i
    pub b:Scalar<Bls12_381_1>,// k_i
    pub xi_j_i:Scalar<Bls12_381_1>,
    pub pi_share:Scalar<Bls12_381_1> //Pi‘share = alphai+betaj+ai*bi
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MTAParams
{
    pub mta_A:Option<HashMap<usize,MTAParam>>,
    pub mta_B:Option<HashMap<usize,MTAParam>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MTATag
{
    Mta_A,
    Mta_B
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BBSSignature
{
    pub Aj:Point<Bls12_381_1>,
    pub xi_j:Scalar<Bls12_381_1>,
    pub zeta_j:Scalar<Bls12_381_1>,
    pub uj:Scalar<Bls12_381_1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gsk
{
    pub bbs_signatures_map:HashMap<usize,BBSSignature>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reg
{
    pub tau_i:Tau,
    pub grt_i:Point<Bls12_381_1>,
    pub Aj_gamma_C_map:HashMap<usize,Point<Bls12_381_1>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryQFHex
{
    pub a: String,
    pub b: String,
    pub c: String,
}

pub fn binary_qf_to_hex(binary_qf:&BinaryQF)->BinaryQFHex
{
    BinaryQFHex 
    { 
        a: binary_qf.a.to_hex(), 
        b: binary_qf.b.to_hex(), 
        c: binary_qf.c.to_hex() 
    }
}

pub fn hex_to_binary_qf(binary_qf_hex:&BinaryQFHex)->BinaryQF
{
    BinaryQF
    {
        a: BigInt::from_hex(&binary_qf_hex.a).unwrap(),
        b: BigInt::from_hex(&binary_qf_hex.b).unwrap(),
        c: BigInt::from_hex(&binary_qf_hex.c).unwrap(),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextHex
{
    pub c1: BinaryQFHex,
    pub c2: BinaryQFHex,
}

pub fn hex_to_ciphertext(c_hex:&CiphertextHex)->Ciphertext
{
    Ciphertext
    {
        c1:hex_to_binary_qf(&c_hex.c1),
        c2:hex_to_binary_qf(&c_hex.c2)
    }
}

pub fn ciphertext_to_hex(c:&Ciphertext)->CiphertextHex
{
    CiphertextHex
    {
        c1:binary_qf_to_hex(&c.c1),
        c2:binary_qf_to_hex(&c.c2),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TTripletsHex
{
    pub t1_hex: BinaryQFHex,
    pub t2_hex: BinaryQFHex,
    pub T: Point<Bls12_381_1>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLKeysHex
{
    pub sk_hex:String,
    pub pk_hex:PKHex
}
pub fn cl_keys_to_hex (cl_keys:&CLKeys) -> CLKeysHex
{
    CLKeysHex { 
        sk_hex: cl_keys.sk.0.to_hex(), 
        pk_hex: pk_to_hex(&cl_keys.pk), 
    }
}
pub fn hex_to_cl_keys (cl_keys_hex:&CLKeysHex) -> CLKeys
{
    CLKeys { 
        sk: SK(BigInt::from_hex(&cl_keys_hex.sk_hex).unwrap()), 
        pk: hex_to_pk(&cl_keys_hex.pk_hex), 
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U1U2Hex
{
    u1_hex:String,
    u2_hex:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLDLProofHex {
    t_triple_hex: TTripletsHex,
    u1u2_hex: U1U2Hex,
}

pub fn cldl_proof_to_hex(cldl_proof:&CLDLProof)->CLDLProofHex
{
    CLDLProofHex
    {
        t_triple_hex:TTripletsHex 
        { 
            t1_hex: binary_qf_to_hex(&cldl_proof.t_triple.t1), 
            t2_hex: binary_qf_to_hex(&cldl_proof.t_triple.t2), 
            T: cldl_proof.t_triple.T.clone()
        },
        u1u2_hex:U1U2Hex 
        { 
            u1_hex: cldl_proof.u1u2.u1.to_hex(), 
            u2_hex: cldl_proof.u1u2.u2.to_hex()
        }
    }
}

pub fn hex_to_cldl_proof(cldl_proof_hex:&CLDLProofHex)->CLDLProof
{
    CLDLProof
    {
        t_triple:TTriplets
        {
            t1: hex_to_binary_qf(&cldl_proof_hex.t_triple_hex.t1_hex),
            t2: hex_to_binary_qf(&cldl_proof_hex.t_triple_hex.t2_hex),
            T: cldl_proof_hex.t_triple_hex.T.clone()
        },
        u1u2: U1U2
        {
            u1:BigInt::from_hex(&cldl_proof_hex.u1u2_hex.u1_hex).unwrap(),
            u2:BigInt::from_hex(&cldl_proof_hex.u1u2_hex.u2_hex).unwrap()
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct  CLGroupHex {
     delta_k_hex: String,
     delta_q_hex: String,
     gq_hex: BinaryQFHex,
     stilde_hex: String,
}
pub fn clgroup_to_hex(cl_group:&CLGroup) -> CLGroupHex {
    CLGroupHex {
        delta_k_hex : cl_group.delta_k.to_hex(),
        delta_q_hex : cl_group.delta_q.to_hex(),
        gq_hex : binary_qf_to_hex(&cl_group.gq),
        stilde_hex : cl_group.stilde.to_hex(),
    }
}
pub fn hex_to_cl_group(cl_group_hex:&CLGroupHex) -> CLGroup {
    CLGroup { 
        delta_k : BigInt::from_hex(&cl_group_hex.delta_k_hex).unwrap(), 
        delta_q : BigInt::from_hex(&cl_group_hex.delta_q_hex).unwrap(),
        gq : hex_to_binary_qf(&cl_group_hex.gq_hex), 
        stilde :  BigInt::from_hex(&cl_group_hex.stilde_hex).unwrap(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PKHex(pub BinaryQFHex);

pub fn pk_to_hex(pk:&PK)->PKHex
{
    PKHex(binary_qf_to_hex(&pk.0))
}

pub fn hex_to_pk(pk_hex:&PKHex)->PK
{
    PK(hex_to_binary_qf(&pk_hex.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SKHex(String);

// #[derive(Clone, Debug, Serialize, Deserialize)] 
// pub enum JoinPhaseMTASharedMessageType
// {
//     NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg(NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg),
//     ProxyToNodesJoinIssuePhaseTwoBroadcastMsg(ProxyToNodesJoinIssuePhaseTwoBroadcastMsg)
// }

#[derive(Clone, Debug, Serialize, Deserialize)] 
pub enum JoinPhaseRevokeSharedMessageType
{
    RevokePhaseStartFlag(RevokePhaseStartFlag),
    NodeToProxyJoinIssuePhaseFlag(NodeToProxyJoinIssuePhaseFlag)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeBBSSignature
{
    pub Bj:Point<Bls12_381_1>,
    pub xi_j:Scalar<Bls12_381_1>,
    pub zeta_j:Scalar<Bls12_381_1>,
    pub vj:Scalar<Bls12_381_1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EiInfo
{
    pub t:Tau,
    pub h_sim_t:Point<Bls12_381_1>,
    pub revoke_bbs_signatures_map:HashMap<usize,RevokeBBSSignature>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RL
{
    pub h_sim_t:Point<Bls12_381_1>,
    pub h_hat_t:Point<Bls12_381_2>,
    pub grt_map:HashMap<u16, Point<Bls12_381_1>>
}

// #[derive(Clone, Debug, Serialize, Deserialize)] 
// pub enum RevokePhaseMTASharedMessageType {
//     NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg(NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg),
//     ProxyToNodesRevokePhaseOneBroadcastMsg(ProxyToNodesRevokePhaseOneBroadcastMsg)
// }

#[derive(Clone, Debug, Serialize, Deserialize)] 
pub enum RevokePhaseSignSharedMessageType
{
    SignPhaseStartFlag(SignPhaseStartFlag),
    NodeToProxyRevokePhaseTwoFlag(NodeToProxyRevokePhaseTwoFlag)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sigma
{
    pub psi_1: Point<Bls12_381_1>,
    pub psi_2: Point<Bls12_381_1>,
    pub psi_3: Point<Bls12_381_1>,
    pub psi_4: Point<Bls12_381_1>,
    pub psi_5: Point<Bls12_381_1>,
    pub psi_6: Point<Bls12_381_1>,
    pub psi_7: Point<Bls12_381_2>,
    pub c: Scalar<Bls12_381_1>,
    pub s_alpha: Scalar<Bls12_381_1>,
    pub s_beta: Scalar<Bls12_381_1>,
    pub s_zeta_1: Scalar<Bls12_381_1>,
    pub s_xi_1: Scalar<Bls12_381_1>,
    pub s_zeta_2: Scalar<Bls12_381_1>,
    pub s_xi_2: Scalar<Bls12_381_1>,
    pub s_u: Scalar<Bls12_381_1>,
    pub s_x: Scalar<Bls12_381_1>,
    pub s_delta_1: Scalar<Bls12_381_1>,
    pub s_delta_2: Scalar<Bls12_381_1>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSignature{
    pub user_id:u16,
    pub m:String,
    pub sigma:Sigma
}



