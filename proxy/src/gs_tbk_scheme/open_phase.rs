use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::elliptic::curves::bls12_381::Pair;
use log::info;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use crate::proxy::Proxy;
use crate::Error::{self, InvalidKey, InvalidSS};
use gs_tbk_scheme::messages::node::open_msg::{NodeToProxyOpenPhaseOneP2PMsg,NodeToProxyOpenPhaseTwoP2PMsg};
use gs_tbk_scheme::messages::user::sign_msg::SignPhaseStartFlag;
use gs_tbk_scheme::messages::proxy::open_msg::{ProxyToNodesOpenPhaseOneBroadcastMsg,ProxyToNodesOpenPhaseTwoBroadcastMsg};

impl Proxy
{
    /// 合并 psi gamma_O 计算出用户的签名A
    pub fn open_phase_one(&self, msg_vec:&Vec<NodeToProxyOpenPhaseOneP2PMsg>)->ProxyToNodesOpenPhaseOneBroadcastMsg
    {
        info!("Open phase is staring!");
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        // Merge
        let psi_1_gamma_O = msg_vec.iter().fold(Point::<Bls12_381_1>::zero(), |acc,msg|acc+&msg.psi_1_gamma_O_i);
        let Aj = &msg_vec[0].sigma.psi_2 - psi_1_gamma_O;
        ProxyToNodesOpenPhaseOneBroadcastMsg
        {
            sender:self.id,
            role:self.role.clone(), 
            user_id:msg_vec[0].user_id,
            Aj 
        }
    }

    /// 合并出 A_gamma_C
    pub fn open_phase_two(&self,msg_vec:&Vec<NodeToProxyOpenPhaseTwoP2PMsg>)->ProxyToNodesOpenPhaseTwoBroadcastMsg
    {
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        let Aj_gamma_C = msg_vec.iter().fold(Point::<Bls12_381_1>::zero(), |acc,msg|acc+&msg.Aj_gamma_C_i);
        info!("Open phase is finished!");
        ProxyToNodesOpenPhaseTwoBroadcastMsg
        {
            sender:self.id,
            role:self.role.clone(),
            user_id:msg_vec[0].user_id,
            Aj_gamma_C
        }
    }
}