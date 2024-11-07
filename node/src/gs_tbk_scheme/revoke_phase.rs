use std::collections::HashMap;
use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use log::info;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use crate::node::Node;
use gs_tbk_scheme::params::{DKGTag, MTATag};
use gs_tbk_scheme::messages::node::join_issue_msg::{MtAPhaseOneP2PMsg,MtAPhaseTwoP2PMsg};
use gs_tbk_scheme::messages::node::revoke_msg::{
    NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg,
    NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg,
    KiPishareInfo, 
    NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg,
    NodeToProxyRevokePhaseTwoFlag
};
use gs_tbk_scheme::messages::proxy::revoke_msg::{ProxyToNodesRevokePhaseOneBroadcastMsg, ProxyToNodesRevokePhaseTwoBroadcastMsg};

impl Node
{
    /// 启动mta的计算
    pub fn revoke_phase_one_mta_one(&mut self,dkgtag:&DKGTag,msg:&ProxyToNodesRevokePhaseOneBroadcastMsg, mtatag:&MTATag)->NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg
    {
        let mut mta_pone_p2pmsg_map:HashMap<usize, MtAPhaseOneP2PMsg> = HashMap::new();
        for tree_node in self.tree.as_ref().unwrap().cstbk(msg.leaf_node_id)
        {
            self.bbs_mtaparam_init(dkgtag, tree_node.id, mtatag, msg.user_id);
            let mta_pone_p2pmsg = self.mta_phase_one( tree_node.id, mtatag, msg.user_id);
            mta_pone_p2pmsg_map.insert(tree_node.id, mta_pone_p2pmsg);
        }
        NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg
        {  
            sender:self.id.unwrap(),
            role:self.role.clone(),
            mta_pone_p2pmsg_map:mta_pone_p2pmsg_map,
            user_id:msg.user_id
        }
    }

    pub fn revoke_phase_one_mta_two(&mut self,msg:&NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg, mtatag:&MTATag)->NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg
    {
        let mut mta_ptwo_p2pmsg_map:HashMap<usize, MtAPhaseTwoP2PMsg> = HashMap::new();
        for (tree_node_id, mta_pone_p2pmsg) in msg.mta_pone_p2pmsg_map.clone()
        {
            let mta_ptwo_p2pmsg = self.mta_phase_two( mta_pone_p2pmsg, tree_node_id, mtatag, msg.user_id);
            mta_ptwo_p2pmsg_map.insert(tree_node_id, mta_ptwo_p2pmsg); 
        }
        NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg
        {
            sender:self.id.unwrap(), 
            role:self.role.clone(),
            mta_ptwo_p2pmsg_map:mta_ptwo_p2pmsg_map, 
            user_id:msg.user_id 
        }
    }

    pub fn revoke_phase_one_mta_three(&mut self, msg:NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg, mtatag:&MTATag)
    {
        for (tree_node_id, mta_ptwo_p2pmsg) in msg.mta_ptwo_p2pmsg_map
        {
            self.mta_phase_three( mta_ptwo_p2pmsg, tree_node_id, mtatag, msg.user_id);
        }
    }

    /// 完成mta的联合计算，发送相关结果给代理
    pub fn revoke_phase_one_final(&self, msg:&NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg, mtatag:&MTATag)->NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg
    {
        let mut ki_pi_share_map:HashMap<usize, KiPishareInfo> = HashMap::new();
        for(tree_node_id, _) in msg.mta_ptwo_p2pmsg_map.clone()
        {
            let mtaparams = self.choose_mtaparam(mtatag, tree_node_id, msg.user_id);
            let ki = mtaparams.b.clone();
            let xi_j_i = mtaparams.xi_j_i.clone();
            let pi_share = mtaparams.pi_share.clone();
            ki_pi_share_map.insert(tree_node_id, KiPishareInfo { pi_share: pi_share, ki:ki, xi_j_i:xi_j_i});
        }
        NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(), 
            ki_pi_share_map:ki_pi_share_map,
            user_id:msg.user_id
        }
    }

    /// 存下撤销用户名单信息和revoke计算出来的信息
    pub fn revoke_phase_two(&mut self,msg:&ProxyToNodesRevokePhaseTwoBroadcastMsg)->NodeToProxyRevokePhaseTwoFlag
    {
        self.user_info_map.as_mut().unwrap().get_mut(&msg.user_id).as_mut().unwrap().ei_info = Some(msg.ei_info.clone());
        info!("{}'s ei info has been finished",msg.user_id); 
        // match self.rl {
        //     None=>{
        //         self.rl = Some(msg.rl.clone()); 
        //     }
        //     _=>{ 

        //     }
        // };
        NodeToProxyRevokePhaseTwoFlag{
            sender:self.id.unwrap(),
            role:self.role.clone(),
            user_id:msg.user_id
        }
    }    
}
