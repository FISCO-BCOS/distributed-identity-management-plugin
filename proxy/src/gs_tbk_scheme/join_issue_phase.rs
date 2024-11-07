use std::collections::HashMap;
use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use log::info;
use sha2::{Sha256, Digest};

use crate::Error::{self, InvalidKey, InvalidSS};
use crate::proxy::{Proxy};
use gs_tbk_scheme::{messages::user::join_issue_msg::UserToProxyJoinIssuePhaseTwoP2PMsg, params::MTAParams};
use gs_tbk_scheme::messages::proxy::join_issue_msg::{
    ProxyToUserJoinIssuePhaseOneP2PMsg, 
    ProxyToNodesJoinIssuePhaseTwoBroadcastMsg,
    UserInfo, 
    TreeNodeBaseInfo, 
    ProxyToUserJoinIssuePhaseThreeP2PMsg, 
    A1kCKInfo, 
    ProxyToNodesJoinIssuePhaseThreeBroadcastMsg,
    ProxyToNodesJoinIssuePhaseFourBroadcastMsg,
    ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
};
use gs_tbk_scheme::messages::node::join_issue_msg::{ 
    NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg,
    NodeToProxyJoinIssuePhaseThreeP2PMsg,
    NodeToProxyJoinIssuePhaseFourP2PMsg
};
use gs_tbk_scheme::tree::{Tree,TreeNode};
use gs_tbk_scheme::params::{BBSSignature,Gsk,Reg,pk_to_hex};
use class_group::primitives::cl_dl_public_setup::*;
use gs_tbk_scheme::params::{hex_to_ciphertext,ciphertext_to_hex,cldl_proof_to_hex,hex_to_cldl_proof,hex_to_pk};

impl Proxy 
{
    /// 接收用户的信息，分配id，然后形成用户列表
    pub fn join_issue_phase_one(&mut self, user_num:&i32)-> ProxyToUserJoinIssuePhaseOneP2PMsg
    {
        info!("Join phase is staring!");
        if user_num == &(1 as i32){
            self.user_info_map = Some(HashMap::<u16,UserInfo>::new());
        }
        let user_id = user_num.clone();
        ProxyToUserJoinIssuePhaseOneP2PMsg
        {
            sender:self.id,
            role:self.role.clone(),
            user_id:user_id as u16,
            gpk:self.gpk.as_ref().unwrap().clone(),
        } 
    }
    
    /// 验证zkp proof 然后计算签名的base部分
    pub fn join_issue_phase_two(&mut self, msg:&UserToProxyJoinIssuePhaseTwoP2PMsg)->Result<(ProxyToNodesJoinIssuePhaseTwoBroadcastMsg), Error>
    {
        let gpk = self.gpk.as_ref().unwrap();
        let R = (&gpk.h2*&msg.s_x)-(&msg.X * &msg.c_x);
        let R_sim = (&gpk.g_sim * &msg.s_x)-(&msg.X_sim * &msg.c_x);
        let vc_x_b=Sha256::new() 
            .chain_point(&msg.X)
            .chain_point(&msg.X_sim)
            .chain_point(&R)
            .chain_point(&R_sim)
            .result_bigint();
        let vc_x = Scalar::<Bls12_381_1>::from_bigint(&vc_x_b);
        assert_eq!(&msg.c_x,&vc_x);
        if &msg.c_x==&vc_x
        {
            //let mut user_info_map = self.user_info_map.clone().unwrap();
            let id = msg.sender as usize;
            let user_leaf_node = self.tree.choose_leaf(id);
            let mut base_info_map:HashMap<usize,TreeNodeBaseInfo>= HashMap::new();
            for tree_node in self.tree.path(user_leaf_node.id)
            {
                let zeta_j = Scalar::<Bls12_381_1>::random();
                let gpk = self.gpk.as_ref().unwrap();
                let u_j = tree_node.scalar;
                let base_j = &gpk.g + &gpk.h0*&zeta_j + &gpk.h1*&u_j + &msg.X;
                base_info_map.insert(tree_node.id,TreeNodeBaseInfo{base_j:base_j,zeta_j:zeta_j,u_j:u_j});
            }

            let user_info = UserInfo
            {
                id:id.clone() as u16,
                address:msg.address.clone(),
                name:msg.name.clone(),
                pk_hex:msg.pk_hex.clone(), 
                X:msg.X.clone(), 
                X_sim:msg.X_sim.clone(),
                tau:user_leaf_node.tau.clone(), 
                leaf_node:user_leaf_node,
                leaf_node_base_info_map:base_info_map,
                mtaparams:MTAParams{
                    mta_A:None,
                    mta_B:None,
                },
                ei_info:None,
                user_signature_info:None
            };

            //user_info_map.insert(id.clone() as u16,user_info.clone());
            // 修改
            self.user_info_map.as_mut().unwrap().insert(id.clone() as u16,user_info.clone());

            Ok( 
                ProxyToNodesJoinIssuePhaseTwoBroadcastMsg
                { 
                    sender:self.id,
                    role:self.role.clone(),
                    user_id:id.clone() as u16,
                    X:msg.X.clone(),
                    X_sim:msg.X_sim.clone(),
                    c_x:msg.c_x.clone(),
                    s_x:msg.s_x.clone(),
                    user_info:user_info
                },
                    
            )
        }
        else 
        {
            Err(Error::InvalidCom)
        }
    } 

    /// 合并指数,计算签名A的1/k，颁发签名给用户 
    pub fn join_issue_phase_three(&mut self,msg_vec:&Vec<NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg>)->(ProxyToUserJoinIssuePhaseThreeP2PMsg,ProxyToNodesJoinIssuePhaseThreeBroadcastMsg)
    { 
        assert_eq!(msg_vec.len(),(self.threashold_param.threshold + 1) as usize);
        let user_id = msg_vec[0].user_id;
        let mut A_1_k_c_k_map:HashMap<usize,A1kCKInfo> = HashMap::new();
        let mut A_1_k_map: HashMap<usize,Point<Bls12_381_1>> = HashMap::new();
        // Merge
        let leaf_node_base_info_map = &self.user_info_map.as_ref().unwrap().get(&user_id).unwrap().leaf_node_base_info_map;
        let (c_zero,_) = encrypt(&self.group, &hex_to_pk(&self.user_info_map.as_ref().unwrap().get(&user_id).unwrap().pk_hex), &Scalar::<Bls12_381_1>::zero());
        for (tree_node_id,base_info) in leaf_node_base_info_map
        {
            let xi_j = msg_vec
            .iter()
            .map(|msg|msg.c_ki_pi_share_map.get(&tree_node_id).unwrap().xi_j_i.clone()).sum();

            let exp_share:Scalar<Bls12_381_1> = msg_vec
            .iter()
            .map(|msg|msg.c_ki_pi_share_map.get(&tree_node_id).unwrap().pi_share.clone()).sum();
            

            let c_k = msg_vec
            .iter()
            .fold(c_zero.clone(), |acc,msg|eval_sum(&acc, &hex_to_ciphertext(&msg.c_ki_pi_share_map.get(&tree_node_id).unwrap().c_ki_hex)));
            
            let A_1_k = &base_info.base_j * &exp_share.invert().unwrap();
            A_1_k_map.insert(tree_node_id.clone(), A_1_k.clone());
            A_1_k_c_k_map.insert(tree_node_id.clone(), A1kCKInfo { A_1_k: A_1_k.clone(), c_k_hex: ciphertext_to_hex(&c_k), xi_j: xi_j, zeta_j:base_info.zeta_j.clone(), uj:base_info.u_j.clone(), tau:self.user_info_map.as_ref().unwrap().get(&user_id).unwrap().tau.clone()});

        }
        (
            ProxyToUserJoinIssuePhaseThreeP2PMsg
            {
                sender:self.id,
                role:self.role.clone(),
                A_1_k_c_k_map:A_1_k_c_k_map.clone()
            }, 
            ProxyToNodesJoinIssuePhaseThreeBroadcastMsg
            {
                sender:self.id,
                role:self.role.clone(),
                user_id:user_id,
                A_1_k_map:A_1_k_map
            }
        )

    }

    /// 合并 A_gamma_C_k
    pub fn join_issue_phase_four(&self,msg_vec:&Vec<NodeToProxyJoinIssuePhaseThreeP2PMsg>)->ProxyToNodesJoinIssuePhaseFourBroadcastMsg
    {
        assert_eq!(msg_vec.len(),(self.threashold_param.threshold + 1) as usize);
        let user_id = msg_vec.first().unwrap().user_id.clone();
        let mut A_gamma_C_k_map:HashMap<usize,Point<Bls12_381_1>> = HashMap::new();
        let tree_node_id_vec = msg_vec.first().unwrap().A_gamma_C_i_k_map.keys().cloned().collect::<Vec<_>>();
        for tree_node_id in tree_node_id_vec
        {
            let A_gamma_C_k = msg_vec
            .iter()
            .fold(Point::<Bls12_381_1>::zero(), |acc,msg| acc + msg.A_gamma_C_i_k_map.get(&tree_node_id).unwrap());

            A_gamma_C_k_map.insert(tree_node_id,A_gamma_C_k);
        }
        ProxyToNodesJoinIssuePhaseFourBroadcastMsg
         {
            sender:self.id,
            role:self.role.clone(),
            user_id:user_id,
            A_gamma_C_k_map:A_gamma_C_k_map
         }
    }

    /// 合并 A_gamma_C
    pub fn join_issue_phase_five(&self,msg_vec:&Vec<NodeToProxyJoinIssuePhaseFourP2PMsg>)->ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
    {
        assert_eq!(msg_vec.len(),(self.threashold_param.threshold + 1) as usize);
        let user_id = msg_vec.first().unwrap().user_id.clone();
        let mut A_gamma_C_map:HashMap<usize,Point<Bls12_381_1>> = HashMap::new();
        let tree_node_id_vec = msg_vec.first().unwrap().A_gamma_C_k_ki_map.keys().cloned().collect::<Vec<_>>();
        for tree_node_id in tree_node_id_vec
        {
            let A_gamma_C = msg_vec
            .iter()
            .fold(Point::<Bls12_381_1>::zero(), |acc,msg| acc + msg.A_gamma_C_k_ki_map.get(&tree_node_id).unwrap());

            A_gamma_C_map.insert(tree_node_id,A_gamma_C);
        }
        info!("Join phase is finished!");
        println!("User {}'s key is generated!",user_id);
        ProxyToNodesJoinIssuePhaseFiveBroadcastMsg
        {
            sender:self.id,
            role:self.role.clone(),
            user_id:user_id,
            A_gamma_C_map:A_gamma_C_map
        } 
    }

}

#[test]
fn test(){
    let a:Option<HashMap<i32,i32>> = None;
    let mut user_info_map = match a.clone(){
        Some(b)=> 
        {
            a.unwrap()
        }
        None => HashMap::new()
    };
    //println!("{:?}",user_info_map.len());
}