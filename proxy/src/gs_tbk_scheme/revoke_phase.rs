use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use log::info;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::time::Duration as StdDuration;
use chrono::{DateTime,Local,Duration,NaiveDateTime,prelude::*};

use crate::proxy::Proxy;
use gs_tbk_scheme::tree::Tau;
use gs_tbk_scheme::params::{RevokeBBSSignature,EiInfo,RL};
use gs_tbk_scheme::messages::proxy::revoke_msg::{TreeNodeBaseInfo,ProxyToNodesRevokePhaseOneBroadcastMsg,RevokeInfo,ProxyToNodesRevokePhaseTwoBroadcastMsg,ProxyToUserRevokePhaseBroadcastMsg};
use gs_tbk_scheme::messages::node::revoke_msg::{NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg};
use gs_tbk_scheme::messages::user::revoke_msg::RevokePhaseStartFlag;

impl Proxy
{
    /// 根据当前时间，选择参数并计算出签名的base部分
    pub fn revoke_phase_one(&mut self, user_id:u16)->ProxyToNodesRevokePhaseOneBroadcastMsg
    {
        info!("Revoke phase is starting!");
        println!("Revoke phase is starting!");
        let gpk = self.gpk.as_ref().unwrap(); 
        let yt = Scalar::<Bls12_381_1>::random().to_bigint();
        let h_sim_t =&gpk.g_sim * Scalar::<Bls12_381_1>::from_bigint(&yt);
        let h_hat_t = &gpk.g_hat * Scalar::<Bls12_381_2>::from_bigint(&yt);

        // Find the closest leaf node
        let time = Local::now(); 
        let time_str = time.format("%Y-%m-%d %H:%M:%S").to_string();
        let t = Tau  
        {
            scalar:Scalar::<Bls12_381_1>::random(),
            realtime:time_str,
        };
        let mut leaf_node = self.tree.tree[0].clone();
        for tree_node in self.tree.get_leaf_nodes()
        {
            let tree_node_time = Local.from_local_datetime(&NaiveDateTime::parse_from_str(&tree_node.tau.realtime, "%Y-%m-%d %H:%M:%S").unwrap()).unwrap();
            if time < tree_node_time
            {
                leaf_node = tree_node;
                break;
            }
        }
        let mut base_info_map:HashMap<usize,TreeNodeBaseInfo>= HashMap::new();
        for tree_node in self.tree.cstbk(leaf_node.id.clone())
        {
            let zeta_j = Scalar::<Bls12_381_1>::random();
            let v_j = tree_node.scalar;
            let base_j = &gpk.g + &gpk.h0*&zeta_j + &gpk.h1*&v_j + &gpk.h2*&t.scalar ;
            base_info_map.insert(tree_node.id,TreeNodeBaseInfo{base_j:base_j,zeta_j:zeta_j,v_j:v_j});
        }
        self.revoke_info = Some(
            RevokeInfo{
                leaf_node_id:leaf_node.id,
                t:t.clone(),
                yt:Scalar::<Bls12_381_1>::from_bigint(&yt),
                h_sim_t:h_sim_t,                 
                h_hat_t:h_hat_t,
                leaf_node_base_info_map:base_info_map.clone(),
            }
        );
        ProxyToNodesRevokePhaseOneBroadcastMsg
        {
            sender:self.id.clone(),
            role:self.role.clone(),
            leaf_node_id:leaf_node.id, 
            t:t,
            base_info_map:base_info_map,
            user_id:user_id
        }
        
    }
 
    /// 选择需要提前撤销的用户，然后计算出RL
    pub fn choose_revoke_user(&mut self,ru_list:Vec<u16>) -> RL
    {
        // info!("77777777777777777777777");
        let mut grt_map:HashMap<u16, Point<Bls12_381_1>> = HashMap::new();
        for id in ru_list
        {
            grt_map.insert(id, self.user_info_map.as_ref().unwrap().get(&id).unwrap().X_sim.clone() * self.revoke_info.as_ref().unwrap().yt.clone());
        }
        
        // info!("77777777777777777777777");
        RL{
            h_sim_t:self.revoke_info.as_ref().unwrap().h_sim_t.clone(),
            h_hat_t:self.revoke_info.as_ref().unwrap().h_hat_t.clone(),
            grt_map,
        }
        
    } 
     
    /// 合并mta的share，和相关参数分片，计算出完整签名。
    pub fn revoke_phase_two(&mut self,msg_vec:&Vec<NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg>) -> (ProxyToNodesRevokePhaseTwoBroadcastMsg,ProxyToUserRevokePhaseBroadcastMsg)
    {
        assert_eq!(msg_vec.len(),(self.threashold_param.threshold + 1) as usize);
        // Compute ei_t
        let leaf_node_base_info_map = &self.revoke_info.as_ref().unwrap().leaf_node_base_info_map;
        let mut revoke_bbs_signatures_map:HashMap<usize,RevokeBBSSignature> = HashMap::new();
        for (tree_node_id,base_info) in leaf_node_base_info_map
        {
            let xi_j:Scalar<Bls12_381_1> = msg_vec
            .iter()
            .map(|msg|msg.ki_pi_share_map.get(&tree_node_id).unwrap().xi_j_i.clone()).sum();

            let exp_share:Scalar<Bls12_381_1> = msg_vec
            .iter()
            .map(|msg|msg.ki_pi_share_map.get(&tree_node_id).unwrap().pi_share.clone()).sum();
            
            let k:Scalar<Bls12_381_1> = msg_vec
            .iter()
            .map(|msg|msg.ki_pi_share_map.get(&tree_node_id).unwrap().ki.clone()).sum();
           
            let Bi = &base_info.base_j * (&exp_share.invert().unwrap() * &k);
            revoke_bbs_signatures_map.insert(tree_node_id.clone(), RevokeBBSSignature { Bj: Bi, xi_j: xi_j, zeta_j: base_info.zeta_j.clone(), vj: base_info.v_j.clone() });
        }
        let ei_info = EiInfo{t:self.revoke_info.as_ref().unwrap().t.clone(),revoke_bbs_signatures_map,h_sim_t:self.revoke_info.as_ref().unwrap().h_sim_t.clone()};
        
        //info!("6666666666666666666");
        // Compute RL 生成撤销用户名单
        // let rl = match self.rl{
        //     None => {
        //         let ru_list:Vec<u16> = vec![2];
        //         self.choose_revoke_user(ru_list)
        //     }
        //     _=>{
        //         self.rl.as_ref().unwrap().clone()
        //     }
                
        // };
        //info!("6666666666666666666");

        self.ei_info =Some(ei_info.clone());
        //self.rl =Some(rl.clone());

        //info!("6666666666666666666");
        
        info!("Revoke phase is finished!");
        println!("Revoke phase is finished!");
        (
            ProxyToNodesRevokePhaseTwoBroadcastMsg
            {
                sender:self.id.clone(),
                role:self.role.clone(),
                ei_info:ei_info.clone(),
                //rl:rl,
                user_id:msg_vec[0].user_id.clone(),
            },
            ProxyToUserRevokePhaseBroadcastMsg
            {
                sender:self.id.clone(),
                role:self.role.clone(),
                ei_info:ei_info.clone(),
            }
        )
    }
}

 