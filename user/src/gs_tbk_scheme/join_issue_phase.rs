use curv::{elliptic::curves::{Bls12_381_1, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use std::collections::HashMap;


use crate::user::User;
use gs_tbk_scheme::{messages::user::join_issue_msg::{UserToProxyJoinIssuePhaseTwoP2PMsg,UserJoinIssuePhaseStartFlag}, params::Gsk};
use gs_tbk_scheme::messages::proxy::join_issue_msg::{ProxyToUserJoinIssuePhaseOneP2PMsg,ProxyToUserJoinIssuePhaseThreeP2PMsg};
use crate::config::config::Config;
use class_group::primitives::cl_dl_public_setup::*;
use gs_tbk_scheme::params::{CLKeys,BBSSignature,hex_to_ciphertext,pk_to_hex};
use log::{info,warn,error};

 
impl User 
{
    /// 初始化自己信息
    pub fn init(config:Config) -> Self
    {
        let group = CLGroup::new();
        // Initialize Node Info
        let (sk,pk) = group.keygen();
        User 
        {
            id:None, 
            name:config.name,
            role:"User".to_string(),
            proxy_addr:config.proxy_addr,
            user_addr:config.user_addr,
            listen_addr:config.listen_addr,
            clkeys:CLKeys { sk: sk, pk: pk },
            group:group,
            usk:None,
            tau:None,
            gpk:None,
            gsk:None,
            ei_info:None
        }

    }

    /// 发送自己的信息给代理
    pub fn join_issue_phase_one(&self)->UserJoinIssuePhaseStartFlag
    {
        info!("Join phase is starting!");
        println!("Join phase is starting!");
        UserJoinIssuePhaseStartFlag
        {
            //sender:self.id.unwrap(),
            role:self.role.clone(),
            ip:self.user_addr.clone(),
            name:self.name.clone()
        }
    }

    /// 提交自己的信息公钥和相关zkp proof
    pub fn join_issue_phase_two(&mut self,msg:ProxyToUserJoinIssuePhaseOneP2PMsg)->UserToProxyJoinIssuePhaseTwoP2PMsg
    {
        self.gpk = Some(msg.gpk.clone());
        self.id = Some(msg.user_id);
        
        let gpk = msg.gpk;
        let x_i = Scalar::<Bls12_381_1>::random();//uski
        
        let X_i = &gpk.h2 * &x_i;
        let X_i_sim = &gpk.g_sim* &x_i;

        let r_x = Scalar::<Bls12_381_1>::random();
        let R = &gpk.h2 * &r_x;
        let R_sim = &gpk.g_sim * &r_x;

        let c_x_b = Sha256::new()
            .chain_point(&X_i)
            .chain_point(&X_i_sim)
            .chain_point(&R) 
            .chain_point(&R_sim)
            .result_bigint();

        let c_x = Scalar::<Bls12_381_1>::from_bigint(&c_x_b);
        let s_x = r_x + &c_x * &x_i;
        self.usk = Some(x_i.clone());

        UserToProxyJoinIssuePhaseTwoP2PMsg 
        {  
            sender: self.id.unwrap(), 
            role:self.role.clone(),
            address:self.user_addr.clone(),
            name:self.name.clone(),
            pk_hex:pk_to_hex(&self.clkeys.pk),
            X: X_i, 
            X_sim: X_i_sim, 
            s_x: s_x, 
            c_x: c_x 
        } 
    }

    /// 解密得到k，然后自行计算出A，得到gski
    pub fn join_issue_phase_three(&mut self,msg:ProxyToUserJoinIssuePhaseThreeP2PMsg)
    {
        let mut gsk_i_map:HashMap<usize,BBSSignature> = HashMap::new();
        for (tree_node_id,info) in msg.A_1_k_c_k_map
        { 
            let k = decrypt(&self.group, &self.clkeys.sk, &hex_to_ciphertext(&info.c_k_hex));
            //println!("tree_node_id {:?},k {:?}",tree_node_id,k);
            //assert_eq!(k,info.k);
            let Aj = &info.A_1_k * k;
            gsk_i_map.insert(tree_node_id, BBSSignature { Aj: Aj, xi_j: info.xi_j, zeta_j: info.zeta_j, uj: info.uj });
        }
        self.gsk = Some(Gsk{bbs_signatures_map:gsk_i_map});
        info!("Join phase is finished!");
        println!("Join phase is finished!");
    }
}