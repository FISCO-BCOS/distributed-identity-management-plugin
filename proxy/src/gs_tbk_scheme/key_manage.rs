use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS,ShamirSecretSharing};
use curv::elliptic::curves::{Point, Bls12_381_1,Bls12_381_2, Scalar};
use log::{warn, info};
use std::collections::HashMap;

use crate::proxy::Proxy;
use class_group::primitives::cl_dl_public_setup::*;
use gs_tbk_scheme::messages::node::key_manage_msg::{NodeToProxyKeyRecoverP2PMsg,NodeToProxyKeyRefreshOneP2PMsg};
use gs_tbk_scheme::messages::node::keygen_msg::ShareProof;
use gs_tbk_scheme::messages::proxy::key_manage_msg::ProxyToNodeKeyRefreshPhaseTwoP2PMsg;
use crate::Error::{self, InvalidKey, InvalidSS};
use gs_tbk_scheme::params::{Gpk,hex_to_ciphertext,hex_to_cldl_proof,hex_to_pk,ciphertext_to_hex}; 

impl Proxy 
{
    /// 恢复密钥（t,n）
    pub fn key_recover(&self,nodes_id:&Vec<u16>,ui_vec:Vec<Scalar<Bls12_381_1>>,xi_vec:Vec<Scalar<Bls12_381_1>>)->bool
    {
        let vss_scheme = VerifiableSS
        {
            parameters:ShamirSecretSharing { threshold: self.threashold_param.threshold, share_count: self.threashold_param.share_counts },
            commitments:vec![Point::<Bls12_381_1>::zero()]
        };
        let xl:Scalar<Bls12_381_1> = ui_vec.iter().sum();
        let xr = vss_scheme.reconstruct(&nodes_id, &xi_vec);
        if xl == xr
        {
            true
        }
        else 
        {
            false 
        }
    }
    
    /// 恢复密钥（t,t）
    pub fn key_recover_add(&self,nodes_id:&Vec<u16>,ui_vec:Vec<Scalar<Bls12_381_1>>,xi_vec:Vec<Scalar<Bls12_381_1>>,addshare_vec:Vec<Scalar<Bls12_381_1>>)->bool
    {
        let vss_scheme = VerifiableSS
        {
            parameters:ShamirSecretSharing { threshold: self.threashold_param.threshold, share_count: self.threashold_param.share_counts },
            commitments:vec![Point::<Bls12_381_1>::zero()]
        };
        let xl:Scalar<Bls12_381_1> = ui_vec.iter().sum();
        let xr = vss_scheme.reconstruct(&nodes_id, &xi_vec);
        let x_add:Scalar<Bls12_381_1> = addshare_vec.iter().sum();
        if xl == xr && xl == x_add && xr == x_add
        {
            true
        }
        else 
        {
            false
        }
    }

    /// 恢复密钥并验证
    pub fn key_recover_phase(&self,msg_vec:&Vec<NodeToProxyKeyRecoverP2PMsg>)
    {
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        info!("Key recover is staring!");
        let participants:Vec<u16> = self.participants.as_ref().unwrap().clone();
        let nodes_id : Vec<u16> = participants.iter().map(|id|id -1 ).collect();

        let mut msg_map :HashMap<u16,NodeToProxyKeyRecoverP2PMsg> = HashMap::new();

        for msg in msg_vec.clone()
        {
            msg_map.insert(msg.sender,msg);
        }
        //println!("{:?}",msg_vec);
        //println!("{:?}",participants);
        //println!("{:?}",msg_map.keys().cloned());
        assert_eq!(msg_map.len(),msg_vec.len());
        let mut ui_vec_gamma_A:Vec<Scalar<Bls12_381_1>> = msg_vec.iter().map(|msg| msg.keysinfo.gamma_A.ui.clone()).collect();
        let mut xi_vec_gamma_A:Vec<Scalar<Bls12_381_1>> = Vec::new();
        for id in participants.clone() 
        {
            xi_vec_gamma_A.push(msg_map.get(&id).unwrap().keysinfo.gamma_A.xi.clone()); 
        }
        let addshare_vec_gamma_A:Vec<Scalar<Bls12_381_1>> = msg_vec.iter().map(|msg|msg.keysinfo.gamma_A.addshare.clone()).collect();
        if self.key_recover_add(&nodes_id, ui_vec_gamma_A, xi_vec_gamma_A, addshare_vec_gamma_A)
        {
            info!("Gamma A is vaild!")
        }

        let mut ui_vec_gamma_B:Vec<Scalar<Bls12_381_1>> = msg_vec.iter().map(|msg| msg.keysinfo.gamma_B.ui.clone()).collect();
        let mut xi_vec_gamma_B:Vec<Scalar<Bls12_381_1>> = Vec::new();
        for id in participants.clone() 
        {
            xi_vec_gamma_B.push(msg_map.get(&id).unwrap().keysinfo.gamma_B.xi.clone()); 
        }
        let addshare_vec_gamma_B:Vec<Scalar<Bls12_381_1>> = msg_vec.iter().map(|msg|msg.keysinfo.gamma_B.addshare.clone()).collect();
        if self.key_recover_add(&nodes_id, ui_vec_gamma_B, xi_vec_gamma_B, addshare_vec_gamma_B)
        {
            info!("Gamma B is vaild!")
        }

        let mut ui_vec_gamma_C:Vec<Scalar<Bls12_381_1>> = msg_vec.iter().map(|msg| msg.keysinfo.gamma_C.ui.clone()).collect();
        let mut xi_vec_gamma_C:Vec<Scalar<Bls12_381_1>> = Vec::new();
        for id in participants.clone() 
        {
            xi_vec_gamma_C.push(msg_map.get(&id).unwrap().keysinfo.gamma_C.xi.clone()); 
        }
        if self.key_recover(&nodes_id, ui_vec_gamma_C, xi_vec_gamma_C)
        {
            info!("Gamma C is vaild!")
        }

        let mut ui_vec_gamma_O:Vec<Scalar<Bls12_381_1>> = msg_vec.iter().map(|msg| msg.keysinfo.gamma_O.ui.clone()).collect();
        let mut xi_vec_gamma_O:Vec<Scalar<Bls12_381_1>> = Vec::new();
        for id in participants.clone() 
        {
            xi_vec_gamma_O.push(msg_map.get(&id).unwrap().keysinfo.gamma_O.xi.clone()); 
        }
        if self.key_recover(&nodes_id, ui_vec_gamma_O, xi_vec_gamma_O)
        {
            info!("Gamma O is vaild!")
        }
        info!("Key recover is finished!");
    }

    /// 验证 CLDLProof 然后合并系数承诺和share
    pub fn key_refresh_phase_two(&self,msg_vec:&Vec<NodeToProxyKeyRefreshOneP2PMsg>) -> Result<HashMap<u16, ProxyToNodeKeyRefreshPhaseTwoP2PMsg>,Error>
    {
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        info!("Key refresh is staring!");
        let dkgtag = msg_vec[0].dkgtag.clone();
        let group = self.group.clone();
        // Verify CLDLProof
        let mut all_verify_flag = true;
        let share_proof_map_vec:Vec<HashMap<u16,ShareProof>> = msg_vec.iter().map(|msg|msg.share_proof_map.clone()).collect();
        let vss_commitments_vec:Vec<VerifiableSS<Bls12_381_1>> =  msg_vec.iter().map(|msg| msg.vss_scheme.clone()).collect();
        for node in self.node_info_vec.as_ref().unwrap()
        {
            for i in 0..share_proof_map_vec.len()
            {
                let share_proof_info = share_proof_map_vec[i].get(&node.id).unwrap();
                //let share_proof_map = share_proof_map_vec.get(i).unwrap();
                let vss_commitments = vss_commitments_vec.get(i).unwrap();

                let c_share = hex_to_ciphertext(&share_proof_info.c_share_hex);
                let commit = vss_commitments.get_point_commitment(i as u16);
                let share_proof = hex_to_cldl_proof(&share_proof_info.share_proof_hex);

                let flag = share_proof.verify(&group,&hex_to_pk(&node.pk_hex),&c_share,&commit).is_ok();
                all_verify_flag = all_verify_flag && flag;
                
            }
            
        }
        if all_verify_flag  
        { 
            // Merge commitment
            let vss_commitments_vec:Vec<Vec<Point<Bls12_381_1>>> = msg_vec.iter().map(|msg|msg.vss_scheme.commitments.clone()).collect();
            let total_vss_commitments = vss_commitments_vec
            .iter()
            .fold(vec![Point::<Bls12_381_1>::zero();vss_commitments_vec.len()], |acc,v| 
                { 
                    acc.iter()
                    .zip(v.iter())
                    .map(|(a,b)| a+b)
                    .collect()
                }
            );
            
            // Merge CL share
            let share_proof_map_vec:Vec<HashMap<u16,ShareProof>> = msg_vec.iter().map(|msg| msg.share_proof_map.clone()).collect();
            let mut msg_map:HashMap<u16, ProxyToNodeKeyRefreshPhaseTwoP2PMsg> = HashMap::new(); 
            for node in self.node_info_vec.as_ref().unwrap()
            {
                let (c_zero,_) = encrypt(&group, &hex_to_pk(&node.pk_hex), &Scalar::<Bls12_381_1>::zero());
                let c_share_sum:Ciphertext = share_proof_map_vec.iter().fold(c_zero, |acc,v|{eval_sum(&acc, &hex_to_ciphertext(&v.get(&node.id).as_ref().unwrap().c_share_hex.clone()))});
                msg_map.insert
                (node.id.clone(), ProxyToNodeKeyRefreshPhaseTwoP2PMsg
                    {
                        dkgtag:dkgtag.clone(),
                        sender:self.id.clone(),
                        role:self.role.clone(),
                        c_share_sum_hex:ciphertext_to_hex(&c_share_sum),
                        vss_scheme_sum:VerifiableSS 
                        { 
                            parameters: 
                            ShamirSecretSharing 
                            { 
                                threshold: self.threashold_param.threshold, 
                                share_count: self.threashold_param.share_counts 
                            }, 
                            commitments: total_vss_commitments.clone() 
                        }
                    }
                );
            }
            info!("Key recover is finished!");
            Ok(msg_map)
        }
        else  
        { 
            Err(Error::InvalidZkp)
        }
    }
}