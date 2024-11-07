use std::collections::HashMap;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::arithmetic::traits::*;
use rand::seq::SliceRandom;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS,ShamirSecretSharing};
use log::{error, info, warn};

use gs_tbk_scheme::{messages::{proxy::keygen_msg::{ProxyKeyGenPhaseStartFlag,ProxyKeyGenPhaseOneBroadcastMsg,ProxyToNodeKeyGenPhaseThreeP2PMsg,ProxyToNodesKeyGenPhasefiveBroadcastMsg}, node::keygen_msg::ZkpProof}};
use gs_tbk_scheme::messages::node::keygen_msg::{NodeToProxyKeyGenPhaseTwoP2PMsg,ShareProof,NodeToProxyKeyGenPhaseFiveP2PMsg};
use crate::proxy::{Proxy};
use class_group::primitives::cl_dl_public_setup::*;
use crate::Error::{self, InvalidKey, InvalidSS};
use gs_tbk_scheme::params::{Gpk,hex_to_ciphertext,hex_to_cldl_proof,hex_to_pk,ciphertext_to_hex};  

impl Proxy 
{
    /// 生成部分公钥，随机选择参与方，然后广播给管理员
    pub fn keygen_phase_one(&mut self)->(ProxyKeyGenPhaseStartFlag, ProxyKeyGenPhaseOneBroadcastMsg)
    {
        info!("Keygen phase is staring!");
        println!("Keygen phase is staring!");
        let flag = ProxyKeyGenPhaseStartFlag
        {
            sender:self.id,
            role:self.role.clone(),
        };

        let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
        let g_hat = Point::<Bls12_381_2>::generator() * Scalar::<Bls12_381_2>::from(1);
        let f = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::random();
        let g_sim = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::random();
        let g2 = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::random();
        let h0 = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::random();
        let h1 = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::random();
        let h2 = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::random();

        let node_id_vec:Vec<u16> = self.node_info_vec.as_ref().unwrap().iter().map(|node|node.id).collect();
        // 随机选择参与节点
        let mut rng = rand::thread_rng();
        let participants:Vec<u16> = node_id_vec.choose_multiple(&mut rng,(self.threashold_param.threshold + 1) as usize).cloned().collect();
        self.participants = Some(participants.clone());
        self.gpk = Some(Gpk{
            g:g.clone(),
            g_hat:g_hat.clone(),
            f:f.clone(), 
            g_sim:g_sim.clone(),
            g2:g2.clone(), 
            h0:h0.clone(),
            h1:h1.clone(),
            h2:h2.clone(),
            vk_A:None,
            vk_B:None,
            g1:None
        });
        let msg = ProxyKeyGenPhaseOneBroadcastMsg{
            g:g,
            g_hat:g_hat,
            f:f, 
            g_sim:g_sim,
            g_2:g2, 
            h_0:h0,
            h_1:h1,
            h_2:h2,
            participants:participants
        };
        (flag,msg) 
    }
 
    /// 验证 CLDLProof 然后合并系数承诺和share碎片
    pub fn keygen_phase_three(&self,msg_vec:Vec<NodeToProxyKeyGenPhaseTwoP2PMsg>) -> Result<HashMap<u16, ProxyToNodeKeyGenPhaseThreeP2PMsg>,Error>
    {
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
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
                let commit = vss_commitments.get_point_commitment(node.id as u16);
                
                let share_proof = hex_to_cldl_proof(&share_proof_info.share_proof_hex);

                let flag = share_proof.verify(&group,&hex_to_pk(&node.pk_hex),&c_share,&commit).is_ok();
                all_verify_flag = all_verify_flag && flag;
                
            } 
            
            // for share_proof_map in share_proof_map_vec.clone()
            // {
            //     let share_proof_info = share_proof_map.get(&node.id).unwrap();
            //     let c_share = hex_to_ciphertext(&share_proof_info.c_share_hex);
            //     let share_proof = hex_to_cldl_proof(&share_proof_info.share_proof_hex);
            //     let flag = share_proof.verify(&group,&hex_to_pk(&node.pk_hex),&c_share,&share_proof_info.g_share).is_ok();
            //     all_verify_flag = all_verify_flag && flag;
            // }
            
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
            let mut msg_map:HashMap<u16, ProxyToNodeKeyGenPhaseThreeP2PMsg> = HashMap::new(); 
            for node in self.node_info_vec.as_ref().unwrap()
            {
                let (c_zero,_) = encrypt(&group, &hex_to_pk(&node.pk_hex), &Scalar::<Bls12_381_1>::zero());
                let c_share_sum:Ciphertext = share_proof_map_vec.iter().fold(c_zero, |acc,v|{eval_sum(&acc, &hex_to_ciphertext(&v.get(&node.id).as_ref().unwrap().c_share_hex.clone()))});
                msg_map.insert
                (node.id.clone(), ProxyToNodeKeyGenPhaseThreeP2PMsg
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
            
            Ok(msg_map)
        }
        else  
        { 
            Err(Error::InvalidZkp)
        }
    }

    /// 验证零知识证明，然后组合出完整的GPK
    pub fn keygen_phase_five(&mut self,msg_vec:&Vec<NodeToProxyKeyGenPhaseFiveP2PMsg>)->Result<ProxyToNodesKeyGenPhasefiveBroadcastMsg,Error>
    {
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        // Verify zkp
        let gpk = self.gpk.as_ref().unwrap();
        let mut all_zkp_flag = true;
        for msg in msg_vec
        {
            let g_z_gamma_A = &gpk.g * &msg.zkp_proof.z_gamma_A_i;
            let g_z_gamma_B = &gpk.g * &msg.zkp_proof.z_gamma_B_i;
            let g_z_gamma_O = &gpk.g * &msg.zkp_proof.z_gamma_O_i;
            let g_hat_z_gamma_A = &gpk.g_hat * Scalar::<Bls12_381_2>::from_bigint(&msg.zkp_proof.z_gamma_A_i.to_bigint());
            let g_hat_z_gamma_B = &gpk.g_hat * Scalar::<Bls12_381_2>::from_bigint(&msg.zkp_proof.z_gamma_B_i.to_bigint());
            let f_z_gamma_O = &gpk.f * &msg.zkp_proof.z_gamma_O_i;
            let flag = if (
                (g_z_gamma_A == &msg.zkp_proof.g_t + &msg.zkp_proof.g_gamma_A_i * &msg.zkp_proof.e && g_hat_z_gamma_A == &msg.zkp_proof.g_hat_t + &msg.vk_A_i * Scalar::<Bls12_381_2>::from_bigint(&msg.zkp_proof.e.to_bigint()))
                &&
                (g_z_gamma_B == &msg.zkp_proof.g_t + &msg.zkp_proof.g_gamma_B_i * &msg.zkp_proof.e && g_hat_z_gamma_B == &msg.zkp_proof.g_hat_t + &msg.vk_B_i * Scalar::<Bls12_381_2>::from_bigint(&msg.zkp_proof.e.to_bigint()))
                &&
                (g_z_gamma_O == &msg.zkp_proof.g_t + &msg.zkp_proof.g_gamma_O_i * &msg.zkp_proof.e && f_z_gamma_O == &msg.zkp_proof.f_t + &msg.g1_i * &msg.zkp_proof.e)
            )
            {
                true
            }
            else
            {
                false
            };
            all_zkp_flag = all_zkp_flag && flag;
        };

        if all_zkp_flag
        {
            let g_hat_gamma_A:Point<Bls12_381_2> = msg_vec.iter().map(|msg| msg.vk_A_i.clone()).sum();
            let g_hat_gamma_B:Point<Bls12_381_2> = msg_vec.iter().map(|msg| msg.vk_B_i.clone()).sum();
            let f_gamma_O:Point<Bls12_381_1> = msg_vec.iter().map(|msg| msg.g1_i.clone()).sum();
            self.gpk.as_mut().unwrap().vk_A = Some(g_hat_gamma_A.clone());
            self.gpk.as_mut().unwrap().vk_B = Some(g_hat_gamma_B.clone());
            self.gpk.as_mut().unwrap().g1 = Some(f_gamma_O.clone());
            //println!("msg length is {:?}",msg_vec.len());
            
            info!("Keygen phase is finished!");
            println!("Keygen phase is finished!");
            Ok(
                ProxyToNodesKeyGenPhasefiveBroadcastMsg
                {
                    sender:self.id,
                    role:self.role.clone(),
                    vk_A:g_hat_gamma_A,
                    vk_B:g_hat_gamma_B,
                    g1:f_gamma_O
                }
            )
        }
        else 
        {
            Err(InvalidSS)      
        }
        

    }

}

