// use curv::cryptographic_primitives::hashing::DigestExt;
// use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
// use curv::elliptic::curves::bls12_381::Pair;
// use sha2::{Sha256, Digest};
// use std::collections::HashMap;

use crate::node::Node;
// use crate::Error::{self, InvalidKey, InvalidSS};
// use gs_tbk_scheme::params::Reg;
use gs_tbk_scheme::params::Sigma;
use gs_tbk_scheme::messages::proxy::verify_msg::ProxyToNodesVerifyPhaseBroadcastMsg;
use gs_tbk_scheme::messages::proxy::open_msg::{ProxyToNodesOpenPhaseOneBroadcastMsg,ProxyToNodesOpenPhaseTwoBroadcastMsg};
use gs_tbk_scheme::messages::node::open_msg::{NodeToProxyOpenPhaseOneP2PMsg,NodeToProxyOpenPhaseTwoP2PMsg};
use log::{info,warn};

impl Node
{
    /// 计算 psi 1/gamma_O_i
    pub fn open_phase_one(&self,msg:&ProxyToNodesVerifyPhaseBroadcastMsg)->NodeToProxyOpenPhaseOneP2PMsg
    {
        info!("Open Phase is starting");
        println!("Open Phase is starting"); 
        //println!("reg is {:?}",self.reg);
        let signature = self.user_info_map.as_ref().unwrap().get(&msg.user_id).unwrap().user_signature_info.as_ref().unwrap().signature.clone();
        let psi_1_gamma_O_i = &signature.psi_1 * self.dkgparams.dkgparam_O.as_ref().unwrap().ui.as_ref().unwrap();
        NodeToProxyOpenPhaseOneP2PMsg
        {
            sender:self.id.unwrap(), 
            role:self.role.clone(),
            user_id:msg.user_id, 
            psi_1_gamma_O_i,
            sigma:signature,
        }
    }

    /// 计算A_gamma_C_i
    pub fn open_phase_two(&self,msg:&ProxyToNodesOpenPhaseOneBroadcastMsg)->NodeToProxyOpenPhaseTwoP2PMsg
    {
        let Aj_gamma_C_i = &msg.Aj * self.dkgparams.dkgparam_C.as_ref().unwrap().ui.as_ref().unwrap();
        NodeToProxyOpenPhaseTwoP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            user_id:msg.user_id,
            Aj_gamma_C_i,
        }
    }

    /// 揭示使用无效签名的用户
    pub fn open_phase_three(&self,msg:&ProxyToNodesOpenPhaseTwoBroadcastMsg)
    {
        let reg = self.reg.as_ref().unwrap();
        if reg.contains_key(&msg.user_id)
        { 
            for (user_id,reg_i) in reg
            {
                if user_id == &msg.user_id
                {
                    info!("Find the user successfully");
                    let mut flag = true;
                    for (tree_node_id,Aj_gamma_C) in reg_i.Aj_gamma_C_map.clone()
                    {
                        if Aj_gamma_C == msg.Aj_gamma_C  // 过期
                        { 
                            // assert_eq!(Aj_gamma_C,msg.Aj_gamma_C);
                            info!("----------------------------------------------------------------------------------------");
                            info!("This user {} maybe used a revoked key!",user_id);
                            // info!("Find sensetive words in block id 52");//
                            info!("This user {} maybe malicious!",user_id);// 
                            info!("The infomation is: ");
                            info!("user_id:{}",user_id);
                            info!("user_name:{}",self.user_info_map.as_ref().unwrap().get(&user_id).unwrap().name); 
                            info!("user address:{:?}",self.user_info_map.as_ref().unwrap().get(&user_id).unwrap().address);
                            info!("----------------------------------------------------------------------------------------");
                            flag = false;
                            break;
                        }
                    }
                    if flag// 违规密钥
                    {
                        info!("----------------------------------------------------------------------------------------");
                        info!("This user {} maybe used a invaild key!",user_id);
                        // info!("Find sensetive words in block id 40");//
                        info!("This user {} maybe malicious!",user_id);//
                        info!("The infomation is: ");
                        info!("user_id:{}",user_id);
                        info!("user_name:{}",self.user_info_map.as_ref().unwrap().get(&user_id).unwrap().name); 
                        info!("user address:{:?}",self.user_info_map.as_ref().unwrap().get(&user_id).unwrap().address);
                        info!("----------------------------------------------------------------------------------------");
                    }
                    
                }
                
            }
            //println!("Didn't find the user!");
        }
        else 
        {
            warn!("The user is not exit!");    
        }
        info!("Open phase is finished!");
        println!("Open phase is finished!")
    }
}