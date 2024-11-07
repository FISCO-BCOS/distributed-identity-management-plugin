use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::elliptic::curves::bls12_381::Pair;
use gs_tbk_scheme::messages::user::sign_msg::UserSignatureInfo;
use log::{warn, info};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str;
use regex::Regex;

use crate::node::Node;
use crate::Error::{self, InvalidKey, InvalidSS};
use gs_tbk_scheme::messages::proxy::verify_msg::ProxyToNodesVerifyPhaseBroadcastMsg;

impl Node 
{
    /// 验证用户的签名
    // pub fn verify_phase_1(&self,msg:&ProxyToNodesVerifyPhaseBroadcastMsg,m:String)->Result<(),Error>
    // {
    //     let sigma = &msg.sigma;
    //     let gpk = self.gpk.clone().unwrap();
    //     if Pair::compute_pairing(&sigma.psi_6, &gpk.g_hat) != Pair::compute_pairing(&gpk.g_sim, &sigma.psi_7) {
    //         warn!("User {} Proxy::verify_phase() : invalid signature",msg.user_id);
    //         Err(Error::InvalidSig)
    //     }
    //     else 
    //     {
    //         let R1: Pair = Pair::compute_pairing(&(&sigma.s_zeta_1 * &gpk.h0), &gpk.g_hat)
    //             .add_pair(&Pair::compute_pairing(&(&sigma.s_u * &gpk.h1), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.s_x* &gpk.h2), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.s_alpha * gpk.g1.as_ref().unwrap()), gpk.vk_A.as_ref().unwrap()))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.s_delta_1 * gpk.g1.as_ref().unwrap()), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(&(-&sigma.s_xi_1) * &sigma.psi_2), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(-&sigma.c * &sigma.psi_2), gpk.vk_A.as_ref().unwrap()))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.c * &gpk.g), &gpk.g_hat));
    //         let R2:Pair = Pair::compute_pairing(&(&sigma.s_zeta_2 * &gpk.h0), &gpk.g_hat)
    //             .add_pair(&Pair::compute_pairing(&(&sigma.s_u * &gpk.h1), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.s_alpha * &gpk.g2), gpk.vk_B.as_ref().unwrap()))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.s_delta_2 * &gpk.g2), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(&(-&sigma.s_xi_2) * &sigma.psi_3), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(-&sigma.c * &sigma.psi_3), gpk.vk_B.as_ref().unwrap()))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.c * &gpk.g), &gpk.g_hat))
    //             .add_pair(&Pair::compute_pairing(&(&sigma.c * &self.ei_info.as_ref().unwrap().t.scalar * &gpk.h2), &gpk.g_hat));
    //         let R3: Point<Bls12_381_1> = (&sigma.s_xi_1 * &sigma.psi_1) - &sigma.s_delta_1 * &gpk.f;
    //         let R4: Point<Bls12_381_1> = (&sigma.s_xi_2 * &sigma.psi_1) - &sigma.s_delta_2 * &gpk.f;
    //         let R5: Point<Bls12_381_1> = (&sigma.s_beta * &self.ei_info.as_ref().unwrap().h_sim_t) + (-&sigma.c * &sigma.psi_4);
    //         let R6: Point<Bls12_381_1> = (&sigma.s_x + &sigma.s_beta) * &sigma.psi_6 + &(-&sigma.c * &sigma.psi_5);
    //         let c = Sha256::new()
    //         .chain_point(&sigma.psi_1)
    //         .chain_point(&sigma.psi_2)
    //         .chain_point(&sigma.psi_3)
    //         .chain_point(&sigma.psi_4)
    //         .chain_point(&sigma.psi_5)
    //         .chain_point(&sigma.psi_6)
    //         .chain_point(&sigma.psi_7)
    //         .chain_point(&R3)
    //         .chain_point(&R4)
    //         .chain_point(&R5)
    //         .chain_point(&R6)
    //         .chain(R1.e.to_string().as_bytes())
    //         .chain(R2.e.to_string().as_bytes())
    //         .chain(m.as_bytes())
    //         .result_scalar();
    //         if c != sigma.c
    //         {
    //             warn!("User {} Proxy::verify_phase() : invalid hash",msg.user_id);
    //             return Err(Error::InvalidSig);
    //         }
    //         else 
    //         {
    //             let grt_map = self.rl.as_ref().unwrap().grt_map.clone();
    //             if grt_map.contains_key(&msg.user_id) && Pair::compute_pairing(&(grt_map.get(&msg.user_id).unwrap() + &sigma.psi_4), &sigma.psi_7) == Pair::compute_pairing(&sigma.psi_5, &self.rl.as_ref().unwrap().h_hat_t)
    //             {
    //                 warn!("User {} Node::verify_phase() : invalid signature",msg.user_id);
    //                 return Err(Error::InvalidSig);
    //             }
    //             else 
    //             {
    //                 info!("User {} Node::verify_phase() : verify successfully",msg.user_id);
    //                 Ok(())
    //             }
    //         }
    //     }
    // }

    pub fn verify_phase(&mut self,msg:&ProxyToNodesVerifyPhaseBroadcastMsg)->Result<(),Error>{
        // 调用java SDK查询
        let script_path = "/home/test/fisco/user-signatures/dist/signature_run.sh";
        let script_args = ["query",&self.user_info_map.as_ref().unwrap().get(&msg.user_id).unwrap().name];

        // 保存原来的工作目录
        let original_dir = env::current_dir().expect("Failed to get current directory");

        let java_project_dir = PathBuf::from("/home/test/fisco/user-signatures/dist");
        env::set_current_dir(&java_project_dir)
            .expect("Failed to change current directory");

        let mut child = Command::new("bash")
            .arg(script_path)
            .arg(script_args[0])
            .arg(script_args[1])
            .stdin(Stdio::null()) 
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to execute Bash script");

        let output = child.wait_with_output().expect("Failed to read Bash script output");

        if output.status.success() {
            let stdout = str::from_utf8(&output.stdout)
                .expect("Invalid UTF-8 sequence in stdout");
            // println!("Bash script return value: {}", stdout.trim());

            // // 定义正则表达式
            let re = Regex::new(r"signature\s*(.*)").unwrap();

            // 在文本中查找匹配项
            if let Some(captures) = re.captures(stdout.trim()) {
                if let Some(matched) = captures.get(1) {
                    // println!("signature:{}", matched.as_str().trim());
                    let user_signature_info:UserSignatureInfo = serde_json::from_str(&matched.as_str().trim()).unwrap();
                    //info!("query signature from chain successfully!");
                    
                    // 查询到后存到结构体中
                    self.user_info_map.as_mut().unwrap().get_mut(&msg.user_id).unwrap().user_signature_info = Some(user_signature_info.clone());
                    //info!("{:?}",self.user_info_map.as_ref().unwrap().get(&msg.user_id).unwrap().user_signature_info.as_ref().unwrap().name);

                    // 链上数据验证
       
                    let m = &user_signature_info.m;
                    let sigma = &user_signature_info.signature; 
                    let gpk = self.gpk.clone().unwrap();
                    if Pair::compute_pairing(&sigma.psi_6, &gpk.g_hat) != Pair::compute_pairing(&gpk.g_sim, &sigma.psi_7) {
                        warn!("User {} Proxy::verify_phase() : invalid signature",&user_signature_info.user_id);
                        println!("User {} Proxy::verify_phase() : invalid signature",&user_signature_info.user_id);
                        return Err(Error::InvalidSig);
                    }
                    else 
                    {
                        let ei_info = self.user_info_map.as_ref().unwrap().get(&msg.user_id).unwrap().ei_info.clone().unwrap();
                        let R1: Pair = Pair::compute_pairing(&(&sigma.s_zeta_1 * &gpk.h0), &gpk.g_hat)
                            .add_pair(&Pair::compute_pairing(&(&sigma.s_u * &gpk.h1), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(&sigma.s_x* &gpk.h2), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(&sigma.s_alpha * gpk.g1.as_ref().unwrap()), gpk.vk_A.as_ref().unwrap()))
                            .add_pair(&Pair::compute_pairing(&(&sigma.s_delta_1 * gpk.g1.as_ref().unwrap()), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(&(-&sigma.s_xi_1) * &sigma.psi_2), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(-&sigma.c * &sigma.psi_2), gpk.vk_A.as_ref().unwrap()))
                            .add_pair(&Pair::compute_pairing(&(&sigma.c * &gpk.g), &gpk.g_hat));
                        let R2:Pair = Pair::compute_pairing(&(&sigma.s_zeta_2 * &gpk.h0), &gpk.g_hat)
                            .add_pair(&Pair::compute_pairing(&(&sigma.s_u * &gpk.h1), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(&sigma.s_alpha * &gpk.g2), gpk.vk_B.as_ref().unwrap()))
                            .add_pair(&Pair::compute_pairing(&(&sigma.s_delta_2 * &gpk.g2), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(&(-&sigma.s_xi_2) * &sigma.psi_3), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(-&sigma.c * &sigma.psi_3), gpk.vk_B.as_ref().unwrap()))
                            .add_pair(&Pair::compute_pairing(&(&sigma.c * &gpk.g), &gpk.g_hat))
                            .add_pair(&Pair::compute_pairing(&(&sigma.c * &ei_info.t.scalar * &gpk.h2), &gpk.g_hat));
                        let R3: Point<Bls12_381_1> = (&sigma.s_xi_1 * &sigma.psi_1) - &sigma.s_delta_1 * &gpk.f;
                        let R4: Point<Bls12_381_1> = (&sigma.s_xi_2 * &sigma.psi_1) - &sigma.s_delta_2 * &gpk.f;
                        let R5: Point<Bls12_381_1> = (&sigma.s_beta * &ei_info.h_sim_t) + (-&sigma.c * &sigma.psi_4);
                        let R6: Point<Bls12_381_1> = (&sigma.s_x + &sigma.s_beta) * &sigma.psi_6 + &(-&sigma.c * &sigma.psi_5);

                        let c = Sha256::new()
                        .chain_point(&sigma.psi_1)
                        .chain_point(&sigma.psi_2)
                        .chain_point(&sigma.psi_3)
                        .chain_point(&sigma.psi_4)
                        .chain_point(&sigma.psi_5)
                        .chain_point(&sigma.psi_6)
                        .chain_point(&sigma.psi_7)
                        .chain_point(&R3)
                        .chain_point(&R4)
                        .chain_point(&R5)
                        .chain_point(&R6)
                        .chain(R1.e.to_string().as_bytes())
                        .chain(R2.e.to_string().as_bytes())
                        .chain(m.as_bytes())
                        .result_scalar();
                        

                        if c != sigma.c
                        {
                            warn!("User {} Proxy::verify_phase() : invalid hash",msg.user_id);
                            println!("User {} Proxy::verify_phase() : invalid hash",msg.user_id);
                            return Err(Error::InvalidSig);
                        }
                        else 
                        {
                            // let grt_map = self.rl.as_ref().unwrap().grt_map.clone();
                            // if grt_map.contains_key(&msg.user_id) && Pair::compute_pairing(&(grt_map.get(&msg.user_id).unwrap() + &sigma.psi_4), &sigma.psi_7) == Pair::compute_pairing(&sigma.psi_5, &self.rl.as_ref().unwrap().h_hat_t)
                            // {
                            //     warn!("User {} Node::verify_phase() : invalid signature",msg.user_id);
                            //     println!("User {} Node::verify_phase() : invalid signature",msg.user_id);
                            //     return Err(Error::InvalidSig);
                            // }
                            // else 
                            // {
                                info!("User {} Node::verify_phase() : verify successfully",msg.user_id);
                                println!("User {} Node::verify_phase() : verify successfully",msg.user_id);
                                return Ok(());
                            //}
                        }
                    }
                }
            }

        } else {
            let stderr = str::from_utf8(&output.stderr)
                .expect("Invalid UTF-8 sequence in stderr");
            println!("Bash script failed: {}", stderr.trim());
        }
        // 切换回原来的工作目录
        env::set_current_dir(original_dir)
        .expect("Failed to change current directory");
        
        return Ok(());
    }
}