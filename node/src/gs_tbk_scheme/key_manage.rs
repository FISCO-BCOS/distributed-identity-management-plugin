use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS,ShamirSecretSharing};
use curv::elliptic::curves::{Point, Bls12_381_1,Bls12_381_2, Scalar};
use log::info;
use std::collections::HashMap;

use crate::node::{Node};
use crate::Error::{self, InvalidKey, InvalidSS};
use class_group::primitives::cl_dl_public_setup::*;
use gs_tbk_scheme::messages::node::keygen_msg::ShareProof;
use gs_tbk_scheme::messages::proxy::key_manage_msg::ProxyToNodeKeyRefreshPhaseTwoP2PMsg;
use gs_tbk_scheme::messages::node::key_manage_msg::{KeyInfo,KeyInfoWithAddshare,KeysInfo,NodeToProxyKeyRecoverP2PMsg,NodeToProxyKeyRefreshOneP2PMsg};
use gs_tbk_scheme::params::{Gpk,DKGTag,ciphertext_to_hex,cldl_proof_to_hex,hex_to_pk, pk_to_hex,hex_to_ciphertext};

impl Node
{ 
    /// 获取对应的拉格朗日系数
    pub fn gey_li(&self)->Scalar<Bls12_381_1>
    {
        let params = ShamirSecretSharing 
        { 
            threshold: self.threashold_param.threshold, 
            share_count: self.threashold_param.share_counts,
        };
        let participants:Vec<u16> = self.participants.as_ref().unwrap().iter().map(|id| id-1).collect();
        //println!("id {:?} participants is {:?}",self.id.unwrap()-1,participants);
        VerifiableSS::<Bls12_381_1>::map_share_to_new_params(&params, self.id.unwrap()-1, &participants)
        
    }

    /// 获取加法共享的share
    pub fn get_addshare(&mut self, dkgtag: &DKGTag)
    {
        let li = self.gey_li();
        match dkgtag {
            DKGTag::Gamma_A=>{
                self.dkgparams.dkgparam_A.as_mut().unwrap().addshare = Some(&li * self.dkgparams.dkgparam_A.as_ref().unwrap().mskshare.as_ref().unwrap())
            }
            DKGTag::Gamma_B=>{
                self.dkgparams.dkgparam_B.as_mut().unwrap().addshare = Some(&li * self.dkgparams.dkgparam_B.as_ref().unwrap().mskshare.as_ref().unwrap())
            }
            DKGTag::Gamma_O=>{
                self.dkgparams.dkgparam_O.as_mut().unwrap().addshare = Some(&li * self.dkgparams.dkgparam_O.as_ref().unwrap().mskshare.as_ref().unwrap())
            }
            DKGTag::Gamma_C=>{
                self.dkgparams.dkgparam_C.as_mut().unwrap().addshare = Some(&li * self.dkgparams.dkgparam_C.as_ref().unwrap().mskshare.as_ref().unwrap())
            }
        }

    }
    
    /// 密钥恢复
    pub fn key_recover_phase(&self)->NodeToProxyKeyRecoverP2PMsg
    {
        let (gamma_A_add,gamma_B_add) = if self.participants.as_ref().unwrap().contains(self.id.as_ref().unwrap())
        {
            (self.dkgparams.dkgparam_A.as_ref().unwrap().addshare.clone().unwrap(), self.dkgparams.dkgparam_B.as_ref().unwrap().addshare.clone().unwrap() )
        }
        else
        {
            (Scalar::<Bls12_381_1>::zero(), Scalar::<Bls12_381_1>::zero())
        };
        NodeToProxyKeyRecoverP2PMsg 
        { 
            sender: self.id.unwrap(), 
            role:self.role.clone(),
            keysinfo: KeysInfo 
            { 
                gamma_A: KeyInfoWithAddshare 
                { 
                    ui: self.dkgparams.dkgparam_A.as_ref().unwrap().ui.clone().unwrap(),  
                    xi: self.dkgparams.dkgparam_A.as_ref().unwrap().mskshare.clone().unwrap(), 
                    addshare: gamma_A_add
                }, 
                gamma_B: KeyInfoWithAddshare 
                { 
                    ui: self.dkgparams.dkgparam_B.as_ref().unwrap().ui.clone().unwrap(), 
                    xi: self.dkgparams.dkgparam_B.as_ref().unwrap().mskshare.clone().unwrap(), 
                    addshare: gamma_B_add
                },  
                gamma_C: KeyInfo 
                { 
                    ui: self.dkgparams.dkgparam_C.as_ref().unwrap().ui.clone().unwrap(), 
                    xi: self.dkgparams.dkgparam_C.as_ref().unwrap().mskshare.clone().unwrap(), 
                },  
                gamma_O: KeyInfo 
                { 
                    ui: self.dkgparams.dkgparam_O.as_ref().unwrap().ui.clone().unwrap(), 
                    xi: self.dkgparams.dkgparam_O.as_ref().unwrap().mskshare.clone().unwrap(), 
                },  
            } 
        }
    }

    /// 密钥刷新，创建 0 的 vss share
    pub fn key_refresh_phase_one(&self,dkgtag: DKGTag) -> NodeToProxyKeyRefreshOneP2PMsg
    {
        println!("{:?} key refresh is starting!",dkgtag);
        info!("{:?} key refresh is starting!",dkgtag);;
        let (vss_scheme, secret_shares) =
        VerifiableSS::share(self.threashold_param.threshold, self.threashold_param.share_counts, &Scalar::<Bls12_381_1>::zero());
        let shares = secret_shares.to_vec();
        let mut share_proof_map:HashMap<u16,ShareProof> = HashMap::new();
        // Encrypt share and make CLDLProof
        for node in self.node_info_vec.as_ref().unwrap()
        { 
            let id = node.id; 
            // share 1~n, vec 0~n-1 
            let share = &shares[id as usize-1 ];
            let g_share = share * self.gpk.as_ref().unwrap().g.clone();
            let (c_share,share_proof) = verifiably_encrypt(&self.group,&hex_to_pk(&node.pk_hex),(&share,&g_share));
            let c_share_hex = ciphertext_to_hex(&c_share);
            let share_proof_hex = cldl_proof_to_hex(&share_proof);
            let share_proof = ShareProof
            {
                c_share_hex:c_share_hex,
                g_share:g_share,
                share_proof_hex:share_proof_hex
            };
            share_proof_map.insert(id, share_proof);
        }
        NodeToProxyKeyRefreshOneP2PMsg
        {
            dkgtag:dkgtag,
            sender:self.id.unwrap(),
            role:self.role.clone(),
            share_proof_map:share_proof_map,
            vss_scheme:vss_scheme,
        }
         
    }
    
    /// 密钥刷新，叠加share到原来的mskshare上形成新的share
    pub fn key_refresh_phase_three(&mut self, msg:ProxyToNodeKeyRefreshPhaseTwoP2PMsg, )-> Result<(), Error>
    {
        let dkgtag = msg.dkgtag.clone();
        // Decrypt CL share
        let group = self.group.clone();
        let x_i = decrypt(&group, &self.clkeys.sk, &hex_to_ciphertext(&msg.c_share_sum_hex));

        // verify coefficient commitment
        // add share to original share
        if msg.vss_scheme_sum.validate_share(&x_i, self.id.unwrap()).is_ok()
        {
            //println!("Sharing phase: vss share x{} is {}",self.id.unwrap(),x_i.to_bigint()); 
            match dkgtag {
                DKGTag::Gamma_A=>{
                    self.dkgparams.dkgparam_A.as_mut().unwrap().mskshare = Some(self.dkgparams.dkgparam_A.as_ref().unwrap().mskshare.clone().unwrap() + x_i);
                    println!("Gamma_A is refreshed!");
                    info!("Gamma_A is refreshed!");
                }
                DKGTag::Gamma_B=>{
                    self.dkgparams.dkgparam_B.as_mut().unwrap().mskshare = Some(self.dkgparams.dkgparam_B.as_ref().unwrap().mskshare.clone().unwrap() + x_i);;
                    println!("Gamma_B is refreshed!");
                    info!("Gamma_B is refreshed!");
                }
                DKGTag::Gamma_O=>{
                    self.dkgparams.dkgparam_O.as_mut().unwrap().mskshare = Some(self.dkgparams.dkgparam_O.as_ref().unwrap().mskshare.clone().unwrap() + x_i);;
                    println!("Gamma_O is refreshed!");
                    info!("Gamma_O is refreshed!");
                }
                DKGTag::Gamma_C=>{
                    self.dkgparams.dkgparam_C.as_mut().unwrap().mskshare = Some(self.dkgparams.dkgparam_C.as_ref().unwrap().mskshare.clone().unwrap() + x_i);;
                    println!("Gamma_C is refreshed!");
                    info!("Gamma_C is refreshed!");
                }
            }
            Ok(
                ()
            )
        }   
        else
        {
            Err(InvalidSS)
        }
    }

}
