use std::collections::HashMap;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::BigInt;
use log::info;
use sha2::{Sha256, Digest}; 

 
use crate::Error::{self, InvalidKey, InvalidSS};
use class_group::primitives::cl_dl_public_setup::*;
use gs_tbk_scheme::messages::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg,ShareProof,NodeToProxyKeyGenPhaseTwoP2PMsg,ZkpProof,NodeToProxyKeyGenPhaseFiveP2PMsg};
use gs_tbk_scheme::messages::proxy::keygen_msg::{ProxyKeyGenPhaseOneBroadcastMsg,ProxyToNodeKeyGenPhaseThreeP2PMsg,ProxyToNodesKeyGenPhasefiveBroadcastMsg};
use gs_tbk_scheme::params::{Gpk,DKGTag,ciphertext_to_hex,cldl_proof_to_hex,hex_to_pk,hex_to_ciphertext};
use crate::node::{Node,DKGParam};

impl Node { 
    /// 选择对应密钥的dkg参数
    pub fn choose_dkgparam(&self, dkgtag:&DKGTag)-> &DKGParam
    {
        let dkgparam = match dkgtag 
        {
            DKGTag::Gamma_A=>
            {
                self.dkgparams.dkgparam_A.as_ref().unwrap()
            }
            DKGTag::Gamma_B=>
            {
                self.dkgparams.dkgparam_B.as_ref().unwrap()
            }
            DKGTag::Gamma_O=>
            {
                self.dkgparams.dkgparam_O.as_ref().unwrap()
            }
            DKGTag::Gamma_C=>
            {
                self.dkgparams.dkgparam_C.as_ref().unwrap()
            }
        };
        dkgparam
    }
    
    /// 自选(n,n) share 的私钥碎片，计算哈希承诺并广播
    pub fn keygen_phase_one(&mut self, dkgtag:DKGTag,msg:ProxyKeyGenPhaseOneBroadcastMsg) -> NodeKeyGenPhaseOneBroadcastMsg
    {
        info!("Key {:?} is generating!",dkgtag);
        let gpk = Gpk
        {
            f:msg.f,
            g:msg.g,
            g_sim:msg.g_sim,
            g_hat:msg.g_hat,
            g2:msg.g_2,
            h0:msg.h_0,
            h1:msg.h_1,
            h2:msg.h_2,
            vk_A:None,
            vk_B:None,
            g1:None  
        };
        self.gpk = Some(gpk);
        self.participants = Some(msg.participants);
        let ui = Scalar::<Bls12_381_1>::random();
        let yi = &self.gpk.as_ref().unwrap().g * &ui;//g_ui
        match dkgtag  
        {
            DKGTag::Gamma_A=>{ 
                self.dkgparams.dkgparam_A.as_mut().unwrap().ui = Some(ui);
                self.dkgparams.dkgparam_A.as_mut().unwrap().yi = Some(yi.clone());
            }
            DKGTag::Gamma_B=>{
                self.dkgparams.dkgparam_B.as_mut().unwrap().ui = Some(ui);
                self.dkgparams.dkgparam_B.as_mut().unwrap().yi = Some(yi.clone());
            }
            DKGTag::Gamma_O=>{
                self.dkgparams.dkgparam_O.as_mut().unwrap().ui = Some(ui);
                self.dkgparams.dkgparam_O.as_mut().unwrap().yi = Some(yi.clone());
            }
            DKGTag::Gamma_C=>{
                self.dkgparams.dkgparam_C.as_mut().unwrap().ui = Some(ui);
                self.dkgparams.dkgparam_C.as_mut().unwrap().yi = Some(yi.clone());
            }
        }
        let blind_factor = BigInt::sample(256);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(yi.clone().to_bytes(true).as_ref()),
            &blind_factor,
        );
        
        NodeKeyGenPhaseOneBroadcastMsg
        {
            dkgtag:dkgtag,
            sender:self.id.unwrap(),
            role:self.role.clone(),
            blind_factor:blind_factor,
            yi:yi,
            com:com,
        }
       
    }


    /// 验证哈希承诺，然后进行feldman vss，发送share 和 相关系数承诺   
    pub fn keygen_phase_two(&mut self, msg_vec:&Vec<NodeKeyGenPhaseOneBroadcastMsg>)-> Result<NodeToProxyKeyGenPhaseTwoP2PMsg, Error>
    {
        //verify length
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        let dkgtag = msg_vec[0].dkgtag.clone();
        //Verify all Hashcommitment
        let all_com_verify_tag = (0..msg_vec.len()).all( |i| {
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(&BigInt::from_bytes(msg_vec[i].yi.to_bytes(true).as_ref()), &msg_vec[i].blind_factor )== msg_vec[i].com
        }); 
        if all_com_verify_tag
        {
            // Merge and save y,y_i_map
            let mut yi_map:HashMap<u16, Point<Bls12_381_1>> = HashMap::new();
            for msg in msg_vec
            {
                yi_map.insert(msg.sender, msg.yi.clone());
            }
            let y:Point<Bls12_381_1> = msg_vec.iter().map(|msg| &msg.yi).sum();
            match dkgtag  
            {
                DKGTag::Gamma_A=>{
                    self.dkgparams.dkgparam_A.as_mut().unwrap().yi_map = Some(yi_map);
                    self.dkgparams.dkgparam_A.as_mut().unwrap().y = Some(y);
                }
                DKGTag::Gamma_B=>{
                    self.dkgparams.dkgparam_B.as_mut().unwrap().yi_map = Some(yi_map);
                    self.dkgparams.dkgparam_B.as_mut().unwrap().y = Some(y);
                }
                DKGTag::Gamma_O=>{
                    self.dkgparams.dkgparam_O.as_mut().unwrap().yi_map = Some(yi_map);
                    self.dkgparams.dkgparam_O.as_mut().unwrap().y = Some(y);
                }
                DKGTag::Gamma_C=>{
                    self.dkgparams.dkgparam_C.as_mut().unwrap().yi_map = Some(yi_map);
                    self.dkgparams.dkgparam_C.as_mut().unwrap().y = Some(y);
                }
            }
            
            let dkgparam = self.choose_dkgparam(&dkgtag);
            let (vss_scheme, secret_shares) =
            VerifiableSS::share(self.threashold_param.threshold, self.threashold_param.share_counts, &dkgparam.ui.as_ref().unwrap());
            let shares = secret_shares.to_vec();
            
            let mut share_proof_map:HashMap<u16,ShareProof> = HashMap::new();
            
            for node in self.node_info_vec.as_ref().unwrap()
            { 
                let id = node.id; 
                // share 1~n, vec 0~n-1
                let share = &shares[id as usize-1 ];
                let g_share = share * &self.gpk.as_ref().unwrap().g;
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
            Ok
            (
                NodeToProxyKeyGenPhaseTwoP2PMsg
                {
                    dkgtag:dkgtag,
                    sender:self.id.unwrap(),
                    role:self.role.clone(),
                    share_proof_map:share_proof_map,
                    vss_scheme:vss_scheme,
                }
            )
        } 
        else
        {
            Err(Error::InvalidCom)
        }
    }

    /// 解密share，然后进行系数承诺验证
    pub fn keygen_phase_four(&mut self, msg:ProxyToNodeKeyGenPhaseThreeP2PMsg, )->Result<(), Error>
    {
        let dkgtag = msg.dkgtag.clone();
        // Decrypt CL share
        let group = self.group.clone();
        let x_i = decrypt(&group, &self.clkeys.sk, &hex_to_ciphertext(&msg.c_share_sum_hex));
        // verify coefficient commitment
        if msg.vss_scheme_sum.validate_share(&x_i, self.id.unwrap()).is_ok()
        {
            //println!("Sharing phase:DKGTag is {:?} vss share x{} is {}",dkgtag,self.id.unwrap(),x_i.to_bigint()); 
            match dkgtag {
                DKGTag::Gamma_A=>{
                    self.dkgparams.dkgparam_A.as_mut().unwrap().mskshare = Some(x_i);
                    info!("Gamma_A is generated!");
                }
                DKGTag::Gamma_B=>{
                    self.dkgparams.dkgparam_B.as_mut().unwrap().mskshare = Some(x_i);
                    info!("Gamma_B is generated!");
                }
                DKGTag::Gamma_O=>{
                    self.dkgparams.dkgparam_O.as_mut().unwrap().mskshare = Some(x_i);
                    info!("Gamma_O is generated!");
                }
                DKGTag::Gamma_C=>{
                    self.dkgparams.dkgparam_C.as_mut().unwrap().mskshare = Some(x_i);
                    info!("Gamma_C is generated!");
                }
            }
            Ok
            (
                ()
            )
        }   
        else
        {
            Err(InvalidSS)
        }
            
    }

    /// 作零知识证明，发送proof
    pub fn keygen_phase_five(&self) -> NodeToProxyKeyGenPhaseFiveP2PMsg
    {
        let gpk = self.gpk.as_ref().unwrap();
        let g_hat_gamma_A_i = &gpk.g_hat * Scalar::<Bls12_381_2>::from_bigint(&self.dkgparams.dkgparam_A.as_ref().unwrap().ui.as_ref().unwrap().to_bigint());
        let g_hat_gamma_B_i = &gpk.g_hat * Scalar::<Bls12_381_2>::from_bigint(&self.dkgparams.dkgparam_B.as_ref().unwrap().ui.as_ref().unwrap().to_bigint());
        let f_gamma_O_i = &gpk.f * self.dkgparams.dkgparam_O.as_ref().unwrap().ui.as_ref().unwrap();

        let t_rand = Scalar::<Bls12_381_1>::random();
        let g_t = &gpk.g * &t_rand;
        let g_hat_t = &gpk.g_hat * Scalar::<Bls12_381_2>::from_bigint(&t_rand.to_bigint());
        let f_t = &gpk.f * &t_rand;

        // challenge
        let e = Sha256::new() 
        .chain_point(&gpk.g)
        .chain_point(&gpk.g_hat)
        .chain_point(&gpk.f)
        .chain_point(&g_hat_gamma_A_i)
        .chain_point(&g_hat_gamma_B_i)
        .chain_point(&f_gamma_O_i)
        .chain_point(&self.dkgparams.dkgparam_A.as_ref().unwrap().yi_map.as_ref().unwrap().get(&self.id.unwrap().clone()).unwrap())
        .chain_point(&self.dkgparams.dkgparam_B.as_ref().unwrap().yi_map.as_ref().unwrap().get(&self.id.unwrap().clone()).unwrap())
        .chain_point(&self.dkgparams.dkgparam_O.as_ref().unwrap().yi_map.as_ref().unwrap().get(&self.id.unwrap().clone()).unwrap())
        .chain_point(&g_t)
        .chain_point(&g_hat_t)
        .chain_point(&f_t)
        .result_scalar();

        // challenge response
        let z_gamma_A_i = &t_rand + &e * self.dkgparams.dkgparam_A.as_ref().unwrap().ui.as_ref().unwrap();
        let z_gamma_B_i = &t_rand + &e * self.dkgparams.dkgparam_B.as_ref().unwrap().ui.as_ref().unwrap();
        let z_gamma_O_i = &t_rand + &e * self.dkgparams.dkgparam_O.as_ref().unwrap().ui.as_ref().unwrap();

        NodeToProxyKeyGenPhaseFiveP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            zkp_proof:ZkpProof 
            { 
                z_gamma_A_i: z_gamma_A_i, 
                z_gamma_B_i: z_gamma_B_i, 
                z_gamma_O_i: z_gamma_O_i,
                g_gamma_A_i: self.dkgparams.dkgparam_A.as_ref().unwrap().yi.as_ref().unwrap().clone(),
                g_gamma_B_i: self.dkgparams.dkgparam_B.as_ref().unwrap().yi.as_ref().unwrap().clone(),
                g_gamma_O_i: self.dkgparams.dkgparam_O.as_ref().unwrap().yi.as_ref().unwrap().clone(), 
                e: e, 
                g_t: g_t, 
                g_hat_t: g_hat_t, 
                f_t: f_t 
            },
            vk_A_i:g_hat_gamma_A_i,
            vk_B_i:g_hat_gamma_B_i,
            g1_i:f_gamma_O_i
        }
    }
    
    /// 接收然后组合出完整的GPK
    pub fn keygen_phase_six(&mut self,msg:ProxyToNodesKeyGenPhasefiveBroadcastMsg)
    {
        self.gpk.as_mut().unwrap().vk_A = Some(msg.vk_A);
        self.gpk.as_mut().unwrap().vk_B = Some(msg.vk_B);
        self.gpk.as_mut().unwrap().g1 = Some(msg.g1);
        info!("Keygen phase is finished!");
        println!("Keygen phase is finished!");
    }

}

#[test]
fn test(){
    let group = CLGroup::new();
    let (sk,pk) = group.keygen();
    let a = Scalar::<Bls12_381_1>::random();
    let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
    let g_a = &g * &a;
    //let (c,proof) = CLGroup::verifiably_encrypt(&group, &pk, (&a,&g_a));
    let (c,_) = encrypt(&group, &pk, &a);
    println!("{:?}",c);
}

#[test]
pub fn test1()
{
   
}



