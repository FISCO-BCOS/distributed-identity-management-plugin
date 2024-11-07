use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::elliptic::curves::bls12_381::Pair;
use log::{info, warn};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use crate::proxy::Proxy;
use gs_tbk_scheme::messages::user::sign_msg::SignPhaseStartFlag;
use gs_tbk_scheme::messages::proxy::verify_msg::ProxyToNodesVerifyPhaseBroadcastMsg;

impl Proxy
{
    /// 验证用户的签名
    pub fn verify_phase(&self,user_id:u16)->ProxyToNodesVerifyPhaseBroadcastMsg
    {   
        
        ProxyToNodesVerifyPhaseBroadcastMsg
            {
                sender:self.id,
                role:self.role.clone(), 
                user_id:user_id,
            }
    }
}