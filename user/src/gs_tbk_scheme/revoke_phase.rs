use std::collections::HashMap;
use curv::{elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar}, cryptographic_primitives::hashing::DigestExt};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use crate::user::User;
use gs_tbk_scheme::messages::user::revoke_msg::RevokePhaseStartFlag;
use gs_tbk_scheme::messages::proxy::revoke_msg::ProxyToUserRevokePhaseBroadcastMsg;

impl User
{
    pub fn revoke_phase_start_flag(&self) -> RevokePhaseStartFlag
    {
        RevokePhaseStartFlag
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
        }
    }

    pub fn revoke_phase(&mut self,msg:&ProxyToUserRevokePhaseBroadcastMsg)
    {
        self.ei_info = Some(msg.ei_info.clone());
    } 
}
