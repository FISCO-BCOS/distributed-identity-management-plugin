use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use curv::elliptic::curves::{Bls12_381_1, Point, Scalar};

use gs_tbk_scheme::{params::ThreasholdParam, messages::proxy::setup_msg::NodeInfo};
use gs_tbk_scheme::messages::proxy::join_issue_msg::UserInfo;
use gs_tbk_scheme::messages::proxy::revoke_msg::RevokeInfo;
use gs_tbk_scheme::params::{Gpk,Reg,EiInfo,RL};
use gs_tbk_scheme::tree::{TreeNode,Tree};
use class_group::primitives::cl_dl_public_setup::*;



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proxy 
{
    pub id: u16,  
    pub role:String,
    pub group:CLGroup, 
    pub address: String, 
    pub tree:Tree, 
    pub threashold_param: ThreasholdParam,
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub user_info_map:Option<HashMap<u16,UserInfo>>,
    pub participants: Option<Vec<u16>>,
    pub revoke_info:Option<RevokeInfo>,
    pub ei_info:Option<EiInfo>,
     pub rl:Option<RL>
}



  