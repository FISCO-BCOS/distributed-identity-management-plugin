use std::collections::HashMap;


use curv::{elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar, Generator}};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use serde::{Deserialize, Serialize};


use gs_tbk_scheme::params::{ThreasholdParam,Gpk,CLKeys,Reg,EiInfo,RL, CLKeysHex, CLGroupHex};
use gs_tbk_scheme::messages::proxy::setup_msg::NodeInfo;
use gs_tbk_scheme::messages::proxy::join_issue_msg::UserInfo;
use gs_tbk_scheme::tree::Tree;
use class_group::primitives::cl_dl_public_setup::*;

 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node
{
    pub id: Option<u16>,
    pub role:String,
    pub node_addr: String, 
    pub listen_addr:String,
    pub proxy_address: String,
    pub threashold_param: ThreasholdParam,
    pub tree:Option<Tree>,
    pub group:CLGroup,
    pub clkeys:CLKeys,
    pub dkgparams: DKGParams, 
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub user_info_map:Option<HashMap<u16,UserInfo>>,
    pub participants: Option<Vec<u16>>,
    pub reg:Option<HashMap<u16,Reg>>,
    // pub ei_info:Option<EiInfo>,
     pub rl:Option<RL>
 
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig
{
    pub id: Option<u16>,
    pub role:String,
    pub node_addr: String, 
    pub listen_addr:String,
    pub proxy_address: String,
    pub threashold_param: ThreasholdParam,
    pub tree:Option<Tree>,
    pub group_hex:CLGroupHex,
    pub clkeys_hex:CLKeysHex,
    pub dkgparams: DKGParams, 
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub user_info_map:Option<HashMap<u16,UserInfo>>,
    pub participants: Option<Vec<u16>>, 
    pub reg:Option<HashMap<u16,Reg>>,
    // pub ei_info:Option<EiInfo>,
     pub rl:Option<RL>

}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DKGParams
{
    pub dkgparam_A:Option<DKGParam>,
    pub dkgparam_B:Option<DKGParam>,
    pub dkgparam_O:Option<DKGParam>,
    pub dkgparam_C:Option<DKGParam>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DKGParam
{
    pub ui:Option<Scalar<Bls12_381_1>>, 
    pub yi:Option<Point<Bls12_381_1>>,
    pub yi_map:Option<HashMap<u16, Point<Bls12_381_1>>>,
    pub y:Option<Point<Bls12_381_1>>,
    pub mskshare: Option<Scalar<Bls12_381_1>>,// x_i
    pub addshare:Option<Scalar<Bls12_381_1>>,// x_i * li
    // pub mtaparams_map:Option<HashMap<usize,MtaParams>>
}


