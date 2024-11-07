use std::net::SocketAddrV4;
use log::info;
use serde::{Deserialize, Serialize};
use class_group::primitives::cl_dl_public_setup::*;
use curv::BigInt;
use curv::arithmetic::traits::*;

use crate::config::config::Config;
use crate::node::{Node,DKGParams,DKGParam};
use gs_tbk_scheme::messages::proxy::setup_msg::{ProxySetupPhaseBroadcastMsg,ProxySetupPhaseFinishFlag};
use gs_tbk_scheme::messages::node::setup_msg::{NodeToProxySetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};
use gs_tbk_scheme::params::{CLKeys,pk_to_hex};

impl Node{
    /// 初始化自身信息，加载配置，生成cl密钥对等
    pub fn init(gs_tbk_config:Config) -> Self
    {
        let group = CLGroup::new();
        // Initialize Node Info 
        let (sk,pk) = group.keygen();
        let clkeys = CLKeys{sk:sk,pk:pk};
        Self
        {  
            id:None,
            role:"Group Manager Node".to_string(),
            node_addr:gs_tbk_config.node_addr,
            listen_addr:gs_tbk_config.listen_addr,
            proxy_address:gs_tbk_config.proxy_addr,
            threashold_param:gs_tbk_config.threshold_params,
            tree:None, 
            group:group,
            clkeys:clkeys,
            dkgparams:DKGParams
            { 
                // dkgparam_A:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None,mtaparams_map:None}),
                // dkgparam_B:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None,mtaparams_map:None}),
                // dkgparam_O:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None,mtaparams_map:None}),
                // dkgparam_C:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None,mtaparams_map:None})
                dkgparam_A:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None}),
                dkgparam_B:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None}),
                dkgparam_O:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None}),
                dkgparam_C:Some(DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None})
            },
            gpk:None,
            node_info_vec:None,
            user_info_map:None,
            participants:None,
            reg:None,
            // ei_info:None,
             rl:None
        }
        
    }

    /// 发送自己的公钥和地址给代理
    pub fn setup_phase_one(&self)->NodeToProxySetupPhaseP2PMsg
    {
        info!("Setup phase is starting!");
        NodeToProxySetupPhaseP2PMsg
        {
            role:self.role.clone(),
            pk_hex:pk_to_hex(&self.clkeys.pk.clone()),
            address:self.node_addr.clone()
        }

    }

    /// 存储所有管理员的基本信息，公钥，id，地址等等
    pub fn setup_phase_two(&mut self, msg:ProxySetupPhaseBroadcastMsg)-> NodeSetupPhaseFinishFlag
    {
        for node in msg.node_info_vec.iter()
        {
            if node.address == self.node_addr
            {
                self.id = Some(node.id);
            }
        }
        self.node_info_vec = Some(msg.node_info_vec);
        self.tree = Some(serde_json::from_str(&msg.tree).unwrap());
        NodeSetupPhaseFinishFlag 
        { 
            sender: self.id.unwrap(), 
            role:self.role.clone(),
        }
    }

    pub fn setup_phase_three(&self,flag:ProxySetupPhaseFinishFlag)
    {
        info!("Setup phase is finished!")
    }
 
}
  




#[test]
fn test()
{
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/config/config_files/gs_tbk_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let node = Node::init(gs_tbk_config);
    //println!("{:?}",node);
}