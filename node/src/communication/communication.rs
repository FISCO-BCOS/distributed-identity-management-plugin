use gs_tbk_scheme::messages::proxy::setup_msg::NodeInfo;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{Framed, LinesCodec};
use tokio_stream::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::net::SocketAddr;
use std::collections::HashMap;
use log::{error, info, warn};

use crate::node::{Node, NodeConfig};
use gs_tbk_scheme::messages::common_msg::GSTBKMsg;
use gs_tbk_scheme::params::{clgroup_to_hex,cl_keys_to_hex};

///接收并序列化消息
pub async fn get_message(mut framed:Framed<TcpStream,LinesCodec>) -> Result<GSTBKMsg, Box<dyn std::error::Error>>
{
    let message = match framed.next().await 
    {
        Some(Ok(m)) => m,
        //坏了传不进来
        Some(Err(e)) => 
        {
            error!("Failed to get from framed: {:?}",e);
            return Err(Box::new(e));
        }
        None => 
        {
            error!("Failed to get a message.");
            return Err("Failed to get a message.".into());
        }
    };
    let result: Result<GSTBKMsg,_> =  serde_json::from_str(&message);
    let msg = match result 
    {
        Ok(v) => v,
        Err(e) => 
        {
            error!("Error deserializing JSON: {:?}", e);
            return Err(Box::new(e));
        }
    };
    return  Ok(msg);
}

/// 序列化setup阶段的消息
pub fn setup_to_gstbk(msg_setup : gs_tbk_scheme::messages::node::common_msg::SetupMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::SetupMsg(msg_setup))).unwrap();
    return msg_str;
}

///Keygen阶段序列化消息
pub fn keygen_to_gstbk(msg_keygen : gs_tbk_scheme::messages::node::common_msg::KeyGenMsg)->String
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyGenMsg(msg_keygen))).unwrap();
    return msg_str;
}

///Join阶段序列化消息
pub fn join_issue_to_gstbk(msg_join : gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::JoinIssueMsg(msg_join))).unwrap();
    return msg_str;
}

///Revoke阶段序列化消息
pub fn revoke_to_gstbk (msg_revoke : gs_tbk_scheme::messages::node::common_msg::RevokeMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::RevokeMsg(msg_revoke))).unwrap();
    return msg_str;
}

///Open阶段序列化消息
pub fn open_to_gstbk (msg_open : gs_tbk_scheme::messages::node::common_msg::OpenMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::OpenMsg(msg_open))).unwrap();
    return msg_str;
}

///KeyManage阶段序列化消息
pub fn key_manage_to_gstbk (msg_key_manage : gs_tbk_scheme::messages::node::common_msg::KeyManageMsg) -> String
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyManageMsg(msg_key_manage))).unwrap();
    return msg_str;
}

///创建转为16进制的node
pub fn get_node_config (node : Node) -> NodeConfig 
{
    NodeConfig 
    { 
        id: node.id, 
        role: node.role, 
        node_addr: node.node_addr, 
        listen_addr:node.listen_addr,
        proxy_address: node.proxy_address, 
        threashold_param: node.threashold_param, 
        tree: node.tree, 
        group_hex: clgroup_to_hex(&node.group), 
        clkeys_hex: cl_keys_to_hex(&node.clkeys), 
        dkgparams: node.dkgparams, 
        gpk: node.gpk, 
        node_info_vec: node.node_info_vec, 
        user_info_map: node.user_info_map, 
        participants: node.participants, 
        reg: node.reg, 
        //ei_info: node.ei_info, 
         rl: node.rl, 
    }
}

///p2p信道
pub async fn p2p(msg : &String,str_add : &String) -> Result<(), anyhow::Error> 
{
    let add : SocketAddr = str_add.parse()?;
    let mut tcp_stream = TcpStream::connect(add).await?;
    tcp_stream.write_all(msg.as_bytes()).await?; 
    tcp_stream.shutdown().await?;
    Ok(())
}

///node之间的p2p信到
pub async fn to_node(msg : &String,id : &u16,node_list : &Vec<NodeInfo>) -> Result<(), anyhow::Error> 
{
    if let Some(node) = node_list.iter().find(|&node_info| &node_info.id == id) 
    {
        let add : SocketAddr = node.address.parse()?;
        let mut node_stream = TcpStream::connect(add).await?;
        node_stream.write_all(msg.as_bytes()).await?;
        node_stream.shutdown().await?;
    }
    else 
    {
        warn!("Nodelist with id {} not found.", id);
    }
    Ok(())
}

///广播信道
pub async fn broadcast(msg : &String,node_list : &Vec<NodeInfo>,node_id : &u16) -> Result<(), anyhow::Error> 
{
    for node in node_list 
    {
            if node_id == &node.id  
            {
                continue;
            }
            else 
            {
                let add : SocketAddr = node.address.parse()?;
                let mut tcp_stream = TcpStream::connect(add).await?;
                tcp_stream.write_all(msg.as_bytes()).await?; 
                tcp_stream.shutdown().await?;
            }    
    }
    Ok(())
}
