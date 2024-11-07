use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{Framed, LinesCodec};
use tokio_stream::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::net::SocketAddr;
use std::collections::HashMap;
use log::{error, info, warn};

use gs_tbk_scheme::messages::common_msg::GSTBKMsg;
use gs_tbk_scheme::messages::proxy::join_issue_msg::UserInfo;
use gs_tbk_scheme::messages::proxy::setup_msg::NodeInfo;
use gs_tbk_scheme::messages::node::setup_msg::{NodeToProxySetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};


/// 接受并序列化消息
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
    let node_message = match result 
    {
        Ok(v) => v,
        Err(e) => 
        {
            error!("Error deserializing JSON: {:?}", e);
            return Err(Box::new(e));
        }
    };
    return  Ok(node_message);
}

/// 拆分处理各种类型的消息
pub async fn handle_setup_msg(msg : NodeToProxySetupPhaseP2PMsg, msg_vec : &Arc<TokioMutex<Vec<NodeToProxySetupPhaseP2PMsg>>>, msg_num : &Arc<TokioMutex<i32>>) 
{
    let mut locked_msg_vec = msg_vec.lock().await; 
    let mut locked_num = msg_num.lock().await;
    locked_msg_vec.push(msg.clone());
    *locked_num += 1;
}

/// 处理setup阶段node的finish消息
pub async fn handle_setup_tag(msg : NodeSetupPhaseFinishFlag, node_setup_finish_vec : &Arc<TokioMutex<Vec<NodeSetupPhaseFinishFlag>>>, finish_num : &Arc<TokioMutex<i32>>) 
{
    let mut locked_vec = node_setup_finish_vec.lock().await;
    let mut locked_num = finish_num.lock().await;
    locked_vec.push(msg);
    *locked_num += 1;
}

/// 序列化setup阶段的消息
pub fn setup_to_gstbk(msg_setup : gs_tbk_scheme::messages::proxy::common_msg::SetupMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::SetupMsg(msg_setup))).unwrap();
    return msg_str;
}

/// 序列化keygen阶段的消息
pub fn keygen_to_gstbk(msg_keygen : gs_tbk_scheme::messages::proxy::common_msg::KeyGenMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::KeyGenMsg(msg_keygen))).unwrap();
    return msg_str;
}

/// 序列化join阶段的消息
pub fn join_issue_to_gstbk(msg_join : gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::JoinIssueMsg(msg_join))).unwrap();
    return msg_str;
}

/// 序列化revoke阶段的消息
pub fn revoke_to_gstbk (msg_revoke : gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::RevokeMsg(msg_revoke))).unwrap();
    return msg_str;
}

/// 序列化verify阶段的消息
pub fn verify_to_gstbk (msg_verify : gs_tbk_scheme::messages::proxy::common_msg::VerifyMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::VerifyMsg(msg_verify))).unwrap();
    return msg_str;
}

/// 序列化open阶段的消息
pub fn open_to_gstbk (msg_open : gs_tbk_scheme::messages::proxy::common_msg::OpenMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::OpenMsg(msg_open))).unwrap();
    return msg_str;
}

/// 序列化key manage阶段的消息
pub fn key_manage_to_gstbk (msg_key_manage : gs_tbk_scheme::messages::proxy::common_msg::KeyManageMsg) -> String
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::KeyManageMsg(msg_key_manage))).unwrap();
    return msg_str;
}

/// 广播信道
pub async fn broadcast(msg : &String, node_list : &Vec<NodeInfo>) -> Result<(), anyhow::Error> 
{
    for node in node_list 
    {
        let addr : SocketAddr = node.address.parse()?;
        let mut node_stream = TcpStream::connect(addr).await?;
        node_stream.write_all(msg.as_bytes()).await?; 
        node_stream.shutdown().await?;
    }
    Ok(())
}

/// node p2p信道
pub async fn p2p(msg : &String, id : &u16, node_list : &Vec<NodeInfo>) -> Result<(), anyhow::Error> 
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

/// user p2p 信道
pub async fn to_user (msg : &String, addr : &String) -> Result<(), anyhow::Error> 
{
    let add : SocketAddr = addr.parse()?;
    let mut node_stream = TcpStream::connect(add).await?;
    node_stream.write_all(msg.as_bytes()).await?;
    node_stream.shutdown().await?;
    Ok(())
}

/// user 广播信道
pub async fn broadcast_to_user(user_info : &HashMap<u16,UserInfo>,msg : &String) -> Result<(), anyhow::Error> 
{
    for (_ , user) in user_info 
    {
        let add : SocketAddr = user.address.parse()?;
        let mut user_stream = TcpStream::connect(add).await?;
        user_stream.write_all(msg.as_bytes()).await?;
        user_stream.shutdown().await?;
    }
    Ok(())
}

// // 测试密钥恢复和刷新
// let key_recover_flag = ProxyToNodeKeyRocoverPhseStartFlag
// {
//     sender:locked_proxy.id,
//     role:locked_proxy.role.clone()
// };
// let key_recover_flag_str = serde_json::to_string(&&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::KeyManageMsg(KeyManageMsg::ProxyToNodeKeyRocoverPhseStartFlag(key_recover_flag)))).unwrap();
// let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
// match broadcast(key_recover_flag_str, node_list.clone()).await
// {
//     Ok(_) =>{}
//     Err(e) => 
//     {
//         error!("Error: {}, ProxyToNodeKetRocoverPhseStartFlag can not sent ",e);
//         return ;
//     }
// };

// 刷新
// let key_refresh_flag = ProxyToNodeKeyRefreshPhaseStartFlag
// {
//     sender:locked_proxy.id,
//     role:locked_proxy.role.clone(),
//     dkgtag:DKGTag::Gamma_A
// };
// let key_refresh_flag_str = serde_json::to_string(&&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::KeyManageMsg(KeyManageMsg::ProxyToNodeKeyRefreshPhaseStartFlag(key_refresh_flag)))).unwrap();
// let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
// match broadcast(key_refresh_flag_str, node_list.clone()).await
// {
//     Ok(_) =>{}
//     Err(e) => 
//     {
//         error!("Error: {}, ProxyToNodeKetRocoverPhseStartFlag can not sent ",e);
//         return ;
//     }
// };

// //刷新完再恢复一下
// let key_recover_flag = ProxyToNodeKeyRocoverPhseStartFlag
// {
//     sender:locked_proxy.id,
//     role:locked_proxy.role.clone()
// };
// let key_recover_flag_str = serde_json::to_string(&&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::KeyManageMsg(KeyManageMsg::ProxyToNodeKeyRocoverPhseStartFlag(key_recover_flag)))).unwrap();
// let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
// match broadcast(key_recover_flag_str, node_list.clone()).await
// {
//     Ok(_) =>{}
//     Err(e) => 
//     {
//         error!("Error: {}, ProxyToNodeKetRocoverPhseStartFlag can not sent ",e);
//         return ;
//     }
// };
