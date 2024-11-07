use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{Framed, LinesCodec};
use tokio_stream::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::net::SocketAddr;
use std::collections::HashMap;
use log::{error, info, warn};

use crate::user::{User, UserConfig};
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

///p2p发送给代理信道
pub async fn to_proxy (msg : String,add : &String) -> Result<(), anyhow::Error> 
{
    let add : SocketAddr = add.parse()?;
    let mut node_stream = TcpStream::connect(add).await?;
    node_stream.write_all(msg.as_bytes()).await?;
    node_stream.shutdown().await?;
    Ok(())
}

///Join阶段序列化消息
pub fn join_issue_to_gstbk(msg_join : gs_tbk_scheme::messages::user::common_msg::JoinIssueMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgU(gs_tbk_scheme::messages::user::common_msg::GSTBKMsg::JoinIssueMsg(msg_join))).unwrap();
    return msg_str;
}

///sign阶段序列化消息
pub fn sign_to_gstbk(msg_sign : gs_tbk_scheme::messages::user::common_msg::SignMsg) -> String 
{
    let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgU(gs_tbk_scheme::messages::user::common_msg::GSTBKMsg::SignMsg(msg_sign))).unwrap();
    return msg_str;
}

//创建转16进制的user
pub fn get_user_config(user:User) -> UserConfig 
{
    UserConfig 
    { 
        id: user.id,
        name: user.name,
        role: user.role, 
        proxy_addr: user.proxy_addr, 
        user_addr: user.user_addr,
        listen_addr:user.listen_addr, 
        clkeys_hex: cl_keys_to_hex(&user.clkeys), 
        group_hex: clgroup_to_hex(&user.group), 
        usk: user.usk, 
        gpk: user.gpk, 
        tau: user.tau, 
        gsk: user.gsk, 
        ei_info: user.ei_info, 
    }
}