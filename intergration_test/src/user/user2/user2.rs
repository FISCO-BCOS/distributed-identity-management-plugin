use std::env;
use std::net::SocketAddr;
use log::{info,error,warn};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncWriteExt;
//use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Framed, LinesCodec};
use tokio_stream::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

use user::communication::communication::*;
use user::user::{User, UserConfig};
use gs_tbk_scheme::messages::common_msg::GSTBKMsg;
use gs_tbk_scheme::messages::user::revoke_msg::RevokePhaseStartFlag;
use gs_tbk_scheme::params::{cl_keys_to_hex, clgroup_to_hex,UserSignature};
use user::config::config::Config;


#[tokio::main] 
pub async fn main () -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/user/user2/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    let config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/user/user2/config/config_file/user_config.json";
    //println!("path is {}",config_path);
    let config:Config = serde_json::from_str(&Config::load_config(&config_path)).unwrap();
    let user_normal = User::init(config);
    //创建user的共享变量
    let shared_user = Arc::new(TokioMutex::new(user_normal.clone()));
    //开启user的监听窗口
    let add : SocketAddr = user_normal.listen_addr.parse()?;
    let listener = TcpListener::bind(add).await?;
    info!("User is listening on {}",user_normal.user_addr);
    //发送join消息，代码，启动
    let utp_join_start_msg = user_normal.join_issue_phase_one();
    let utp_join_start_join = gs_tbk_scheme::messages::user::common_msg::JoinIssueMsg::UserJoinIssuePhaseStartFlag(utp_join_start_msg);
    let utp_join_start_str = join_issue_to_gstbk(utp_join_start_join);
    match to_proxy(utp_join_start_str, &user_normal.proxy_addr).await
    {
        Ok(_) => 
        {
            info!("UserJoinIssuePhaseStartFlag have sent");
        }
        Err(e) => 
        {
            error!("Error: {}, UserJoinIssuePhaseStartFlag can not sent ",e);
            drop(e);
        }
    };

    //循环接收消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await 
    {
        //拷贝共享变量
        let user_clone = shared_user.clone();
        tokio::spawn(async move 
            {
            //接收并拆分出消息
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get nodemessage: {:?}",e);
                    return ;
                }
            };
            //拷贝主要共享变量
            let user = user_clone.clone();
            match message {
                GSTBKMsg::GSTBKMsgP(proxy_msg) => 
                {
                    match proxy_msg 
                    {
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::JoinIssueMsg(join_msg) => 
                        {
                            match join_msg 
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToUserJoinIssuePhaseOneP2PMsg(msg) => 
                                {
                                    info!("From id : 0,Role : Proxy Get ProxyToUserJoinIssuePhaseOneP2PMsg");
                                    let mut locked_user = user.lock().await;
                                    let join_phase_two_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::user::common_msg::JoinIssueMsg::UserToProxyJoinIssuePhaseTwoP2PMsg(locked_user.join_issue_phase_two(msg)));
                                    match to_proxy(join_phase_two_msg_str, &locked_user.proxy_addr).await
                                    {
                                        Ok(_) => 
                                        {
                                            info!("UserToProxyJoinIssuePhaseTwoP2PMsg has sent");
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {}, UserToProxyJoinIssuePhaseTwoP2PMsg can not sent ",e);
                                            drop(e);
                                        }
                                    };
                                }
                                
                                gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToUserJoinIssuePhaseThreeP2PMsg(msg) => 
                                {
                                    info!("From id : 0,Role : Proxy Get ProxyToUserJoinIssuePhaseThreeP2PMsg");
                                    let mut locked_user = user.lock().await;
                                    locked_user.join_issue_phase_three(msg);
                                    
                                    // 写到文件里去
                                    let user_config = get_user_config((*locked_user).clone());
                                    let user_str = serde_json::to_string(&user_config).unwrap();
                                    let mut user_path = std::env::current_dir().unwrap();
                                    let path  = "src/user/user2/info/join.json";
                                    user_path.push(path);
                                    std::fs::write(user_path, user_str).unwrap();

                                    //模拟发出revoke申请
                                    let revoke_flag = RevokePhaseStartFlag
                                    {
                                        sender:locked_user.id.unwrap(),
                                        role:locked_user.role.clone()
                                    };
                                    let revoke_flag_msg = gs_tbk_scheme::messages::user::common_msg::RevokeMsg::RevokePhaseStartFlag(revoke_flag);
                                    let revoke_flag_msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgU(gs_tbk_scheme::messages::user::common_msg::GSTBKMsg::RevokeMsg(revoke_flag_msg))).unwrap();
                                    match to_proxy(revoke_flag_msg_str, &locked_user.proxy_addr).await
                                    {
                                        Ok(_) => 
                                        {
                                            info!("RevokePhaseStartFlag has sent");
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {}, RevokePhaseStartFlag can not sent ",e);
                                            drop(e);
                                        }
                                    };
                                }
                                _ => {}
                            }
                        }
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::RevokeMsg(revoke_msg) => 
                        {
                            match revoke_msg 
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg::ProxyToUserRevokePhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0, Role : Proxy Get ProxyToUserRevokePhaseBroadcastMsg");
                                    let mut locked_user = user.lock().await;
                                    locked_user.revoke_phase(&msg);
                                    
                                    let m = "rolldragon".to_string();// 签名信息
                                    let sign_phase_msg = locked_user.sign(m);
                                    let sign_phase_msg_str = sign_to_gstbk(gs_tbk_scheme::messages::user::common_msg::SignMsg::SignPhaseStartFlag(sign_phase_msg));
                                    match to_proxy(sign_phase_msg_str, &locked_user.proxy_addr).await
                                    {
                                        Ok(_) => {
                                            info!("UserToProxySignPhaseP2PMsg has sent");
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {}, UserToProxySignPhaseP2PMsg can not sent ",e);
                                            drop(e);
                                        }
                                    };
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        });
    }
    Ok(())
}


#[test]
fn test() 
{
    match main()  
    { 
        Ok(_) =>  
        {
            println!("Ok");   
        }
        Err(_) =>  
        {      
            println!("No");
        } 
    };
} 