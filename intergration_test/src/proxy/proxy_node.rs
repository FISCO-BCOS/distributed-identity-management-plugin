use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{TcpListener};
use tokio_util::codec::{Framed, LinesCodec};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::thread::sleep;
use std::time::Duration;
use std::env;
use log::{error, info, warn};

use proxy::communication::communication::*;
use gs_tbk_scheme::messages::proxy::common_msg::{SetupMsg, KeyGenMsg,KeyManageMsg};
// use gs_tbk_scheme::messages::node::common_msg::KeyManageMsg;
use gs_tbk_scheme::params::{DKGTag,RevokePhaseSignSharedMessageType,JoinPhaseRevokeSharedMessageType};
use proxy::proxy::Proxy;
use proxy::config::config::Config;
use gs_tbk_scheme::messages::node::setup_msg::{NodeToProxySetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};
use gs_tbk_scheme::messages::node::keygen_msg::{NodeToProxyKeyGenPhaseTwoP2PMsg,NodeToProxyKeyGenPhaseFiveP2PMsg};
use gs_tbk_scheme::messages::node::join_issue_msg::{NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg,NodeToProxyJoinIssuePhaseThreeP2PMsg,NodeToProxyJoinIssuePhaseFourP2PMsg,NodeToProxyJoinIssuePhaseFlag};
use gs_tbk_scheme::messages::node::revoke_msg::NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg;
use gs_tbk_scheme::messages::node::open_msg::{NodeToProxyOpenPhaseOneP2PMsg,NodeToProxyOpenPhaseTwoP2PMsg};
use gs_tbk_scheme::messages::common_msg::{GSTBKMsg};
use gs_tbk_scheme::messages::node::key_manage_msg::{NodeToProxyKeyRecoverP2PMsg,NodeToProxyKeyRefreshOneP2PMsg};
use gs_tbk_scheme::messages::user::revoke_msg::RevokePhaseStartFlag;
use gs_tbk_scheme::messages::user::sign_msg::SignPhaseStartFlag;
use gs_tbk_scheme::messages::proxy::key_manage_msg::{ProxyToNodeKeyRocoverPhaseStartFlag,ProxyToNodeKeyRefreshPhaseStartFlag};
use gs_tbk_scheme::messages::proxy::join_issue_msg::NodeUserJoinRevokeSharedMessage;
use gs_tbk_scheme::messages::proxy::revoke_msg::NodeUserRevokeSignSharedMessage;



#[tokio::main]
pub async fn main () -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/proxy/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    // 初始化
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/proxy/config/config_file/proxy_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let proxy = Proxy::init(gs_tbk_config);

    // 创建setup阶段的一些共享变量
    let shared_node_setup_p2p_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxySetupPhaseP2PMsg>::new()));
    let setup_msg_num = Arc::new(TokioMutex::new(0));
    let setup_finish_num = Arc::new(TokioMutex::new(0));
    let shared_node_setup_finish_vec = Arc::new(TokioMutex::new(Vec::<NodeSetupPhaseFinishFlag>::new()));
    
    // 创建KeyGen阶段的共享变量
    let shared_keygen_phase_two_msg_A_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyGenPhaseTwoP2PMsg>::new()));
    let shared_keygen_phase_two_msg_B_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyGenPhaseTwoP2PMsg>::new()));
    let shared_keygen_phase_two_msg_C_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyGenPhaseTwoP2PMsg>::new()));
    let shared_keygen_phase_two_msg_O_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyGenPhaseTwoP2PMsg>::new()));
    let shared_keygen_phase_five_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyGenPhaseFiveP2PMsg>::new()));
    
    // 创建Join阶段的共享变量
    let user_join_msg_num = Arc::new(TokioMutex::new(0));
    let mta_finish_msg_vec_map:HashMap<u16,Vec<NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg>> = HashMap::new();
    let shared_mta_finish_msg_vec_map = Arc::new(TokioMutex::new(mta_finish_msg_vec_map));
    let join_phase_three_msg_vec_map:HashMap<u16,Vec<NodeToProxyJoinIssuePhaseThreeP2PMsg>> = HashMap::new();
    let shared_join_phase_three_msg_vec_map = Arc::new(TokioMutex::new(join_phase_three_msg_vec_map));
    let join_phase_four_msg_vec_map:HashMap<u16,Vec<NodeToProxyJoinIssuePhaseFourP2PMsg>> = HashMap::new();
    let shared_join_phase_four_msg_vec_map = Arc::new(TokioMutex::new(join_phase_four_msg_vec_map));
    let shared_join_shared_message = Arc::new(TokioMutex::new(NodeUserJoinRevokeSharedMessage{shared_message_map:HashMap::new()}));

    // 创建Revoke阶段的共享变量
    let revoke_mta_finial_msg_map:HashMap<u16, Vec<NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg>> = HashMap::new();
    let shared_revoke_mta_finial_msg_map = Arc::new(TokioMutex::new(revoke_mta_finial_msg_map));
    // let shared_revoke_flag_vec = Arc::new(TokioMutex::new(Vec::<RevokePhaseStartFlag>::new()));
    let shared_revoke_shared_message = Arc::new(TokioMutex::new(NodeUserRevokeSignSharedMessage{shared_message_map:HashMap::new()}));

    // 创建open阶段的共享变量
    let open_phase_one_msg_vec_map:HashMap<u16,Vec<NodeToProxyOpenPhaseOneP2PMsg>> = HashMap::new(); 
    let shared_open_phase_one_msg_vec_map = Arc::new(TokioMutex::new(open_phase_one_msg_vec_map)); 
    let open_phase_two_msg_vec_map:HashMap<u16,Vec<NodeToProxyOpenPhaseTwoP2PMsg>> = HashMap::new();
    let shared_open_phase_two_msg_vec_map = Arc::new(TokioMutex::new(open_phase_two_msg_vec_map));
    
    // 创建KeyManage阶段的共享变量
    let shared_key_recover_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyRecoverP2PMsg>::new()));
    let shared_key_refresh_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyRefreshOneP2PMsg>::new()));

    
    // 开启代理的监听端口
    let proxy_addr:SocketAddr = proxy.address.parse()?;
    let listener = TcpListener::bind(proxy_addr).await?;
    info!("Proxy_node is listening on {}",proxy_addr);
    let shared_proxy = Arc::new(TokioMutex::new(proxy));// 定义共享
    
    // 循环接收消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await 
    {
        // 拷贝共享代理结构体
        let proxy_clone = shared_proxy.clone();

        // 拷贝共享变量
        let shared_node_setup_p2p_msg_vec_clone = shared_node_setup_p2p_msg_vec.clone();
        let msg_num_clone = setup_msg_num.clone();                            
        let finish_num_clone = setup_finish_num.clone();
        let node_setup_finish_vec_clone = shared_node_setup_finish_vec.clone();
        
        //keygen阶段克隆
        let keygen_phase_two_msg_vec_A_clone = shared_keygen_phase_two_msg_A_vec.clone();
        let keygen_phase_two_msg_vec_B_clone = shared_keygen_phase_two_msg_B_vec.clone();
        let keygen_phase_two_msg_vec_O_clone = shared_keygen_phase_two_msg_O_vec.clone();
        let keygen_phase_two_msg_vec_C_clone = shared_keygen_phase_two_msg_C_vec.clone();
        let keygen_phase_five_msg_vec_clone = shared_keygen_phase_five_msg_vec.clone();
        let shared_join_shared_message_clone =shared_join_shared_message.clone();

        //join阶段克隆
        let user_join_msg_num_clone = user_join_msg_num.clone();
        let mta_finish_msg_vec_map_clone = shared_mta_finish_msg_vec_map.clone();
        let join_phase_three_msg_vec_map_clone = shared_join_phase_three_msg_vec_map.clone();
        let join_phase_four_msg_vec_map_clone = shared_join_phase_four_msg_vec_map.clone();
        
        //Revoke阶段克隆
        let revoke_mta_finial_msg_map_clone = shared_revoke_mta_finial_msg_map.clone();
        // let revoke_flag_vec_clone = shared_revoke_flag_vec.clone();
        let shared_revoke_shared_message_clone =shared_revoke_shared_message.clone();
        
        //open阶段克隆
        let open_phase_one_msg_vec_map_clone = shared_open_phase_one_msg_vec_map.clone();
        let open_phase_two_msg_vec_map_clone = shared_open_phase_two_msg_vec_map.clone();

        //Key recover
        let key_recover_msg_vec_clone = shared_key_recover_msg_vec.clone();
        let key_refresh_msg_vec_clone = shared_key_refresh_msg_vec.clone();
        
        //let open_two_vec_clone = shared_ntp_open_two_vec.clone();
        tokio::spawn(async move
        {
            let proxy = proxy_clone.clone();
            //接收并拆分出消息
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await 
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get node's message: {:?}",e);
                    return ;
                } 
            };
            //对不同的消息类型做处理
            match message 
            {
                GSTBKMsg::GSTBKMsgN(gstbkn_msg) => 
                {
                    match gstbkn_msg 
                    {
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::SetupMsg(setup_msg) =>  
                        { 
                            match setup_msg 
                            {
                                gs_tbk_scheme::messages::node::common_msg::SetupMsg::NodeToProxySetupPhaseP2PMsg(msg) => 
                                {
                                    info!("From Role : {}, Get NodeToProxySetupPhaseP2PMsg", msg.role);
                                    let node_setup_p2p_msg_vec = shared_node_setup_p2p_msg_vec_clone.clone();
                                    let msg_num = msg_num_clone.clone(); 
                                    let mut locked_proxy = proxy.lock().await;                           
                                    handle_setup_msg(msg,&node_setup_p2p_msg_vec,&msg_num).await;
                                    //判断收到的消息是否达到了n
                                    if *msg_num.lock().await == (locked_proxy.threashold_param.share_counts as i32) 
                                    {
                                        //info!("Setup phase is starting!");
                                        //等待一秒，等所有的节点监听接口都能打开
                                        let duration = Duration::from_secs(1);
                                        sleep(duration); 
                                        //生成proxy_setup_msg 
                                        let msg_vec = &*node_setup_p2p_msg_vec.lock().await;
                                        let setup_msg_str = setup_to_gstbk(SetupMsg::ProxySetupPhaseBroadcastMsg(locked_proxy.setup_phase_one(msg_vec)));
                                        //广播
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&setup_msg_str, node_list).await{
                                            Ok(_) => 
                                            {
                                                info!("ProxySetupBroadcastMsg has send");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error!: {}, ProxySetupBroadcastMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", msg_num);
                                        return;
                                    }
                                }
                                gs_tbk_scheme::messages::node::common_msg::SetupMsg::NodeSetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get NodeSetupPhaseFinishFlag",msg.sender,msg.role);
                                    let node_setup_finish_vec = node_setup_finish_vec_clone.clone();
                                    let finish_num = finish_num_clone.clone();
                                    let mut locked_proxy = proxy.lock().await;
                                    handle_setup_tag(msg,&node_setup_finish_vec,&finish_num).await;
                                    //判断是否所有节点都发了
                                    if *finish_num.lock().await == (locked_proxy.threashold_param.share_counts as i32) 
                                    {
                                        let msg_vec = &*node_setup_finish_vec.lock().await;
                                        let setup_finish_flag_str = setup_to_gstbk(SetupMsg::ProxySetupPhaseFinishFlag(locked_proxy.setup_phase_two(msg_vec)));
                                        //广播
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&setup_finish_flag_str, node_list).await
                                        {
                                            Ok(_) => {
                                                info!("ProxySetupFinishMsg has send");
                                            }
                                            Err(e) => {
                                                error!("Error: {}, ProxySetupFinishMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", finish_num);
                                        return;
                                    }

                                    //生成第二轮KeyGen的消息
                                    let (keygen_start_flag,keygen_phase_one_msg) = locked_proxy.keygen_phase_one();
                                    //处理发送proxy的Phaseone KeyGenStartFlag
                                    let keygen_start_flag_str = keygen_to_gstbk(KeyGenMsg::ProxyKeyGenPhaseStartFlag(keygen_start_flag));
                                    //广播
                                    let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                    match broadcast(&keygen_start_flag_str, node_list).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("ProxySetupFinishMsg has send");
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenStartFlag can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                    //处理发送proxy的Phase_one ProxyKeyGenPhaseOneBroadcastMsg
                                    let keygen_phase_one_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg));
                                    //广播
                                    match broadcast(&keygen_phase_one_msg_str, node_list).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("ProxySetupFinishMsg has send");
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenPhaseOneMsg can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                }
                                
                            }
                        }
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg {
                                gs_tbk_scheme::messages::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseTwoP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Taget key : {:?}, Get NodeProxyKeyGenPhaseTwoP2PMsg",msg.sender,msg.role,msg.dkgtag);
                                    match msg.dkgtag 
                                    {
                                        DKGTag::Gamma_A => 
                                        {
                                            let locked_proxy = proxy.lock().await;
                                            let keygen_phase_two_msg_vec_A = keygen_phase_two_msg_vec_A_clone.clone();
                                            let mut locked_vec = keygen_phase_two_msg_vec_A.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                            {
                                                let vec = (*locked_vec).clone();
                                                let node_list = locked_proxy.node_info_vec.as_ref().unwrap();
                                                let keygen_phase_three_msg_map =  locked_proxy.keygen_phase_three(vec).unwrap();
                                                for (node_id , keygen_phase_three_msg) in keygen_phase_three_msg_map
                                                {
                                                    let keygen_phase_three_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyToNodeKeyGenPhaseThreeP2PMsg(keygen_phase_three_msg));
                                                    match p2p(&keygen_phase_three_msg_str, &node_id, node_list).await 
                                                    {
                                                        Ok(_) => 
                                                        {
                                                            info!("ProxyToNodeKeyGenPhaseThreeP2PMsg_A has send");
                                                        }
                                                        Err(e) => 
                                                        {
                                                            error!("Error: {}, ProxyToNodeKeyGenPhaseThreeP2PMsg_A can not sent ",e);
                                                            return ;
                                                        }
                                                    }; 
                                                }
                                            }
                                        }
                                        DKGTag::Gamma_B => 
                                        {
                                            let locked_proxy = proxy.lock().await;
                                            let keygen_phase_two_msg_vec_B = keygen_phase_two_msg_vec_B_clone.clone();
                                            let mut locked_vec = keygen_phase_two_msg_vec_B.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                            {
                                                let vec = (*locked_vec).clone();
                                                let node_list = locked_proxy.node_info_vec.as_ref().unwrap();
                                                let keygen_phase_three_msg_map =  locked_proxy.keygen_phase_three(vec).unwrap();
                                                for (node_id , keygen_phase_three_msg) in keygen_phase_three_msg_map
                                                {
                                                    let keygen_phase_three_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyToNodeKeyGenPhaseThreeP2PMsg(keygen_phase_three_msg));
                                                    match p2p(&keygen_phase_three_msg_str, &node_id, node_list).await 
                                                    {
                                                        Ok(_) => 
                                                        {
                                                            info!("ProxyToNodeKeyGenPhaseThreeP2PMsg_B has send");
                                                        }
                                                        Err(e) => 
                                                        {
                                                            error!("Error: {}, ProxyToNodeKeyGenPhaseThreeP2PMsg_B can not sent",e);
                                                            return ;
                                                        }
                                                    }; 
                                                }
                                            }
                                        }
                                        DKGTag::Gamma_O => 
                                        {
                                            let locked_proxy = proxy.lock().await;
                                            let keygen_phase_two_msg_vec_O = keygen_phase_two_msg_vec_O_clone.clone();
                                            let mut locked_vec = keygen_phase_two_msg_vec_O.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                            {
                                                let vec = (*locked_vec).clone();
                                                let node_list = locked_proxy.node_info_vec.as_ref().unwrap();
                                                let keygen_phase_three_msg_map =  locked_proxy.keygen_phase_three(vec).unwrap();
                                                for (node_id , keygen_phase_three_msg) in keygen_phase_three_msg_map
                                                {
                                                    let keygen_phase_three_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyToNodeKeyGenPhaseThreeP2PMsg(keygen_phase_three_msg));
                                                    match p2p(&keygen_phase_three_msg_str, &node_id, node_list).await 
                                                    {
                                                        Ok(_) => 
                                                        {
                                                            info!("ProxyToNodeKeyGenPhaseThreeP2PMsg_O has send");
                                                        }
                                                        Err(e) => 
                                                        {
                                                            error!("Error: {}, ProxyToNodeKeyGenPhaseThreeP2PMsg_O can not sent",e);
                                                            return ;
                                                        }
                                                    }; 
                                                }
                                            }
                                        }
                                        DKGTag::Gamma_C => 
                                        {
                                            let locked_proxy = proxy.lock().await;
                                            let keygen_phase_two_msg_vec_C = keygen_phase_two_msg_vec_C_clone.clone();
                                            let mut locked_vec = keygen_phase_two_msg_vec_C.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                            {
                                                let vec = (*locked_vec).clone();
                                                let node_list = locked_proxy.node_info_vec.as_ref().unwrap();
                                                let keygen_phase_three_msg_map =  locked_proxy.keygen_phase_three(vec).unwrap();
                                                for (node_id , keygen_phase_three_msg) in keygen_phase_three_msg_map
                                                {
                                                    let keygen_phase_three_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyToNodeKeyGenPhaseThreeP2PMsg(keygen_phase_three_msg));
                                                    match p2p(&keygen_phase_three_msg_str, &node_id, node_list).await 
                                                    {
                                                        Ok(_) => 
                                                        {
                                                            info!("ProxyToNodeKeyGenPhaseThreeP2PMsg_C has send");
                                                        }
                                                        Err(e) => 
                                                        {
                                                            error!("Error: {}, ProxyToNodeKeyGenPhaseThreeP2PMsg_C can not sent",e);
                                                            return ;
                                                        }
                                                    }; 
                                                }
                                            }
                                        }
                                    }
                                    
                                }
                                gs_tbk_scheme::messages::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseFiveP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {},  Get NodeToProxyKeyGenPhaseFiveP2PMsg",msg.sender,msg.role);
                                    let mut locked_proxy = proxy.lock().await;
                                    let keygen_five_vec = keygen_phase_five_msg_vec_clone.clone();
                                    let mut locked_keygen_phase_msg_five_vec = keygen_five_vec.lock().await;
                                    locked_keygen_phase_msg_five_vec.push(msg);
                                    if locked_keygen_phase_msg_five_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                    {
                                        let msg_vec = &*locked_keygen_phase_msg_five_vec;
                                        let keygen_phase_five_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyToNodesKeyGenPhasefiveBroadcastMsg(locked_proxy.keygen_phase_five(msg_vec).unwrap()));
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&keygen_phase_five_msg_str, node_list).await
                                        {
                                            Ok(_) => 
                                            {
                                                info!("ProxyToNodesKeyGenPhasefiveBroadcastMsg has send");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {},ProxyToNodesKeyGenPhasefiveBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    
                                    // 测试密钥刷新
                                    // let key_refresh_start_flag = key_manage_to_gstbk(
                                    //     gs_tbk_scheme::messages::proxy::common_msg::KeyManageMsg::ProxyToNodeKeyRefreshPhaseStartFlag(
                                    //         ProxyToNodeKeyRefreshPhaseStartFlag{
                                    //             sender:locked_proxy.id.clone(),
                                    //             role:locked_proxy.role.clone(),
                                    //             dkgtag:DKGTag::Gamma_C
                                    // }));
                                    // //广播
                                    // let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                    // match broadcast(key_refresh_start_flag, node_list.clone()).await
                                    // {
                                    //     Ok(_) => 
                                    //     {
                                    //         info!("KeyRefreshStartFlag has send");
                                    //     }
                                    //     Err(e) => 
                                    //     {
                                    //         error!("KeyRefreshStartFlag can not sent Error: {}",e);
                                    //         return ;
                                    //     }
                                    // };
                                    
                                    // 测试密钥恢复
                                    // let key_recover_start_flag = key_manage_to_gstbk(
                                    //     gs_tbk_scheme::messages::proxy::common_msg::KeyManageMsg::ProxyToNodeKeyRocoverPhaseStartFlag(
                                    //         ProxyToNodeKeyRocoverPhaseStartFlag{
                                    //             sender:locked_proxy.id.clone(),
                                    //             role:locked_proxy.role.clone(),
                                                
                                    // }));
                                    // //广播
                                    // let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                    // match broadcast(key_recover_start_flag, node_list.clone()).await
                                    // {
                                    //     Ok(_) => 
                                    //     {
                                    //         info!("KeyRefreshStartFlag has send");
                                    //     }
                                    //     Err(e) => 
                                    //     {
                                    //         error!("KeyRefreshStartFlag can not sent Error: {}",e);
                                    //         return ;
                                    //     }
                                    // };

                                }
                                _ => 
                                {

                                }  
                            } 
                        }
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::JoinIssueMsg(join_issue_msg) => 
                        {
                            match join_issue_msg 
                            {
                                gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {},  Get NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg about user {}",msg.sender,msg.role,msg.user_id);
                                    let user_id = msg.user_id;
                                    let mut locked_proxy = proxy.lock().await;
                                    let mta_finish_vec_map = mta_finish_msg_vec_map_clone.clone();
                                    let mut locked_finish_vec_map = mta_finish_vec_map.lock().await;
                                    if !locked_finish_vec_map.contains_key(&user_id) 
                                    {
                                        locked_finish_vec_map.insert(user_id, Vec::<NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg>::new());
                                    }                                 
                                    let finish_vec = locked_finish_vec_map.get_mut(&user_id).unwrap();
                                    finish_vec.push(msg);
                                    if finish_vec.len() == (locked_proxy.threashold_param.threshold + 1) as usize 
                                    {
                                        let (ptu_join_three_msg,ptn_join_three_msg) = locked_proxy.join_issue_phase_three(&*finish_vec);
                                        let ptu_join_three_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToUserJoinIssuePhaseThreeP2PMsg(ptu_join_three_msg));
                                        let ptn_join_three_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseThreeBroadcastMsg(ptn_join_three_msg));
                                        let user_addr = &locked_proxy.user_info_map.as_ref().unwrap().get(&user_id).as_ref().unwrap().address;
                                        match to_user(&ptu_join_three_msg_str, user_addr).await
                                        {
                                            Ok(_) => 
                                            {
                                                info!("ProxyToUserJoinIssuePhaseThreeP2PMsg has send about user {}", finish_vec[0].user_id);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {},ProxyToUserJoinIssuePhaseThreeP2PMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                        let participants = locked_proxy.participants.as_ref().unwrap();
                                        for participant in participants 
                                        {
                                            match p2p(&ptn_join_three_msg_str, participant, locked_proxy.node_info_vec.as_ref().unwrap()).await 
                                            {
                                                Ok(_) => 
                                                {
                                                    info!("ProxyToNodeJoinIssuePhaseThreeP2PMsg has send");
                                                }
                                                Err(e) => 
                                                {
                                                    error!("ProxyToNodeJoinIssuePhaseThreeP2PMsg can not sent Error: {}",e);
                                                    return ;
                                                }
                                            }; 
                                        }
                                        finish_vec.clear();
                                    }
                                }
                                gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseThreeP2PMsg(msg) => 
                                {
                                    let user_id = msg.user_id;
                                    info!("From id : {}, Role : {}, Get NodeToProxyJoinIssuePhaseThreeP2PMsg about user {}",msg.sender, msg.role, user_id);
                                    let locked_proxy = proxy.lock().await;
                                    let join_phase_three_msg_vec_map_map = join_phase_three_msg_vec_map_clone.clone();
                                    let mut locked_join_phase_three_msg_vec_map = join_phase_three_msg_vec_map_map.lock().await;
                                    if !locked_join_phase_three_msg_vec_map.contains_key(&user_id)
                                    {
                                        locked_join_phase_three_msg_vec_map.insert(msg.user_id, Vec::<NodeToProxyJoinIssuePhaseThreeP2PMsg>::new());
                                    }                                 
                                    let join_phase_three_msg_vec = locked_join_phase_three_msg_vec_map.get_mut(&user_id).unwrap();
                                    join_phase_three_msg_vec.push(msg);
                                    if join_phase_three_msg_vec.len() == (locked_proxy.threashold_param.threshold + 1) as usize 
                                    {
                                        let msg_vec = &*join_phase_three_msg_vec;
                                        let ptn_join_four_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseFourBroadcastMsg(locked_proxy.join_issue_phase_four(msg_vec)));
                                        let participants = locked_proxy.participants.as_ref().unwrap();
                                        for participant in participants 
                                        {
                                            match p2p(&ptn_join_four_msg_str, participant, locked_proxy.node_info_vec.as_ref().unwrap()).await 
                                            {
                                                Ok(_) => {
                                                    info!("ProxyToNodesJoinIssuePhaseFourBroadcastMsg has sent");
                                                }
                                                Err(e) => {
                                                    error!("Error: {}, ProxyToNodesJoinIssuePhaseFourBroadcastMsg can not sent ",e);
                                                    return ;
                                                }
                                            }; 
                                        }
                                    }
                                }
                                gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseFourP2PMsg(msg) => 
                                {
                                    let user_id = msg.user_id;
                                    info!("From id : {}, Role : {}, Get NodeToProxyJoinIssuePhaseFourP2PMsg about user {}",msg.sender, msg.role, user_id);
                                    let mut locked_proxy = proxy.lock().await;
                                    let join_phase_four_msg_vec_map = join_phase_four_msg_vec_map_clone.clone();
                                    let mut locked_join_phase_four_msg_vec_map = join_phase_four_msg_vec_map.lock().await;
                                    if !locked_join_phase_four_msg_vec_map.contains_key(&user_id) 
                                    {
                                        locked_join_phase_four_msg_vec_map.insert(msg.user_id, Vec::<NodeToProxyJoinIssuePhaseFourP2PMsg>::new());
                                    }                                 
                                    let join_phase_four_msg_vec = locked_join_phase_four_msg_vec_map.get_mut(&user_id).unwrap();
                                    join_phase_four_msg_vec.push(msg);
                                    if join_phase_four_msg_vec.len() == (locked_proxy.threashold_param.threshold + 1) as usize 
                                    {
                                        let msg_vec = &*join_phase_four_msg_vec;
                                        let ptn_join_five_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseFiveBroadcastMsg(locked_proxy.join_issue_phase_five(msg_vec)));
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&ptn_join_five_msg_str, node_list).await
                                        {
                                            Ok(_) =>
                                            {
                                                info!("Join/Issue phase is finished");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, ProxyToNodesJoinIssuePhaseFiveBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                        
                                    }
                                }
                                gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseFlag(msg)=>{
                                    info!("From id : {}, Role : {}, Get NodeToProxyJoinIssuePhaseFlag about user {}",msg.sender,msg.role,msg.user_id);
                                    
                                    let mut locked_proxy = proxy.lock().await;
                                    
                                    let shared_join_shared_message = shared_join_shared_message_clone.clone();
                                    
                                    let mut join_shared_message = shared_join_shared_message.lock().await;
                                    
                                    let join_node_flag_message = JoinPhaseRevokeSharedMessageType::NodeToProxyJoinIssuePhaseFlag(msg.clone());
                                    
                                    if !join_shared_message.shared_message_map.contains_key(&msg.user_id) {
                                        join_shared_message.shared_message_map.insert(msg.user_id, Vec::<JoinPhaseRevokeSharedMessageType>::new());
                                    }
                                    join_shared_message.shared_message_map.get_mut(&msg.user_id).unwrap().push(join_node_flag_message);

                                    // info!("Node saved, current number of message is {}",revoke_shared_message.shared_message_map.get(&msg.sender).unwrap().len());

                                    if join_shared_message.shared_message_map.get(&msg.user_id).unwrap().len() == (locked_proxy.threashold_param.share_counts+1) as usize
                                    {
                                        let ptn_revoke_one_msg = locked_proxy.revoke_phase_one(msg.user_id);
                                        let ptn_revoke_one_revo = gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg::ProxyToNodesRevokePhaseOneBroadcastMsg(ptn_revoke_one_msg);
                                        let ptn_revoke_one_str = revoke_to_gstbk(ptn_revoke_one_revo);
                                        let participants = locked_proxy.participants.as_ref().unwrap();
                                        for participant in participants  
                                        {
                                            match p2p(&ptn_revoke_one_str, &participant, locked_proxy.node_info_vec.as_ref().unwrap()).await 
                                            {
                                                Ok(_) => 
                                                {
                                                    info!("ProxyToNodesRevokePhaseOneBroadcastMsg sent to node {} about user {}",participant, msg.user_id);
                                                }
                                                Err(e) => 
                                                {
                                                    error!("Error: {},ProxyToNodesRevokePhaseOneBroadcastMsg can not sent",e);
                                                    return ;
                                                }
                                            };  
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::RevokeMsg(revoke_msg) => 
                        {
                            match revoke_msg 
                            {
                                gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg about user {}",msg.sender,msg.role,msg.user_id);
                                    let mut locked_proxy = proxy.lock().await;
                                    let revoke_mta_finial_msg_map = revoke_mta_finial_msg_map_clone.clone();
                                    let mut locked_revoke_mta_finial_msg_map = revoke_mta_finial_msg_map.lock().await;
                                    if !locked_revoke_mta_finial_msg_map.contains_key(&msg.user_id) {
                                        locked_revoke_mta_finial_msg_map.insert(msg.user_id, Vec::<NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg>::new());
                                    }
                                    let locked_revoke_mta_finial_msg_vec = locked_revoke_mta_finial_msg_map.get_mut(&msg.user_id).unwrap();
                                    locked_revoke_mta_finial_msg_vec.push(msg); 
                                    let user_id = locked_revoke_mta_finial_msg_vec[0].user_id;
                                    if locked_revoke_mta_finial_msg_vec.len() == (locked_proxy.threashold_param.threshold + 1) as usize  
                                    {
                                        let msg_vec = &*locked_revoke_mta_finial_msg_vec;
                                        let(ptn_revoke_two_msg,ptu_revoke_msg) = locked_proxy.revoke_phase_two(msg_vec);
                                        let ptn_revoke_phase_two_msg_str = revoke_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg::ProxyToNodesRevokePhaseTwoBroadcastMsg(ptn_revoke_two_msg));
                                        let ptu_revoke_phase_msg_str = revoke_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg::ProxyToUserRevokePhaseBroadcastMsg(ptu_revoke_msg));
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&ptn_revoke_phase_two_msg_str, node_list).await
                                        {
                                            Ok(_) =>{
                                                info!("ProxyToNodesRevokePhaseTwoBroadcastMsg sent about user {}",user_id); 
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, ProxyToNodesRevokePhaseTwoBroadcastMsg can not sent ",e);
                                                return ;
                                            } 
                                        };
                                        
                                        let user_addr = locked_proxy.user_info_map.as_ref().unwrap().get(&user_id).as_ref().unwrap().address.clone();
                                        match to_user(&ptu_revoke_phase_msg_str, &user_addr).await
                                        {
                                            Ok(_) =>{
                                                info!("ProxyToUserRevokePhaseBroadcastMsg sent to user: {}",user_id);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, ProxyToUserRevokePhaseBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        }
                                        locked_revoke_mta_finial_msg_vec.clear();
                                    }
                                }
                                gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToProxyRevokePhaseTwoFlag(msg)=>{
                                    info!("From id : {}, Role : {}, Get NodeToProxyRevokePhaseTwoFlag about user {}",msg.sender,msg.role,msg.user_id);
                                    
                                    let locked_proxy = proxy.lock().await;
                                    
                                    let shared_revoke_shared_message = shared_revoke_shared_message_clone.clone();
                                    
                                    let mut revoke_shared_message = shared_revoke_shared_message.lock().await;
                                    
                                    let revoke_shared_node_flag_message = RevokePhaseSignSharedMessageType::NodeToProxyRevokePhaseTwoFlag(msg.clone());
                                    
                                    if !revoke_shared_message.shared_message_map.contains_key(&msg.user_id) 
                                    {
                                        revoke_shared_message.shared_message_map.insert(msg.user_id, Vec::<RevokePhaseSignSharedMessageType>::new());
                                    }
                                    revoke_shared_message.shared_message_map.get_mut(&msg.user_id).unwrap().push(revoke_shared_node_flag_message);

                                    //info!("Node saved, current number of message is {}",revoke_shared_message.shared_message_map.get(&msg.sender).unwrap().len());

                                    if revoke_shared_message.shared_message_map.get(&msg.user_id).unwrap().len() == (locked_proxy.threashold_param.share_counts+1) as usize{
                                        let verify_phase_msg_str = verify_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::VerifyMsg::ProxyToNodesVerifyPhaseBroadcastMsg(locked_proxy.verify_phase(msg.user_id.clone())));
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&verify_phase_msg_str, node_list).await
                                        {
                                            Ok(_) => {
                                                info!("ProxyToNodesVerifyPhaseBroadcastMsg sent to all nodes about user: {}",msg.user_id);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {},ProxyToNodesVerifyPhaseBroadcastMsg can not sent",e);
                                                return ;
                                            }
                                        };
                                    }
                                }

                                _ => {} 
                            }
                        }
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::OpenMsg(open_msg) => 
                        {
                            match open_msg 
                            { 
                                gs_tbk_scheme::messages::node::common_msg::OpenMsg::NodeToProxyOpenPhaseOneP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get NodeToProxyOpenPhaseOneP2PMsg about user {}",msg.sender,msg.role,msg.user_id);
                                    let locked_proxy = proxy.lock().await;
                                    // open phase 的开始
                                    let open_phase_one_msg_vec_map = open_phase_one_msg_vec_map_clone.clone();
                                    let mut locked_map = open_phase_one_msg_vec_map.lock().await;
                                    if !locked_map.contains_key(&msg.user_id)  
                                    {
                                        locked_map.insert(msg.user_id, Vec::<NodeToProxyOpenPhaseOneP2PMsg>::new());
                                    }
                                    let open_phase_one_msg_vec = locked_map.get_mut(&msg.user_id).unwrap();
                                    open_phase_one_msg_vec.push(msg);
                                    
                                    if open_phase_one_msg_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                    {
                                        let msg_vec = &*open_phase_one_msg_vec;
                                        let ptn_open_one_str = open_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::OpenMsg::ProxyToNodesOpenPhaseOneBroadcastMsg(locked_proxy.open_phase_one(msg_vec)));
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&ptn_open_one_str, node_list).await
                                        {
                                            Ok(_) =>{
                                                info!("ProxyToNodesOpenPhaseOneBroadcastMsg has sent about user {}",msg_vec[0].user_id);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, ProxyToNodesOpenPhaseOneBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                }
                                gs_tbk_scheme::messages::node::common_msg::OpenMsg::NodeToProxyOpenPhaseTwoP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {},Get NodeToProxyOpenPhasetwoP2PMsg about user {}",msg.sender,msg.role,msg.user_id);
                                    let locked_proxy = proxy.lock().await;
                                    let open_phase_two_msg_vec_map = open_phase_two_msg_vec_map_clone.clone();
                                    let mut locked_map = open_phase_two_msg_vec_map.lock().await;
                                    if !locked_map.contains_key(&msg.user_id)
                                    {
                                        locked_map.insert(msg.user_id, Vec::<NodeToProxyOpenPhaseTwoP2PMsg>::new());
                                    }
                                    let open_phase_two_msg_vec = locked_map.get_mut(&msg.user_id).unwrap();
                                    open_phase_two_msg_vec.push(msg);
                                    if open_phase_two_msg_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                    {
                                        let msg_vec = &*open_phase_two_msg_vec;
                                        let open_phase_two_msg_vec_str = open_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::OpenMsg::ProxyToNodesOpenPhaseTwoBroadcastMsg(locked_proxy.open_phase_two(msg_vec)));
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&open_phase_two_msg_vec_str, node_list).await
                                        {
                                            Ok(_) =>{
                                                info!("ProxyToNodesOpenPhaseTwoBroadcastMsg has sent about user {}",msg_vec[0].user_id);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, ProxyToNodesOpenPhaseTwoBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }

                                }
                            }
                        }
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyManageMsg(key_manage_msg)=>
                        {
                            match key_manage_msg
                            {
                                gs_tbk_scheme::messages::node::common_msg::KeyManageMsg::NodeToProxyKeyRecoverP2PMsg(msg) =>
                                {
                                    info!("From id : {} Role : Node , Get NodeToProxyKeyRecoverP2PMsg",msg.sender);
                                    let locked_proxy = proxy.lock().await; 
                                    let key_recover_msg_vec = key_recover_msg_vec_clone.clone();
                                    let mut locked_recover_vec = key_recover_msg_vec.lock().await;
                                    locked_recover_vec.push(msg);

                                    if locked_recover_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                    {
                                        
                                        let msg_vec = &*locked_recover_vec;
                                        locked_proxy.key_recover_phase(msg_vec);
                                    }
                                    
                                }
                                gs_tbk_scheme::messages::node::common_msg::KeyManageMsg::NodeToProxyKeyRefreshOneP2PMsg(msg) =>
                                {
                                    info!("From id : {} Role : Node , Get NodeToProxyKeyRefreshOneP2PMsg",msg.sender);
                                    let locked_proxy = proxy.lock().await; 
                                    let key_refresh_msg_vec = key_refresh_msg_vec_clone.clone();
                                    let mut locked_refresh_vec = key_refresh_msg_vec.lock().await;
                                    locked_refresh_vec.push(msg);

                                    if locked_refresh_vec.len() == locked_proxy.threashold_param.share_counts as usize
                                    {
                                        let msg_vec = &*locked_refresh_vec;
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap();
                                        let key_refresh_phase_two_msg_map = match locked_proxy.key_refresh_phase_two(msg_vec)
                                        {
                                            Ok(key_refresh_phase_two_msg_map) => key_refresh_phase_two_msg_map,
                                            Err(err) => 
                                            {
                                                error!("Error: {}, Key refresh phase two error",err);
                                                return ;
                                            }
                                        };

                                        for (node_id, key_refresh_phase_two_msg) in key_refresh_phase_two_msg_map
                                        {
                                            let key_refresh_phase_two_msg_str = key_manage_to_gstbk(KeyManageMsg::ProxyToNodeKeyRefreshPhaseTwoP2PMsg(key_refresh_phase_two_msg));
                                            match p2p(&key_refresh_phase_two_msg_str, &node_id, node_list).await 
                                            {
                                                Ok(_) => 
                                                {
                                                    info!("ProxyToNodeKeyRefreshPhaseTwoP2PMsg has send");
                                                }
                                                Err(e) => 
                                                {
                                                    error!("Error: {}, ProxyToNodeKeyRefreshPhaseTwoP2PMsg can not sent",e);
                                                    return ;
                                                }
                                            }; 
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                GSTBKMsg::GSTBKMsgU(gstbku_msg) => 
                {
                    match gstbku_msg 
                    {
                        gs_tbk_scheme::messages::user::common_msg::GSTBKMsg::JoinIssueMsg(join_msg) => 
                        {
                            match join_msg 
                            {
                                gs_tbk_scheme::messages::user::common_msg::JoinIssueMsg::UserJoinIssuePhaseStartFlag(msg) => 
                                {
                                    let mut user_join_msg_num = user_join_msg_num_clone.lock().await;
                                    *user_join_msg_num += 1;
                                    let mut locked_proxy = proxy.lock().await;
                                    let join_phase_one_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToUserJoinIssuePhaseOneP2PMsg(locked_proxy.join_issue_phase_one(&user_join_msg_num)));
                                    match to_user(&join_phase_one_msg_str, &msg.ip).await
                                    {
                                        Ok(_) => { 
                                            info!("ProxyToUserJoinIssuePhaseOneP2PMsg has sent ")
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {},ProxyToUserJoinIssuePhaseOneP2PMsg can not sent ",e);
                                            return ;
                                        }
                                    };
                                }
                                gs_tbk_scheme::messages::user::common_msg::JoinIssueMsg::UserToProxyJoinIssuePhaseTwoP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get UserToProxyJoinIssuePhaseTwoP2PMsg",msg.sender,msg.role);
                                    let mut locked_proxy = proxy.lock().await;
                                    let join_phase_two_msg = match locked_proxy.join_issue_phase_two(&msg)
                                    {
                                        Ok(v) => v,
                                        Err(e) => 
                                        {
                                            error!("Error: {},ProxyToNodesJoinIssuePhaseTwoBroadcastMsg can not sent",e);
                                            return ;
                                        }
                                    };
                                    let join_phase_two_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseTwoBroadcastMsg(join_phase_two_msg));
                                    let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                    match broadcast(&join_phase_two_msg_str, node_list).await
                                    {
                                        Ok(_) => {
                                            info!("ProxyToNodesJoinIssuePhaseTwoBroadcastMsg has sent to nodes about user {}",msg.sender);
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {},ProxyToNodesJoinIssuePhaseTwoBroadcastMsg can not sent",e);
                                            return ;
                                        }
                                    };
                                } 
                            }
                        }
                        gs_tbk_scheme::messages::user::common_msg::GSTBKMsg::RevokeMsg(revoke_msg)=>
                        {
                            match revoke_msg
                            {
                                gs_tbk_scheme::messages::user::common_msg::RevokeMsg::RevokePhaseStartFlag(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get RevokePhaseStartFlag about user {}",msg.sender,msg.role,msg.sender);
                                    
                                    let mut locked_proxy = proxy.lock().await;
                                    
                                    let shared_join_shared_message = shared_join_shared_message_clone.clone();
                                    
                                    let mut join_shared_message = shared_join_shared_message.lock().await;
                                    
                                    let join_node_flag_message = JoinPhaseRevokeSharedMessageType::RevokePhaseStartFlag(msg.clone());
                                    
                                    if !join_shared_message.shared_message_map.contains_key(&msg.sender) {
                                        join_shared_message.shared_message_map.insert(msg.sender, Vec::<JoinPhaseRevokeSharedMessageType>::new());
                                    }
                                    join_shared_message.shared_message_map.get_mut(&msg.sender).unwrap().push(join_node_flag_message);

                                    // info!("Node saved, current number of message is {}",revoke_shared_message.shared_message_map.get(&msg.sender).unwrap().len());

                                    if join_shared_message.shared_message_map.get(&msg.sender).unwrap().len() == (locked_proxy.threashold_param.share_counts+1) as usize
                                    {
                                        let ptn_revoke_one_msg = locked_proxy.revoke_phase_one(msg.sender);
                                        let ptn_revoke_one_revo = gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg::ProxyToNodesRevokePhaseOneBroadcastMsg(ptn_revoke_one_msg);
                                        let ptn_revoke_one_str = revoke_to_gstbk(ptn_revoke_one_revo);
                                        let participants = locked_proxy.participants.as_ref().unwrap();
                                        for participant in participants  
                                        {
                                            match p2p(&ptn_revoke_one_str, &participant, locked_proxy.node_info_vec.as_ref().unwrap()).await 
                                            {
                                                Ok(_) => 
                                                {
                                                    info!("RevokePhaseStartFlag sent to node {} about user {}",participant, msg.sender);
                                                }
                                                Err(e) => 
                                                {
                                                    error!("Error: {},RevokePhaseStartFlag can not sent",e);
                                                    return ;
                                                }
                                            };  
                                        }
                                    }   
                                }
                            }
                        }
                        gs_tbk_scheme::messages::user::common_msg::GSTBKMsg::SignMsg(sign_msg) => 
                        {
                            match sign_msg {
                                gs_tbk_scheme::messages::user::common_msg::SignMsg::SignPhaseStartFlag(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get SignPhaseStartFlag about user {}",msg.sender,msg.role,msg.sender);
                                    let locked_proxy = proxy.lock().await;
                                    
                                    let shared_revoke_shared_message = shared_revoke_shared_message_clone.clone();
                                    
                                    let mut revoke_shared_message = shared_revoke_shared_message.lock().await;
                                    
                                    let revoke_shared_sign_message = RevokePhaseSignSharedMessageType::SignPhaseStartFlag(msg.clone());
                                    
                                    if !revoke_shared_message.shared_message_map.contains_key(&msg.sender) {
                                        revoke_shared_message.shared_message_map.insert(msg.sender, Vec::<RevokePhaseSignSharedMessageType>::new());
                                    }
                                    revoke_shared_message.shared_message_map.get_mut(&msg.sender).unwrap().push(revoke_shared_sign_message);

                                    //info!("User signed, current number of message is {}",revoke_shared_message.shared_message_map.get(&msg.sender).unwrap().len());

                                    if revoke_shared_message.shared_message_map.get(&msg.sender).unwrap().len() == (locked_proxy.threashold_param.share_counts+1) as usize{
                                        let verify_phase_msg_str = verify_to_gstbk(gs_tbk_scheme::messages::proxy::common_msg::VerifyMsg::ProxyToNodesVerifyPhaseBroadcastMsg(locked_proxy.verify_phase(msg.sender.clone())));
                                        let node_list = locked_proxy.node_info_vec.as_ref().unwrap(); 
                                        match broadcast(&verify_phase_msg_str, node_list).await
                                        {
                                            Ok(_) => {
                                                info!("ProxyToNodesVerifyPhaseBroadcastMsg sent to all nodes about user {}",msg.sender);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {},ProxyToNodesVerifyPhaseBroadcastMsg can not sent",e);
                                                return ;
                                            }
                                        };
                                    }

                                }
                            }
                        }
                    }
                }
                _ => 
                {

                }
                
            }
        });
    }
     
    Ok(())
}

//test
#[test] 
fn test()  
{
   match main() 
   {
    Ok(_) => 
    { 
        info!("Ok");
    }
    Err(_) => 
    {
        error!("No");
    }
   };
}

 