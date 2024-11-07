use std::collections::HashMap;
use tokio::net::{TcpListener};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::codec::{Framed, LinesCodec};
use std::net::SocketAddr;
use std::sync::Arc;
use std::env;
use log::{error, info, warn};


use node::communication::communication::*;
use node::node::{Node, NodeConfig};
use node::config::config::Config;
use gs_tbk_scheme::messages::common_msg::GSTBKMsg;
use gs_tbk_scheme::params::{DKGTag, MTATag};
use gs_tbk_scheme::messages::node::keygen_msg::NodeKeyGenPhaseOneBroadcastMsg;
use gs_tbk_scheme::messages::node::common_msg::{SetupMsg, KeyGenMsg, KeyManageMsg};

use gs_tbk_scheme::messages::node::join_issue_msg::{JoinMTATag, NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg, NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg, NodeProxyJoinMTASharedMessage};
use gs_tbk_scheme::messages::node::revoke_msg::{RevokeMTATag,NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg,NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg, NodeProxyRevokeMTASharedMessage};


#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node1/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    //初始化node
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node1/config/config_file/node_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();

    //将node设置成共享变量以便在async中能够修改
    //不用Arc<node>的原因是,Arc用于共享不可变数据，多个线程可以同时访问,但如果有一个线程尝试修改它，就可能会导致竞争条件和不确定的行为
    let node = Node::init(gs_tbk_config);
    let shared_node = Arc::new(TokioMutex::new(node.clone()));

    //设置keygen阶段的共享变量
    let shared_keygen_phase_one_msg_vec_A = Arc::new(TokioMutex::new(Vec::<NodeKeyGenPhaseOneBroadcastMsg>::new()));
    let shared_keygen_phase_one_msg_vec_B = Arc::new(TokioMutex::new(Vec::<NodeKeyGenPhaseOneBroadcastMsg>::new()));
    let shared_keygen_phase_one_msg_vec_O = Arc::new(TokioMutex::new(Vec::<NodeKeyGenPhaseOneBroadcastMsg>::new()));
    let shared_keygen_phase_one_msg_vec_C = Arc::new(TokioMutex::new(Vec::<NodeKeyGenPhaseOneBroadcastMsg>::new()));
    let shared_xj_num = Arc::new(TokioMutex::new(0));

    //设置join阶段的共享变量
    let join_mta_two_map: HashMap<u16,Vec<NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg>> = HashMap::new();
    let shared_join_mta_two_map = Arc::new(TokioMutex::new(join_mta_two_map));
    let shared_join_mta_tag = Arc::new(TokioMutex::new(JoinMTATag{tag_map:HashMap::new()}));
    let shared_join_mta_shared_message = Arc::new(TokioMutex::new(NodeProxyJoinMTASharedMessage{shared_message_map:HashMap::new()}));

    //设置revoke阶段的共享变量
    let revoke_mta_two_map: HashMap<u16,Vec<NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg>> = HashMap::new();
    let shared_revoke_mta_two_map = Arc::new(TokioMutex::new(revoke_mta_two_map));
    let shared_revoke_mta_tag = Arc::new(TokioMutex::new(RevokeMTATag{tag_map:HashMap::new()}));
    let shared_revoke_mta_shared_message = Arc::new(TokioMutex::new(NodeProxyRevokeMTASharedMessage{shared_message_map:HashMap::new()}));

    //设置key manage阶段的共享变量


    //开启节点监听接口
    let node_addr:SocketAddr = node.listen_addr.parse()?;
    let listener = TcpListener::bind(node_addr).await?;
    info!("node1 is listening on {}",node.node_addr);

    //向proxy发送消息，代码，启动
    let node_setup_msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::SetupMsg(SetupMsg::NodeToProxySetupPhaseP2PMsg(node.setup_phase_one())))).unwrap();
    match p2p(&node_setup_msg_str, &node.proxy_address).await
    {
        Ok(_) => {}
        Err(e) => 
        {
            error!("node setup msg can not send Err:{}",e);
        }
    };

    //循环接受消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await
    {
        //对共享变量进行克隆
        let node_clone = shared_node.clone();
        
        //keygen阶段
        let keygen_phase_one_msg_vec_A_clone = shared_keygen_phase_one_msg_vec_A.clone();
        let keygen_phase_one_msg_vec_B_clone = shared_keygen_phase_one_msg_vec_B.clone();
        let keygen_phase_one_msg_vec_O_clone = shared_keygen_phase_one_msg_vec_O.clone(); 
        let keygen_phase_one_msg_vec_C_clone = shared_keygen_phase_one_msg_vec_C.clone();
        let xj_num_clone = shared_xj_num.clone();

        //join阶段
        let join_mta_two_map_clone = shared_join_mta_two_map.clone();
        let shared_join_mta_tag_clone = shared_join_mta_tag.clone();
        let shared_join_mta_shared_message_clone = shared_join_mta_shared_message.clone();

        //revoke阶段
        let shared_revoke_mta_two_map_clone = shared_revoke_mta_two_map.clone();
        let shared_revoke_mta_shared_message_clone = shared_revoke_mta_shared_message.clone();
        let shared_revoke_mta_tag_clone = shared_revoke_mta_tag.clone();
        tokio::spawn(async move
            {
            //闭包里克隆共享变量
            let node = node_clone.clone();

            //keygen阶段
            let keygen_phase_one_msg_vec_A = keygen_phase_one_msg_vec_A_clone.clone();
            let keygen_phase_one_msg_vec_B = keygen_phase_one_msg_vec_B_clone.clone();
            let keygen_phase_one_msg_vec_O = keygen_phase_one_msg_vec_O_clone.clone();
            let keygen_phase_one_msg_vec_C = keygen_phase_one_msg_vec_C_clone.clone();
            let xj_num = xj_num_clone.clone();
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
            match message 
            {
                GSTBKMsg::GSTBKMsgP(gstbk_proxy_msg) => 
                {
                    match gstbk_proxy_msg
                    {
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::SetupMsg(setup_msg) => 
                        {
                            match setup_msg 
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::SetupMsg::ProxySetupPhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxySetupPhaseBroadcastMsg");
                                    let mut locked_node = node.lock().await;
                                    let setup_phase_two_msg_str = setup_to_gstbk(SetupMsg::NodeSetupPhaseFinishFlag(locked_node.setup_phase_two(msg)));
                                    match p2p(&setup_phase_two_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("From id : 0 ,Role : Proxy  Send NodeToProxySetupFinishMsg");
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {}, NodeToProxySetupFinishMsg can not send ",e);
                                            return ;
                                        }
                                    };
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::SetupMsg::ProxySetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxySetupPhaseFinishFlag");
                                    let locked_node = node.lock().await;
                                    locked_node.setup_phase_three(msg);
                                }
        
                            }
        
                        }
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg  
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::KeyGenMsg::ProxyKeyGenPhaseStartFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyKeyGenPhaseStartFlag");
                                    //info!("StartFlag is {:?}",msg);
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::KeyGenMsg::ProxyKeyGenPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyKeyGenPhaseOneBroadcastMsg");
                                    info!("Keygen phase is staring!");
                                    //生成ABOC
                                    let tag_A = DKGTag::Gamma_A;
                                    let tag_B = DKGTag::Gamma_B;
                                    let tag_O = DKGTag::Gamma_O;
                                    let tag_C = DKGTag::Gamma_C;
                                    let mut locked_node = node.lock().await;

                                    //压入自己的vec
                                    let mut locked_vec_A = keygen_phase_one_msg_vec_A.lock().await;
                                    let mut locked_vec_B = keygen_phase_one_msg_vec_B.lock().await;
                                    let mut locked_vec_O = keygen_phase_one_msg_vec_O.lock().await;
                                    let mut locked_vec_C = keygen_phase_one_msg_vec_C.lock().await;

                                    //生成并序列化NodeKeyGenPhaseOneBroadcastMsg
                                    let keygen_phase_one_msg_A = locked_node.keygen_phase_one(tag_A, msg.clone());
                                    locked_vec_A.push(keygen_phase_one_msg_A.clone());
                                    let keygen_phase_one_msg_B = locked_node.keygen_phase_one(tag_B, msg.clone());
                                    locked_vec_B.push(keygen_phase_one_msg_B.clone());
                                    let keygen_phase_one_msg_O = locked_node.keygen_phase_one(tag_O, msg.clone());
                                    locked_vec_O.push(keygen_phase_one_msg_O.clone());
                                    let keygen_phase_one_msg_C = locked_node.keygen_phase_one(tag_C, msg.clone());
                                    locked_vec_C.push(keygen_phase_one_msg_C.clone());

                                    let keygen_phase_one_msg_A_str = keygen_to_gstbk(KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg_A));
                                    let keygen_phase_one_msg_B_str = keygen_to_gstbk(KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg_B));
                                    let keygen_phase_one_msg_O_str = keygen_to_gstbk(KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg_O));
                                    let keygen_phase_one_msg_C_str = keygen_to_gstbk(KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg_C));
                                    let mut msg_vec:Vec<String> = Vec::new();
                                    msg_vec.push(keygen_phase_one_msg_A_str);
                                    msg_vec.push(keygen_phase_one_msg_B_str);
                                    msg_vec.push(keygen_phase_one_msg_O_str);
                                    msg_vec.push(keygen_phase_one_msg_C_str);
                                    let node_list = locked_node.node_info_vec.as_ref().unwrap();

                                    let node_id = locked_node.id.as_ref().unwrap();

                                    //将消息广播发送出去
                                    for msg in msg_vec
                                    {
                                        match broadcast(&msg, node_list,node_id).await
                                        {
                                            Ok(_) => {
                                                info!("NodeKeyGenPhaseOneBroadcastMsg has sent");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeKeyGenPhaseOneBroadcastMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::KeyGenMsg::ProxyToNodeKeyGenPhaseThreeP2PMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodeKeyGenPhaseThreeP2PMsg");
                                    let mut locked_num = xj_num.lock().await;
                                    let mut locked_node = node.lock().await;
                                    match locked_node.keygen_phase_four(msg) 
                                    {
                                        Ok(_) => 
                                        {
                                            *locked_num += 1; 
                                        }
                                        Err(e) => 
                                        {
                                            error!("can not get xj Err is {}",e);
                                        }
                                    };
                                    if *locked_num == 4 as i32 
                                    {
                                        let keygen_phase_five_msg_str = keygen_to_gstbk(KeyGenMsg::NodeToProxyKeyGenPhaseFiveP2PMsg(locked_node.keygen_phase_five()));
                                        match p2p(&keygen_phase_five_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                        {
                                            Ok(_) => {
                                                info!("NodeToProxyKeyGenPhaseFiveP2PMsg has sent");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeToProxyKeyGenPhaseFiveP2PMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::KeyGenMsg::ProxyToNodesKeyGenPhasefiveBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesKeyGenPhasefiveBroadcastMsg");
                                    let mut locked_node = node.lock().await;
                                    locked_node.keygen_phase_six(msg);
                                    // 写到文件里
                                    let node = (*locked_node).clone();
                                    let node_str = serde_json::to_string(&get_node_config(node)).unwrap();
                                    let mut node_path  = std::env::current_dir().unwrap();
                                    let path = "src/node/node1/info/keygen.json";
                                    node_path.push(path);
                                    std::fs::write(node_path, node_str).unwrap();
                                }
                            }
                        }
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::JoinIssueMsg(join_issue_msg) => 
                        {
                            match join_issue_msg 
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseTwoBroadcastMsg(msg) => 
                                {
                                    let mut locked_node = node.lock().await;
                                    let user_id = msg.user_id;
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseTwoBroadcastMsg about user {}",msg.user_id);
                                    let shared_join_mta_tag = shared_join_mta_tag_clone.clone();
                                    let mut mta_tag = shared_join_mta_tag.lock().await;

                                    if !mta_tag.tag_map.contains_key(&msg.user_id) 
                                    {
                                        mta_tag.tag_map.insert(msg.user_id, true);
                                    }else{
                                        mta_tag.tag_map.insert(msg.user_id, true);
                                    }
                                    
                                    
                                    let participants = &locked_node.participants.clone().unwrap();
                                    if participants.contains(&locked_node.id.unwrap())
                                    {
                                        let join_mta_one_str = join_issue_to_gstbk(gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg(
                                            locked_node.join_issue_phase_two_mta_one(&DKGTag::Gamma_A, &msg, &MTATag::Mta_A).unwrap()
                                        ));
                                        for participant in participants 
                                        {
                                            if participant == &locked_node.id.unwrap() 
                                            {
                                                continue;
                                            }
                                            match to_node(&join_mta_one_str, participant,locked_node.node_info_vec.as_ref().unwrap()).await 
                                            {
                                                Ok(_) => {
                                                    info!("NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg has sent to {} about user {}",participant,msg.user_id);
                                                }
                                                Err(e) => 
                                                {
                                                    error!("Error: {}, NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg can not send ",e);
                                                    return ;
                                                }
                                            };
                                        }
                                    }
                                    else 
                                    {
                                        locked_node.join_issue_phase_two(msg).unwrap();
                                    }

                                    // 执行完mta第一阶段就继续执行，vec里存放的未执行的第二阶段消息
                                    let shared_join_mta_shared_message = shared_join_mta_shared_message_clone.clone();
                                    let join_mta_shared_message = shared_join_mta_shared_message.lock().await;

                                    match join_mta_shared_message.shared_message_map.get(&user_id) {
                                        None=>{

                                        }
                                        _=>{
                                            if !join_mta_shared_message.shared_message_map.get(&user_id).unwrap().is_empty() {
                                                for mta_msg in join_mta_shared_message.shared_message_map.get(&user_id).unwrap() {
                                                    let join_mta_two_str = join_issue_to_gstbk(gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg(locked_node.join_issue_phase_two_mta_two( &mta_msg,&MTATag::Mta_A)));
                                                        match to_node(&join_mta_two_str, &mta_msg.sender,locked_node.node_info_vec.as_ref().unwrap()).await 
                                                        {
                                                            Ok(_) => 
                                                            {
                                                                info!("NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg sent to {} about user {}",mta_msg.sender,mta_msg.user_id);
                                                            }
                                                            Err(e) => 
                                                            {
                                                                error!("Error: {}, NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg can not send ",e);
                                                                return ;
                                                            }
                                                        };
                                                }
                                            }
                                        }
                                    }     
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseThreeBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseThreeBroadcastMsg about user {}",msg.user_id);
                                    let mut locked_node = node.lock().await;
                                    let join_phase_three_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseThreeP2PMsg(locked_node.join_issue_phase_three(&msg)));
                                    match p2p(&join_phase_three_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("ProxyToNodesJoinIssuePhaseThreeBroadcastMsg has sent about user {}",msg.user_id)
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {}, ProxyToNodesJoinIssuePhaseThreeBroadcastMsg can not send ",e);
                                            return ;
                                        }
                                    };
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseFourBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFourBroadcastMsg about user {}",msg.user_id);
                                    let locked_node = node.lock().await;
                                    let join_phase_four_msg_str = join_issue_to_gstbk(gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseFourP2PMsg(locked_node.join_issue_phase_five(&msg)));
                                    match p2p(&join_phase_four_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("ProxyToNodesJoinIssuePhaseFourBroadcastMsg has sent about user {}",msg.user_id)
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {}, ProxyToNodesJoinIssuePhaseFourBroadcastMsg can not send ",e);
                                            return ;
                                        }
                                    };
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::JoinIssueMsg::ProxyToNodesJoinIssuePhaseFiveBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesJoinIssuePhaseFiveBroadcastMsg about user {}",msg.user_id);
                                    let mut locked_node = node.lock().await;
                                    let join_flag_str = join_issue_to_gstbk(gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseFlag(locked_node.join_issue_phase_six(&msg)));
                                    match p2p(&join_flag_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("NodeToProxyJoinIssuePhaseFlag has sent about user {}",msg.user_id)
                                        }
                                        Err(e) => 
                                        {
                                            error!("Error: {}, NodeToProxyJoinIssuePhaseFlag can not send ",e);
                                            return ;
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
                                gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg::ProxyToNodesRevokePhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesRevokePhaseOneBroadcastMsg about user {}",msg.user_id); 
                                    let mut locked_node = node.lock().await;
                                    let user_id = msg.user_id;
                                    let shared_revoke_mta_tag = shared_revoke_mta_tag_clone.clone();
                                    let mut mta_tag = shared_revoke_mta_tag.lock().await;   

                                    if !mta_tag.tag_map.contains_key(&msg.user_id) 
                                    {
                                        mta_tag.tag_map.insert(msg.user_id, true);
                                    }else{
                                        mta_tag.tag_map.insert(msg.user_id, true);
                                    }
                                    
                                    
                                    let revoke_mta_one_str = revoke_to_gstbk(gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg(locked_node.revoke_phase_one_mta_one(&DKGTag::Gamma_B, &msg, &MTATag::Mta_B)));
                                    let participants = locked_node.participants.as_ref().unwrap();
                                    for participant in participants 
                                    { 
                                        if participant == &locked_node.id.unwrap() 
                                        {
                                            continue; 
                                        }
                                        match to_node(&revoke_mta_one_str, &participant,locked_node.node_info_vec.as_ref().unwrap()).await 
                                        {
                                            Ok(_) => 
                                            {
                                                info!("NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg sent to node : {} about user {}",participant,msg.user_id);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }

                                    // 执行完mta第一阶段就继续执行，vec里存放的未执行的第二阶段消息
                                    let shared_revoke_mta_shared_message = shared_revoke_mta_shared_message_clone.clone();
                                    let revoke_mta_shared_message = shared_revoke_mta_shared_message.lock().await;

                                    match revoke_mta_shared_message.shared_message_map.get(&user_id) {
                                        None=>{

                                        }
                                        _=>{
                                            if !revoke_mta_shared_message.shared_message_map.get(&user_id).unwrap().is_empty() {
                                                for mta_msg in revoke_mta_shared_message.shared_message_map.get(&user_id).unwrap() {
                                                    let revoke_mta_two_str = revoke_to_gstbk(gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg(locked_node.revoke_phase_one_mta_two( &mta_msg,&MTATag::Mta_B)));
                                                    match to_node(&revoke_mta_two_str, &mta_msg.sender,locked_node.node_info_vec.as_ref().unwrap()).await 
                                                    {
                                                        Ok(_) => {
                                                            info!("NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg have sent to {} about user {}",&mta_msg.sender,mta_msg.user_id);
                                                        }       
                                                        Err(e) => 
                                                        {
                                                            error!("Error: {}, NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg can not send ",e);
                                                            return ;
                                                        }
                                                    };
                                                }
                                            }
                                        }
                                    }    
                                    
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::RevokeMsg::ProxyToNodesRevokePhaseTwoBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesRevokePhaseTwoBroadcastMsg about user {}",msg.user_id); 
                                    let mut locked_node = node.lock().await; 
                                    let revoke_flag_str = revoke_to_gstbk(gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToProxyRevokePhaseTwoFlag(locked_node.revoke_phase_two(&msg)));
                                    match p2p(&revoke_flag_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("NodeToProxyRevokePhaseTwoFlag has sent about user {}",msg.user_id)
                                        }
                                        Err(e) =>  
                                        {
                                            error!("Error: {}, NodeToProxyRevokePhaseTwoFlag can not send ",e);
                                            return ;
                                        }
                                    };
                                }  
                                _ => {}
                            }
                        }
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::VerifyMsg(verify_msg) => 
                        {
                            match verify_msg  
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::VerifyMsg::ProxyToNodesVerifyPhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesVerifyPhaseBroadcastMsg about user {}",msg.user_id);
                                    let mut locked_node = node.lock().await;
                                    if locked_node.verify_phase(&msg).is_ok() 
                                    {
                                        info!("User : {} has verified",msg.user_id); 
                                    } 
                                    else 
                                    {
                                        let open_one_msg_str = open_to_gstbk(gs_tbk_scheme::messages::node::common_msg::OpenMsg::NodeToProxyOpenPhaseOneP2PMsg(locked_node.open_phase_one(&msg)));
                                        match p2p(&open_one_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                        {
                                            Ok(_) => {
                                                info!("NodeToProxyOpenPhaseOneP2PMsg has sent about {}",msg.user_id)
                                            } 
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeToProxyOpenPhaseOneP2PMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }
                                }
                            }
                        }
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::OpenMsg(open_msg) =>  
                        {
                            match open_msg 
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::OpenMsg::ProxyToNodesOpenPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseOneBroadcastMsg about user {}",msg.user_id);
                                    let locked_node = node.lock().await;
                                    let open_two_msg_str = open_to_gstbk(gs_tbk_scheme::messages::node::common_msg::OpenMsg::NodeToProxyOpenPhaseTwoP2PMsg(locked_node.open_phase_two(&msg)));
                                    match p2p(&open_two_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("NodeToProxyOpenPhaseTwoP2PMsg has sent about {}",msg.user_id)
                                        }
                                        Err(e) => 
                                        
                                        {
                                            error!("Error: {}, NodeToProxyOpenPhaseTwoP2PMsg can not send ",e);
                                            return ;
                                        }
                                    };
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::OpenMsg::ProxyToNodesOpenPhaseTwoBroadcastMsg(msg) => {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodesOpenPhaseTwoBroadcastMsg about user {}", msg.user_id);
                                    let locked_node = node.lock().await;
                                    locked_node.open_phase_three(&msg);
                                }
                            }
                        }
                        gs_tbk_scheme::messages::proxy::common_msg::GSTBKMsg::KeyManageMsg(key_manage_msg) =>
                        {
                            match key_manage_msg
                            {
                                gs_tbk_scheme::messages::proxy::common_msg::KeyManageMsg::ProxyToNodeKeyRocoverPhaseStartFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodeKeyRocoverPhseStartFlag");
                                    let mut locked_node = node.lock().await;
                                    let key_recover_phase_msg_str = key_manage_to_gstbk(KeyManageMsg::NodeToProxyKeyRecoverP2PMsg(locked_node.key_recover_phase()));
                                    match p2p(&key_recover_phase_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("NodeToProxyKeyRecoverP2PMsg has sent")
                                        }
                                        Err(e) => 
                                        { 
                                            error!("Error:{}, NodeToProxyKeyRecoverP2PMsg can not send",e);
                                            return ;
                                        }
                                    };
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::KeyManageMsg::ProxyToNodeKeyRefreshPhaseStartFlag(msg) =>
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodeKeyRefreshPhaseStartFlag");
                                    let mut locked_node = node.lock().await;
                                    let key_refresh_msg_map_str = key_manage_to_gstbk(KeyManageMsg::NodeToProxyKeyRefreshOneP2PMsg(locked_node.key_refresh_phase_one(msg.dkgtag)));
                                    match p2p(&key_refresh_msg_map_str, &(*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {
                                            info!("NodeToProxyKeyRefreshOneP2PMsg has sent")
                                        }
                                        Err(e) => 
                                        { 
                                            error!("Error:{}, NodeToProxyKeyRefreshOneP2PMsg can not send",e);
                                            return ;
                                        }
                                    };
                                }
                                gs_tbk_scheme::messages::proxy::common_msg::KeyManageMsg::ProxyToNodeKeyRefreshPhaseTwoP2PMsg(msg) =>
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodeKeyRefreshPhaseTwoP2PMsg");
                                    let mut locked_node = node.lock().await;
                                    locked_node.key_refresh_phase_three(msg).unwrap();
                                }

                            }
                        }
                    }
                }
                GSTBKMsg::GSTBKMsgN(gstbk_node_msg) => 
                {
                    match gstbk_node_msg
                    {
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg 
                            {
                                gs_tbk_scheme::messages::node::common_msg::KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {} ,Taget : {:?} Get NodeKeyGenPhaseOneBroadcastMsg ",msg.sender,msg.role,msg.dkgtag);
                                    let mut locked_node = node.lock().await;
                                    match msg.dkgtag{
                                        DKGTag::Gamma_A => 
                                        {
                                            let mut locked_vec = keygen_phase_one_msg_vec_A.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                            {
                                                let vec = &(*locked_vec);
                                                let keygen_phase_two_msg = match locked_node.keygen_phase_two(vec) 
                                                {
                                                    Ok(v) => v,
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, can not get NodeToProxyKeyGenPhaseTwoP2PMsg_A ",e);
                                                        return ;
                                                    }
                                                };
                                                let keygen_phase_two_msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(
                                                    gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyGenMsg(gs_tbk_scheme::messages::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseTwoP2PMsg(keygen_phase_two_msg))
                                                )).unwrap();
                                                match p2p(&keygen_phase_two_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                                {
                                                    Ok(_) => {
                                                        info!("NodeToProxyKeyGenPhaseTwoP2PMsg_A has sent")
                                                    }
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, NodeToProxyKeyGenPhaseTwoP2PMsg_A can not send",e);
                                                        return ;
                                                    }
                                                };
                                            }
                                        }
                                        DKGTag::Gamma_B => 
                                        {
                                            let mut locked_vec = keygen_phase_one_msg_vec_B.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                            {
                                                let vec = &(*locked_vec);
                                                let keygen_phase_two_msg = match locked_node.keygen_phase_two(vec) 
                                                {
                                                    Ok(v) => v,
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, can not get NodeToProxyKeyGenPhaseTwoP2PMsg_B ",e);
                                                        return ;
                                                    }
                                                };
                                                let keygen_phase_two_msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(
                                                    gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyGenMsg(gs_tbk_scheme::messages::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseTwoP2PMsg(keygen_phase_two_msg))
                                                )).unwrap();
                                                match p2p(&keygen_phase_two_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                                {
                                                    Ok(_) => {
                                                        info!("NodeToProxyKeyGenPhaseTwoP2PMsg_B has sent")
                                                    }
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, NodeToProxyKeyGenPhaseTwoP2PMsg_B can not send",e);
                                                        return ;
                                                    }
                                                };
                                            }
                                        }
                                        DKGTag::Gamma_O => 
                                        {
                                            let mut locked_vec = keygen_phase_one_msg_vec_O.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                            {
                                                let vec = &(*locked_vec);
                                                let keygen_phase_two_msg = match locked_node.keygen_phase_two(vec) 
                                                {
                                                    Ok(v) => v,
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, can not get NodeToProxyKeyGenPhaseTwoP2PMsg_O ",e);
                                                        return ;
                                                    }
                                                };
                                                let keygen_phase_two_msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(
                                                    gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyGenMsg(gs_tbk_scheme::messages::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseTwoP2PMsg(keygen_phase_two_msg))
                                                )).unwrap();
                                                match p2p(&keygen_phase_two_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                                {
                                                    Ok(_) => {
                                                        info!("NodeToProxyKeyGenPhaseTwoP2PMsg_O has sent")
                                                    }
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, NodeToProxyKeyGenPhaseTwoP2PMsg_O can not send",e);
                                                        return ;
                                                    }
                                                };
                                            }
                                        }
                                        DKGTag::Gamma_C => 
                                        {
                                            let mut locked_vec = keygen_phase_one_msg_vec_C.lock().await;
                                            locked_vec.push(msg);
                                            if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                            {
                                                let vec = &(*locked_vec);
                                                let keygen_phase_two_msg = match locked_node.keygen_phase_two(vec) 
                                                {
                                                    Ok(v) => v,
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, can not get NodeToProxyKeyGenPhaseTwoP2PMsg_C ",e);
                                                        return ;
                                                    }
                                                };
                                                let keygen_phase_two_msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(
                                                    gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyGenMsg(gs_tbk_scheme::messages::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseTwoP2PMsg(keygen_phase_two_msg))
                                                )).unwrap();
                                                match p2p(&keygen_phase_two_msg_str, &(*locked_node.proxy_address).to_string()).await 
                                                {
                                                    Ok(_) => {
                                                        info!("NodeToProxyKeyGenPhaseTwoP2PMsg_C has sent")
                                                    }
                                                    Err(e) => 
                                                    {
                                                        error!("Error:{}, NodeToProxyKeyGenPhaseTwoP2PMsg_C can not send",e);
                                                        return ;
                                                    }
                                                };
                                            }
                                        }
                                    }
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
                                gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {}  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg about user {}",msg.sender,msg.role,msg.user_id);
                                    let mut locked_node = node.lock().await;
                                    let shared_join_mta_shared_message = shared_join_mta_shared_message_clone.clone();
                                    let mut join_mta_shared_message = shared_join_mta_shared_message.lock().await;
                                    if !join_mta_shared_message.shared_message_map.contains_key(&msg.user_id){
                                        join_mta_shared_message.shared_message_map.insert(msg.user_id, Vec::<NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg>::new());
                                    }
                                    let shared_join_mta_tag = shared_join_mta_tag_clone.clone();
                                    let mut mta_tag = shared_join_mta_tag.lock().await;
                                    if !mta_tag.tag_map.contains_key(&msg.user_id){ // 说明二阶段的信息先到，标志位置为false，然后把消息放进去
                                        mta_tag.tag_map.insert(msg.user_id, false);
                                        join_mta_shared_message.shared_message_map.get_mut(&msg.user_id).unwrap().push(msg);

                                    }else{
                                        if mta_tag.tag_map.get(&msg.user_id).unwrap() == &true {// 代表第一阶段已经执行，那么直接执行第二阶段
                                            
                                            let join_mta_two_str = join_issue_to_gstbk(gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg(locked_node.join_issue_phase_two_mta_two( &msg,&MTATag::Mta_A)));
                                            match to_node(&join_mta_two_str, &msg.sender,locked_node.node_info_vec.as_ref().unwrap()).await 
                                            {
                                                Ok(_) => 
                                                {
                                                    info!("NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg sent to {} about user {}",msg.sender,msg.user_id);
                                                }
                                                Err(e) => 
                                                {
                                                    error!("Error: {}, NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg can not send ",e);
                                                    return ;
                                                }
                                            };
                                        }else{// 说明第二条二阶段消息来的时候第一阶段的消息还是没到，则直接把消息丢进去
                                            join_mta_shared_message.shared_message_map.get_mut(&msg.user_id).unwrap().push(msg);
                                        }
                                        
                                    }

                                    
                                }
                                gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {}  Get NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg about user {}",msg.sender,msg.role,msg.user_id);
                                    
                                    let mut locked_node = node.lock().await;
                                    locked_node.join_issue_phase_two_mta_three(&msg, &MTATag::Mta_A);

                                    let join_mta_two_map = join_mta_two_map_clone.clone();
                                    let mut locked_join_mta_two_map = join_mta_two_map.lock().await;
                                    if !locked_join_mta_two_map.contains_key(&msg.user_id) 
                                    {
                                        locked_join_mta_two_map.insert(msg.user_id, Vec::<NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg>::new());
                                    }
                                    let locked_revoke_mta_two_vec = locked_join_mta_two_map.get_mut(&msg.user_id).unwrap();
                                    locked_revoke_mta_two_vec.push(msg.clone());
                                    
                                    if locked_revoke_mta_two_vec.len() == locked_node.participants.as_ref().unwrap().len()-1
                                    {
                                        let join_mta_two_str = join_issue_to_gstbk(gs_tbk_scheme::messages::node::common_msg::JoinIssueMsg::NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg(locked_node.join_issue_phase_two_final(&msg, &MTATag::Mta_A)));
                                        match p2p(&join_mta_two_str, &(*locked_node.proxy_address).to_string()).await 
                                        {
                                            Ok(_) => 
                                            {
                                                info!("NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg have sent to proxy about user {}",locked_revoke_mta_two_vec[0].user_id);
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                        locked_revoke_mta_two_vec.clear(); 
                                    }
                                }
                                _ => {}
                            }
                        }
                        gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::RevokeMsg(revoke_msg) => 
                        {
                            match revoke_msg 
                            {
                                gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {}  Get NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg about user {}",msg.sender,msg.role,msg.user_id);
                                    let mut locked_node = node.lock().await;
                                    let shared_revoke_mta_shared_message = shared_revoke_mta_shared_message_clone.clone();
                                    let mut revoke_mta_shared_message = shared_revoke_mta_shared_message.lock().await;
                                    if !revoke_mta_shared_message.shared_message_map.contains_key(&msg.user_id){
                                        revoke_mta_shared_message.shared_message_map.insert(msg.user_id, Vec::<NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg>::new());
                                    }

                                    let shared_revoke_mta_tag = shared_revoke_mta_tag_clone.clone();
                                    let mut mta_tag = shared_revoke_mta_tag.lock().await;
                                    if !mta_tag.tag_map.contains_key(&msg.user_id){
                                        mta_tag.tag_map.insert(msg.user_id, false);
                                        revoke_mta_shared_message.shared_message_map.get_mut(&msg.user_id).unwrap().push(msg);

                                    }else{
                                        if mta_tag.tag_map.get(&msg.user_id).unwrap() == &true {
                                            
                                            let revoke_mta_two_str = revoke_to_gstbk(gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg(locked_node.revoke_phase_one_mta_two( &msg,&MTATag::Mta_B)));
                                            match to_node(&revoke_mta_two_str, &msg.sender,locked_node.node_info_vec.as_ref().unwrap()).await 
                                            {
                                                Ok(_) => {
                                                    info!("NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg have sent to {} about user {}",&msg.sender,msg.user_id);
                                                }       
                                                Err(e) => 
                                                {
                                                    error!("Error: {}, NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg can not send ",e);
                                                    return ;
                                                }
                                            };
                                        }else{
                                            revoke_mta_shared_message.shared_message_map.get_mut(&msg.user_id).unwrap().push(msg);
                                        }
                                        
                                    }
                                }
                                gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {}  Get NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg about user {}",msg.sender,msg.role,msg.user_id);  
                                    let mut locked_node = node.lock().await;
                                    locked_node.revoke_phase_one_mta_three(msg.clone(), &MTATag::Mta_B); 
                                    let shared_revoke_mta_two_map = shared_revoke_mta_two_map_clone.clone();
                                    let mut locked_revoke_mta_two_map = shared_revoke_mta_two_map.lock().await;
                                    if !locked_revoke_mta_two_map.contains_key(&msg.user_id) 
                                    {
                                        locked_revoke_mta_two_map.insert(msg.user_id, Vec::<NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg>::new());
                                    }
                                    let locked_revoke_mta_two_vec = locked_revoke_mta_two_map.get_mut(&msg.user_id).unwrap();
                                    locked_revoke_mta_two_vec.push(msg.clone());
                                    
                                    if locked_revoke_mta_two_vec.len() ==  locked_node.participants.as_ref().unwrap().len()-1 
                                    {
                                        // info!("current revoke mta number of message is {} about user {}",locked_revoke_mta_two_vec.len(),locked_revoke_mta_two_vec[0].user_id);
                                        let revoke_mta_two_str = revoke_to_gstbk(gs_tbk_scheme::messages::node::common_msg::RevokeMsg::NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg(locked_node.revoke_phase_one_final(&msg, &MTATag::Mta_B)));
                                        match p2p(&revoke_mta_two_str, &(*locked_node.proxy_address).to_string()).await 
                                        {
                                            Ok(_) => {
                                                info!("NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg have sent to proxy about user {}",locked_revoke_mta_two_vec[0].user_id);
                                            }
                                            Err(e) =>  
                                            {
                                                error!("Error: {}, NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                        locked_revoke_mta_two_vec.clear();
                                    }
                                }
                                _ => {

                                }
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