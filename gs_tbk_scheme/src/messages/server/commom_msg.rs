use serde::{Deserialize, Serialize};

use crate::messages::server::server2proxy_msg::{ServerToProxySignMsg,ServerToProxyJoinMsg};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    JoinIssueMsg(JoinIssueMsg),
    SignMsg(SignMsg)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinIssueMsg{
    ServerToProxyJoinMsg(ServerToProxyJoinMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignMsg{
    ServerToProxySignMsg(ServerToProxySignMsg)
}