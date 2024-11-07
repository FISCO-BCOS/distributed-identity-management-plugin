use serde::{Deserialize, Serialize};

use crate::messages::node::setup_msg::{NodeToProxySetupPhaseP2PMsg, NodeSetupPhaseFinishFlag};
use crate::messages::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg,NodeToProxyKeyGenPhaseTwoP2PMsg,NodeToProxyKeyGenPhaseFiveP2PMsg};
use crate::messages::node::join_issue_msg::{
    NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg,
    NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg,
    NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg,
    NodeToProxyJoinIssuePhaseThreeP2PMsg,
    NodeToProxyJoinIssuePhaseFourP2PMsg,
    NodeToProxyJoinIssuePhaseFlag
};
use crate::messages::node::revoke_msg::{NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg,NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg,NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg,NodeToProxyRevokePhaseTwoFlag};
use crate::messages::node::open_msg::{NodeToProxyOpenPhaseOneP2PMsg,NodeToProxyOpenPhaseTwoP2PMsg};
use crate::messages::node::key_manage_msg::{NodeToProxyKeyRecoverP2PMsg, NodeToProxyKeyRefreshOneP2PMsg};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
    JoinIssueMsg(JoinIssueMsg),
    RevokeMsg(RevokeMsg),
    OpenMsg(OpenMsg),
    KeyManageMsg(KeyManageMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    NodeToProxySetupPhaseP2PMsg(NodeToProxySetupPhaseP2PMsg),
    NodeSetupPhaseFinishFlag(NodeSetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    NodeKeyGenPhaseOneBroadcastMsg(NodeKeyGenPhaseOneBroadcastMsg),
    NodeToProxyKeyGenPhaseTwoP2PMsg(NodeToProxyKeyGenPhaseTwoP2PMsg),
    NodeToProxyKeyGenPhaseFiveP2PMsg(NodeToProxyKeyGenPhaseFiveP2PMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinIssueMsg
{
    NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg(NodeToNodeJoinIssuePhaseTwoMtAPhaseOneP2PMsg),
    NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg(NodeToNodeJoinIssuePhaseTwoMtAPhaseTwoP2PMsg),
    NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg(NodeToProxyJoinIssuePhaseTwoMtAPhaseFinalP2PMsg),
    NodeToProxyJoinIssuePhaseThreeP2PMsg(NodeToProxyJoinIssuePhaseThreeP2PMsg),
    NodeToProxyJoinIssuePhaseFourP2PMsg(NodeToProxyJoinIssuePhaseFourP2PMsg),
    NodeToProxyJoinIssuePhaseFlag(NodeToProxyJoinIssuePhaseFlag),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RevokeMsg {
    NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg(NodeToNodeRevokePhaseOneMtAPhaseOneP2PMsg),
    NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg(NodeToNodeRevokePhaseOneMtAPhaseTwoP2PMsg),
    NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg(NodeToProxyRevokePhaseTwoMtAPhaseFinalP2PMsg),
    NodeToProxyRevokePhaseTwoFlag(NodeToProxyRevokePhaseTwoFlag)
    
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OpenMsg {
    NodeToProxyOpenPhaseOneP2PMsg(NodeToProxyOpenPhaseOneP2PMsg),
    NodeToProxyOpenPhaseTwoP2PMsg(NodeToProxyOpenPhaseTwoP2PMsg) 
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyManageMsg 
{
    NodeToProxyKeyRecoverP2PMsg(NodeToProxyKeyRecoverP2PMsg),
    NodeToProxyKeyRefreshOneP2PMsg(NodeToProxyKeyRefreshOneP2PMsg)
}