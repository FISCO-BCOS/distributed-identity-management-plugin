use serde::{Deserialize, Serialize};

use crate::messages::proxy::setup_msg::{ProxySetupPhaseBroadcastMsg,ProxySetupPhaseFinishFlag};
use crate::messages::proxy::keygen_msg::{ProxyKeyGenPhaseOneBroadcastMsg,ProxyToNodeKeyGenPhaseThreeP2PMsg,ProxyKeyGenPhaseStartFlag,ProxyToNodesKeyGenPhasefiveBroadcastMsg};
use crate::messages::proxy::join_issue_msg::{ProxyToNodesJoinIssuePhaseThreeBroadcastMsg,ProxyToUserJoinIssuePhaseOneP2PMsg,ProxyToNodesJoinIssuePhaseTwoBroadcastMsg,ProxyToUserJoinIssuePhaseThreeP2PMsg,ProxyToNodesJoinIssuePhaseFourBroadcastMsg,ProxyToNodesJoinIssuePhaseFiveBroadcastMsg};
use crate::messages::proxy::revoke_msg::{ProxyToNodesRevokePhaseOneBroadcastMsg,ProxyToNodesRevokePhaseTwoBroadcastMsg,ProxyToUserRevokePhaseBroadcastMsg};
use crate::messages::proxy::verify_msg::ProxyToNodesVerifyPhaseBroadcastMsg;
use crate::messages::proxy::open_msg::{ProxyToNodesOpenPhaseOneBroadcastMsg,ProxyToNodesOpenPhaseTwoBroadcastMsg};
use crate::messages::proxy::key_manage_msg::{ProxyToNodeKeyRefreshPhaseTwoP2PMsg,ProxyToNodeKeyRefreshPhaseStartFlag,ProxyToNodeKeyRocoverPhaseStartFlag};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
    JoinIssueMsg(JoinIssueMsg),
    RevokeMsg(RevokeMsg),
    VerifyMsg(VerifyMsg),
    OpenMsg(OpenMsg),
    KeyManageMsg(KeyManageMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    ProxySetupPhaseBroadcastMsg(ProxySetupPhaseBroadcastMsg), 
    ProxySetupPhaseFinishFlag(ProxySetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMSKFlag {
    GammaA(KeyGenMsg),
    GammaB(KeyGenMsg),
    GammaO(KeyGenMsg),
    GammaC(KeyGenMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    ProxyKeyGenPhaseStartFlag(ProxyKeyGenPhaseStartFlag),
    ProxyKeyGenPhaseOneBroadcastMsg(ProxyKeyGenPhaseOneBroadcastMsg),
    ProxyToNodeKeyGenPhaseThreeP2PMsg(ProxyToNodeKeyGenPhaseThreeP2PMsg),
    ProxyToNodesKeyGenPhasefiveBroadcastMsg(ProxyToNodesKeyGenPhasefiveBroadcastMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinIssueMsg {
    ProxyToUserJoinIssuePhaseOneP2PMsg(ProxyToUserJoinIssuePhaseOneP2PMsg),
    ProxyToNodesJoinIssuePhaseTwoBroadcastMsg(ProxyToNodesJoinIssuePhaseTwoBroadcastMsg),
    //ProxyToUserJoinIssuePhaseTwoP2PMsg(ProxyToUserJoinIssuePhaseTwoP2PMsg),
    ProxyToNodesJoinIssuePhaseThreeBroadcastMsg(ProxyToNodesJoinIssuePhaseThreeBroadcastMsg),
    ProxyToUserJoinIssuePhaseThreeP2PMsg(ProxyToUserJoinIssuePhaseThreeP2PMsg),
    ProxyToNodesJoinIssuePhaseFourBroadcastMsg(ProxyToNodesJoinIssuePhaseFourBroadcastMsg),
    ProxyToNodesJoinIssuePhaseFiveBroadcastMsg(ProxyToNodesJoinIssuePhaseFiveBroadcastMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RevokeMsg {
    ProxyToNodesRevokePhaseOneBroadcastMsg(ProxyToNodesRevokePhaseOneBroadcastMsg),
    ProxyToNodesRevokePhaseTwoBroadcastMsg(ProxyToNodesRevokePhaseTwoBroadcastMsg),
    ProxyToUserRevokePhaseBroadcastMsg(ProxyToUserRevokePhaseBroadcastMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VerifyMsg {
    ProxyToNodesVerifyPhaseBroadcastMsg(ProxyToNodesVerifyPhaseBroadcastMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OpenMsg {
    ProxyToNodesOpenPhaseOneBroadcastMsg(ProxyToNodesOpenPhaseOneBroadcastMsg),
    ProxyToNodesOpenPhaseTwoBroadcastMsg(ProxyToNodesOpenPhaseTwoBroadcastMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyManageMsg 
{
    ProxyToNodeKeyRocoverPhaseStartFlag(ProxyToNodeKeyRocoverPhaseStartFlag),
    ProxyToNodeKeyRefreshPhaseStartFlag(ProxyToNodeKeyRefreshPhaseStartFlag),
    ProxyToNodeKeyRefreshPhaseTwoP2PMsg(ProxyToNodeKeyRefreshPhaseTwoP2PMsg)    
}