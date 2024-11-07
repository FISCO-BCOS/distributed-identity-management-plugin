use serde::{Deserialize, Serialize};
use crate::messages::proxy::common_msg::GSTBKMsg as GSTBKMsgP;
use crate::messages::node::common_msg::GSTBKMsg as GSTBKMsgN;
use crate::messages::user::common_msg::GSTBKMsg as GSTBKMsgU;

#[derive(Clone, Debug, Serialize, Deserialize)]

pub enum GSTBKMsg {
    GSTBKMsgN(GSTBKMsgN),
    GSTBKMsgP(GSTBKMsgP),
    GSTBKMsgU(GSTBKMsgU)
}