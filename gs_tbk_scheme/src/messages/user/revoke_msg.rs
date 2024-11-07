use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokePhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}