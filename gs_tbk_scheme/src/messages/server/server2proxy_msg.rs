use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerToProxySignMsg{
    pub role : String,
    pub user : u16, 
    //pub order : String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerToProxyJoinMsg {
    pub role : String,
    pub user : u16, 
    //pub order : String
}