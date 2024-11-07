use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use curv::elliptic::curves::{Point, Bls12_381_1, Bls12_381_2, Scalar};

use node::config::config::Config;
use node::node::Node;
use gs_tbk_scheme::messages::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg};
//use gs_tbk_scheme::messages::common_msg::{KeyGenMsg};

pub fn main(){   
// Setup phase
    // maintain communication
    //let mut communication_map:HashMap<u16, TcpStream> = HashMap::new();
    // Initialize Node info 
        // Load configuration
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/node/src/config/config_files/gs_tbk_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    //println!("666");

    let node = Node::init(gs_tbk_config);
    println!("{:?}",node);
    
    // Connect Proxy and send PK and listen address to it, meanwhile, insert handle to hashmap
    //let node_setup_msg = node.setup_phase_one();
    
    // Recieve Msg and store it

    // Connect to all Nodes

    // Recieve tree and store it



// Keygen phases
    // one
        // y_i -> y_vec needs sort by id
        let mut y_map:HashMap<u16, Point<Bls12_381_1>> = HashMap::new();
        // 发送消息的时候需要用枚举封装一下

    // two
        // collet all commitments and share


    // three

    // four


// join and issue phase

// sign phase

// verify phase

// revoke phase

// open phase

}

#[test]
fn test()
{
    
}