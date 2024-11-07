use std::collections::HashMap;
use std::error::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use proxy::proxy::Proxy;
use proxy::config::config::Config;

pub fn main()
{
// Init and build communication

// Setup phase
    // maintain communication
    let mut communication_map:HashMap<u16, TcpStream> = HashMap::new();
    // Initialize Proxy 
        // Loading configuration
    //println!("{:?}",std::env::current_dir());
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/proxy/src/config/config_files/gs_tbk_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let proxy = Proxy::init(gs_tbk_config);
    println!("{:?}",proxy);
    // recieve msg, assign id for every Node and p2p send NodeSetupInfoMsg to Node 
     
     
    // Build tree and send it to all Nodes
    


// Keygen phase

// join and issue phase

// sign phase

// verify phase

// revoke phase

// open phase

}

#[test]
fn test_load_config() 
{
    println!("{:?}",std::env::current_dir().unwrap().as_path().to_str().unwrap().to_owned()+"/src/config/config_files/gs_tbk_config.json");
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/config/config_files/gs_tbk_config.json";
    println!("{:?}",Config::load_config(&gs_tbk_config_path));
    
}