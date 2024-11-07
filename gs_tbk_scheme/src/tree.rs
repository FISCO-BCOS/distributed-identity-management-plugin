use std::{collections::HashMap, str::Bytes, fmt::Debug};
use chrono::{DateTime,Local,Duration,NaiveDateTime};
use std::time::Duration as StdDuration;
use serde::{Deserialize, Serialize};
use log::{error, info, warn};
use log4rs;
use std::sync::{Arc, RwLock};
use std::env;

use curv::{elliptic::curves::{Scalar, Bls12_381_1}, BigInt};
use num::pow;

use crate::clgroup_gen::new;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tau
{
    pub scalar:Scalar<Bls12_381_1>,
    pub realtime:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeNode
{
    pub id:usize,
    pub scalar:Scalar<Bls12_381_1>,
    pub tau:Tau,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tree{
    pub level:usize,
    pub tree: Vec<TreeNode>,
}
impl Tree {
    /// 初始化树
    pub fn build_tree(level: usize) -> Tree {

        let num = pow(2, level)-1;
        let mut tree_vec: Vec<TreeNode>= Vec::new();
        let mut i: usize = 1;
    
        while i <= num {
            tree_vec.push(
                TreeNode 
                { 
                    id:i, 
                    scalar:Scalar::<Bls12_381_1>::random(), 
                    tau:Tau
                        {
                            scalar: Scalar::<Bls12_381_1>::random(), 
                            realtime: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        }
                }
                
            );
            i += 1;
        }
        Tree::set_time(&mut tree_vec,level);
        Tree { level:level,tree: tree_vec }
     
    }

    /// 为每一个叶子节点赋时间
    pub fn set_time(tree_vec:&mut Vec<TreeNode>,level:usize) {
        let num_leaf = pow(2, level-1);
        let mut first_leaf_order = pow(2, level-1);
        for i in 1..num_leaf {
            let final_time = Local::now() + i * StdDuration::from_secs(130);
            tree_vec[first_leaf_order].tau.realtime = final_time.format("%Y-%m-%d %H:%M:%S").to_string();
            //println!("{:?}",tree_vec[first_leaf_order]);
            first_leaf_order += 1;
        }
        //println!("################################");
    }

    /// 获取所有叶子节点
    pub fn get_leaf_nodes(&self)->Vec<TreeNode>
    {
        let first_leaf_order = pow(2, self.level-1);
        self.tree[first_leaf_order..].to_vec()
    }

    /// 为用户选择叶子节点，默认从第二个叶子节点开始，一个用户依次一个
    pub fn choose_leaf(&self,id:usize)->TreeNode
    {
        let first_leaf_node_id = pow(2, self.level - 1);
        self.tree[first_leaf_node_id + id-1].clone() 
    }

    /// 获取从指定节点到根节点的路径上的所有节点
    pub fn path(&self, id: usize) -> Vec<TreeNode> {
    
        let mut index  = id;
        let mut path_node_vec: Vec<TreeNode> = Vec::new();
        //from leaf node to root
        while index > 0 {
            path_node_vec.push(self.tree[index-1].clone());
            index /= 2;
        }
        
       path_node_vec
    }
    
    /// cstbk算法，获取右子树节点
    pub fn cstbk(&self, id: usize) -> Vec<TreeNode> {
        let leaf_index = id;
        //If id is the first leaf node
        let index = if leaf_index == (self.tree.len()+1)/2 
        {
            leaf_index
        }
        else
        {
            leaf_index-1
        };
        
        let mut path_node_vec = self.path(index);
        let mut cstbk_node_vec: Vec<TreeNode> = Vec::new();
        while !path_node_vec.is_empty(){
            let node_index: usize = path_node_vec.pop().unwrap().id;
            if node_index % 2 == 0 {
                cstbk_node_vec.push(self.tree[node_index].clone());
            }
        }
    
        cstbk_node_vec
    }

}



#[test]
fn test() {

    if let Ok(current_dir) = env::current_dir() {
        println!("Current directory: {:?}", current_dir);
    } else {
        println!("Failed to get current directory");
    }
    // 初始化log4rs
    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

    // 记录一些日志消息
    info!("This is an info message");
    warn!("This is a warn message");
    error!("This is an error message");


    
    // println!("{:?}", tree);
    // println!("-------------------------------------------------------------");
    // println!("{:?}", tree.path(11));
    
    // println!("-------------------------------------------------------------");
    // println!("{:?}", tree.cstbk(10));
    
}