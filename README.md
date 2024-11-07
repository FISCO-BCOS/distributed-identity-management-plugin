# distributed-identity-management-plugin

本文档主要讲述在多个服务器上通过编译源码安装 FISCO BCOS 网络，并在该链上部署多个智能合约，实现分布式身份管理系统

## 1. 安装依赖

安装gcc/g++，make，rust，gmp

`sudo apt-get install -y gcc-g++ make rust libgmp-dev pari-go bison libclang-dev `



## 2. 搭建四节点BCOS区块链网络

参考FISCO BCOS官方文档()[]



## 3. 下载 & 编译源码

**下载分布式身份管理插件源代码**

`git clone https://github.com/FISCO-BCOS/distributed-identity-management-plugin.git`

**编译源码**

`cd distributed-identity-management-plugin`

`cargo build`

耐心等待几分钟，等待编译完成



## 4. 配置

#### 4.1 配置代理节点

`vim ./proxy/src/config/config_files/gs_tbk_config.json`

如下所示：

`````` 
{
 "listen_addr":"0.0.0.0:50000", # 本地监听端口
 "proxy_addr":"127.0.0.1:50000", # 配置代理节点的通信IP
 "threshold_params":{
 "threshold":2, # 配置门限信息
 "share_counts":4 # 配置区块链节点数量
 }
}

``````



#### 4.2 配置区块链节点

`vim ./node/src/config/config_files/gs_tbk_config.json`

如下所示：

`````` 
{
 "listen_addr":"0.0.0.0:50000", # 本地监听端口
 "proxy_addr":"127.0.0.1:50000", # 配置代理节点的通信IP
 "node_addr":"127.0.0.1:50001", # 配置区块链节点自身的通信IP
 "threshold_params":{
 "threshold":2, # 配置门限信息
 "share_counts":4 # 配置区块链节点数量
 }
}

``````

#### 4.3 配置客户端

`vim ./node/src/config/config_files/gs_tbk_config.json`

如下所示：

`````` 
{
 "listen_addr":"0.0.0.0:60000", # 本地监听端口
 "proxy_addr":"127.0.0.1:50000", # 配置代理节点的通信IP
 "user_addr":"127.0.0.1:60001", # 配置区块链节点自身的通信IP
 "name": "user_name" # 配置用户名
}

``````



#### 4.4 配置用户密钥过期时间

`vim ./gs_tbk_scheme/src/tree.rs`

找到下面内容：

```
pub fn set_time(tree_vec:&mut Vec<TreeNode>,level:usize) {
	let num_leaf = pow(2, level-1);
    let mut first_leaf_order = pow(2, level-1);
    for i in 1..num_leaf {
        let final_time = Local::now() + i * StdDuration::from_secs(130);
        tree_vec[first_leaf_order].tau.realtime = final_time.format("%Y-%m-%d %H:%M:%S").to_string();
        //println!("{:?}",tree_vec[first_leaf_order]);
        first_leaf_order += 1;
    }
}
```

修改`from_secs(130)`中130，即可完成用户时间期限修改，单位是秒



## 5. 连接

#### 5.1 启动代理节点

运行`cargo test --package intergration_test --lib -- proxy::proxy_node::test --exact --nocapture`，启动代理节点

#### 5.2 启动四个区块链节点

在四个节点的源目录下运行：`cargo test --package intergration_test --lib -- node::node1::node1::test --exact --nocapture`，启动区块链节点分布式身份管理插件。

在`./intergration_test/src/node/node1/info`下生成keygen.json文件。

终端输出`Keygen phase is finished！`，表示各区块链节点的阈值密钥生成完毕，可进行后续用户注册和签名上链步骤。

#### 5.3 启动用户端

在用户端的源目录下运行：`cargo test --package intergration_test --lib -- user::user1::user1::test --exact --nocapture`，启动用户节点，发起注册请求，并自动对消息进行签名上链。如果签名信息验证失败，自动完成用户身份揭露。

















