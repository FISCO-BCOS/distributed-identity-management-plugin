#!/bin/bash

t=2
n=4

current_path=$(pwd)

folder_num=$(ls -lA | grep "^d" | wc -l)

for ((i=1; i<=folder_num; i++)); do
    config_file="$current_path/node$i/config/config_file/node_config.json"
    
    # 临时文件
    tmp_file="$config_file.tmp"
    
    # 修改 threshold 字段
    sed -e "s/\"threshold\":.*/\"threshold\":$t,/" "$config_file" > "$tmp_file"
    
    # 修改 share_counts 字段
    sed -e "s/\"share_counts\":.*/\"share_counts\":$n/" "$tmp_file" > "$config_file"
    
    # 删除临时文件
    rm "$tmp_file"
done