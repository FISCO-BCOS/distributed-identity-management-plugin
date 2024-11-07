#!/bin/bash

#ip=101.42.36.111:50000
ip=47.103.64.123:50000
#ip=127.0.0.1:50000

current_path=$(pwd)

folder_num=$(ls -lA | grep "^d" | wc -l)

for ((i=1;i<=folder_num;i++)); do

	sed -i "2s/.*/    \"proxy_addr\":\"$ip\",/" "$current_path/node$i/config/config_file/node_config.json"
done
