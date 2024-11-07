#!/bin/bash

# 当前目录为 user 目录
current_dir=$(pwd)

# 遍历当前目录下的所有子目录
for user_dir in */; do
    # 检查是否为目录
    if [ -d "$user_dir" ]; then
        # 配置文件路径
        config_file="${user_dir}config/config_file/user_config.json"
        
        # 检查配置文件是否存在
        if [ -f "$config_file" ]; then
            # 读取文件内容
            json_content=$(cat "$config_file")

            # 提取 name 标签的值
            name=$(echo "$json_content" | jq -r '.name')

            # 提取前缀和数字部分
            prefix=$(echo "$name" | sed -E 's/(.*_)[0-9]+/\1/')
            number=$(echo "$name" | sed -E 's/.*_([0-9]+)/\1/')

            # 修改数字部分（例如，增加1）
            new_number=$((number + 1))

            # 重新拼接新的 name
            new_name="${prefix}${new_number}"

            # 更新 JSON 内容
            new_json_content=$(echo "$json_content" | jq --arg new_name "$new_name" '.name = $new_name')

            # 将更新后的内容写回文件
            echo "$new_json_content" > "$config_file"

            echo "Updated name in $config_file to: $new_name"
        else
            echo "Config file not found: $config_file"
        fi
    fi
done