#!/bin/bash

#获取当前路径

current_path=$(pwd)

#文件夹前缀
folder_prefix="user"

cd "$current_path"

folder_count=$(ls -lA | grep "^d" | wc -l)

#生成文件夹数量
folder_num=$((1 + folder_count))

#log4rs.yaml要修改的行
line1=6

#echo "num is $folder_num"


for ((i=$((folder_count + 1));i<=folder_num;i++)); 
do
	folder_name="${folder_prefix}$i"
	mkdir "$folder_name" 
	cd "$folder_name"
	mkdir "config"
	cd "config"
	mkdir "config_file"
	cd ..
	cp "$current_path/user1/config/config_file/log4rs.yaml" "$current_path/$folder_name/config/config_file"
	sed -i "s/user1/user$i/g" "$current_path/$folder_name/config/config_file/log4rs.yaml"
	cp "$current_path/user1/config/config_file/user_config.json" "$current_path/$folder_name/config/config_file"
	if [ "$i" -gt 9 ]; then
    		sed -i "s/60001/600$i/g" "$current_path/$folder_name/config/config_file/user_config.json"
	elif [ "$i" -gt 99 ]; then
    		sed -i "s/60001/60$i/g" "$current_path/$folder_name/config/config_file/user_config.json"
	elif [ "$i" -gt 999 ]; then
    		sed -i "s/60001/6$i/g" "$current_path/$folder_name/config/config_file/user_config.json"
    	else 
    		sed -i "s/60001/6000$i/g" "$current_path/$folder_name/config/config_file/user_config.json"
	fi
	sed -i "s/user1/user$i/g" "$current_path/$folder_name/config/config_file/user_config.json"

	mkdir "info"
	cp "$current_path/user1/info/join.json" "$current_path/$folder_name/info"
	mkdir "logs"
	cp "$current_path/user1/logs/user.log" "$current_path/$folder_name/logs"
	touch "mod.rs"
	echo "pub mod user$i;" >> "mod.rs"
	echo "pub mod user$i;" >> "$current_path/mod.rs"
	cp "$current_path/user1/user1.rs" "$current_path/$folder_name/user$i.rs"
	sed -i "s/user1/user$i/g" "$current_path/$folder_name/user$i.rs"
	sleep 1
done
