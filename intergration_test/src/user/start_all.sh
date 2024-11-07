#!/bin/bash

current_path=$(pwd)

folder_num=$(ls -lA | grep "^d" | wc -l)

cd "$current_path"

for ((i=1;i<=folder_num;i++)); do 
    
    xterm -hold -e "cargo 'test' '--package' 'intergration_test' '--lib' '--' 'user::user$i::user$i::test' '--exact' '--nocapture'" &
     
    sleep 1

done

wait


