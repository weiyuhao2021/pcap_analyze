#!/bin/bash

# 输入目录路径
path_input=$1
# 输出目录路径
path_output=$2

# 确保输出目录存在
if [ ! -d "$path_output" ]; then
  mkdir -p "$path_output"
fi

# 遍历输入目录中的所有.pcap文件
for filepath in "$path_input"/*.pcap
do
  # 提取文件名，不包含路径
  filename=$(basename -- "$filepath")
  # 去除文件扩展名，仅保留文件名
  basename="${filename%.*}"
  # 构建输出文件的完整路径
  output_filepath="$path_output/$basename.txt"
  # 执行转换命令
  ./mydump.out "$filepath" "$output_filepath"
done

echo "处理完成: $path_input"

