#!/bin/bash

# 获取脚本所在目录
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# 检查是否提供了编译命令参数
if [ $# -ne 1 ]; then
  echo "用法: $0 <编译命令>"
  echo "示例: $0 'pktfmt'"
  exit 1
fi

compile_cmd=$1

# 定义tuple列表，格式为 (字符串, 数字)
tuples=(
  "cond 6"
  "field 7"
  "header 6"
  "length 12"
  "num 1"
  "top_level 6"  
)

# 创建临时目录
tmp_dir="/tmp/compile_diff_$$"
mkdir -p "$tmp_dir"

# 清理函数
cleanup() {
  rm -rf "$tmp_dir"
  echo "已清理临时目录: $tmp_dir"
}

# 注册退出时清理
trap cleanup EXIT

# 外层循环：遍历tuple列表
for tuple in "${tuples[@]}"; do
  # 提取tuple中的字符串和数字
  name=$(echo "$tuple" | awk '{print $1}')
  count=$(echo "$tuple" | awk '{print $2}')
  
  echo "处理协议: $name, 错误数量: $count"
  
  cd $SCRIPT_DIR/$name
  # 内层循环：从1迭代到数字值
  for ((i=1; i<=$count; i++)); do
    # 组成输入文件名
    input_file="./error_${i}.pktfmt"
    echo "处理输入文件: $input_file"
    
    # 检查输入文件是否存在
    if [ ! -e "$input_file" ]; then
      echo "错误: 输入文件 $input_file 不存在"
      exit 2
    fi
    
    # 生成临时输出文件名
    tmp_output="${tmp_dir}/${name}_error_${i}.output"
    
    # 清空临时输出文件
    > "$tmp_output"
    
    # 使用提供的命令编译文件（预期会出错）
    echo "执行编译命令: $compile_cmd $input_file -o result.rs >> $tmp_output 2>&1"
    $compile_cmd "$input_file" -o result.rs >> "$tmp_output" 2>&1
    
    # 检查临时输出文件是否有内容（应该有，因为编译预期会出错）
    if [ ! -s "$tmp_output" ]; then
      echo "错误: 编译命令没有产生预期输出，可能执行成功"
      exit 3
    fi
    
    # 定义预期的解析结果文件路径
    expected_result="${SCRIPT_DIR}/${name}/parse_results/result_${i}"
    
    # 检查预期结果文件是否存在
    if [ ! -e "$expected_result" ]; then
      echo "错误: 预期结果文件 $expected_result 不存在"
      exit 4
    fi
    
    # 比较临时输出和预期结果
    echo "比较编译输出与预期结果..."
    if ! diff -q "$tmp_output" "$expected_result" >/dev/null; then
      echo "错误: 编译输出与预期结果不匹配"
      echo "=== 编译输出 ==="
      cat "$tmp_output"
      echo "=== 预期结果 ==="
      cat "$expected_result"
      echo "=== 差异 ==="
      diff -u "$expected_result" "$tmp_output"
      exit 5
    else
      echo "验证通过: 编译输出与预期结果一致"
    fi
  done
done

echo "所有协议错误文件处理完成，所有输出验证通过"