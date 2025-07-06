#!/bin/bash
set -e

if [ -d "$2" ];then
    mkdir -p "$2"
fi
$1 config set registry https://registry.npmmirror.com/
$1 install
$1 run build BUILD_OUTPUT="$2"