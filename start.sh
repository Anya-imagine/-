#!/bin/bash

# 激活虚拟环境
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 获取虚拟环境中 Python 解释器的完整路径
VENV_PYTHON=$(which python3)

# 使用虚拟环境的 Python 运行应用
sudo $VENV_PYTHON web/app.py 