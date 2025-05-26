# Network Traffic Analyzer

这是一个网络流量分析工具，可以捕获和分析多种网络协议，包括：
- HTTP
- DHCP
- ICMP
- SMB
- SOCKS
- SSH
- TLS

## 功能特点

- 实时捕获网络数据包
- 支持多种协议解析
- 详细的会话信息展示
- 可配置的过滤规则

## 安装要求

- Python 3.7+
- 系统依赖：
  - libpcap-dev
  - libmagic1

## 安装步骤

1. 克隆仓库：
```bash
git clone <repository-url>
cd network-traffic-analyzer
```

2. 安装系统依赖：
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libpcap-dev libmagic1

# CentOS/RHEL
sudo yum install libpcap-devel file-libs
```

3. 安装Python依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

1. 基本用法：
```bash
sudo python main.py -i <interface>
```

2. 使用过滤器：
```bash
sudo python main.py -i <interface> -f "port 80"
```

3. 查看帮助：
```bash
python main.py --help
```

## 示例输出

```
2024-01-20 10:15:30,123 - INFO - ==================================================
2024-01-20 10:15:30,124 - INFO - Protocol: http
2024-01-20 10:15:30,125 - INFO - Source IP: 192.168.1.100
2024-01-20 10:15:30,126 - INFO - Destination IP: 192.168.1.1
2024-01-20 10:15:30,127 - INFO - HTTP Method: GET
2024-01-20 10:15:30,128 - INFO - HTTP URI: /api/v1/users
2024-01-20 10:15:30,129 - INFO - HTTP Status: 200
2024-01-20 10:15:30,130 - INFO - ==================================================
```

## 注意事项

1. 需要root/管理员权限才能捕获网络数据包
2. 建议在测试环境中使用
3. 请遵守相关法律法规

## 许可证

MIT License 