# 网络流量分析与入侵检测系统

这是一个基于Python的网络流量分析与入侵检测系统，可以实时捕获和分析网络数据包，并通过Web界面展示分析结果。

## 功能特点

- 实时捕获网络数据包
- 支持多种协议分析（HTTP、HTTPS、DNS、ICMP、SMB、SSH等）
- 实时数据包展示和过滤
- 协议分布统计
- 流量趋势分析
- 异常检测
- 现代化的Web界面

## 系统要求

- Python 3.8+
- Linux操作系统（需要root权限进行数据包捕获）

## 安装

1. 克隆仓库：
```bash
git clone <repository-url>
cd network-traffic-analyzer
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

1. 启动Web服务器：
```bash
sudo python web/app.py
```

2. 在浏览器中访问：
```
http://localhost:5000
```

3. 点击"开始捕获"按钮开始捕获网络数据包。

## 界面说明

- **实时流量**：显示捕获的数据包详细信息
- **统计分析**：显示协议分布、流量趋势和异常检测图表
- **过滤器**：可以按协议类型、源IP和目标IP进行过滤

## 注意事项

- 需要root权限才能捕获网络数据包
- 建议在测试环境中使用
- 请遵守相关法律法规

## 许可证

MIT License 