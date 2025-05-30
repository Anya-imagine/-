import json
import threading

from flask import Flask, jsonify
from analyzers.packet_sniffer import PacketSniffer, ProtocolAnalyzer
from analyzers.dns import dns_parser, Session
from collections import deque
DNS_HISTORY = deque(maxlen=100)

app = Flask(__name__)




def dns_handler(raw_data, metadata):
    # 添加原始数据校验
    if not raw_data:
        print("[警告] 收到空数据包")
        return

    print(f"[流量追踪] 数据包到达! 长度: {len(raw_data)} 字节")  # 新增流量到达提示

    session = Session()
    try:
        dns_parser(session, 0, bytearray(raw_data), len(raw_data), metadata)
    except Exception as e:
        print(f"[解析错误] {str(e)}")
        return

    if not session.fields:
        print("[警告] 解析后字段为空")
        return

    DNS_HISTORY.append(session.fields)
    print(f"[成功] 已存储 {len(session.fields)} 个字段")

# 在ProtocolAnalyzer初始化后添加调试
analyzer = ProtocolAnalyzer()
print(f"[分析器] 已加载协议处理器: {analyzer.handlers.keys()}")  # 显示已注册的协议

sniffer = PacketSniffer(analyzer)
print(f"[抓包器] 数据处理器链路: {sniffer.processor == analyzer}")  # 验证处理器链路


def start_sniffer():
    """在应用启动时初始化抓包线程"""
    if not hasattr(app, 'sniffer_started'):
        try:
            # 修改为同时监听所有接口（传入空字符串）
            sniffer.start(interface='')  # 空字符串表示监听所有接口
            print(f"[抓包器] 全接口监听模式已启动，PID: {threading.get_native_id()}")
        except Exception as e:  # 添加缺失的异常处理
            print(f"[抓包器] 启动失败: {str(e)}")
            print("※ 需要管理员权限运行！请使用 sudo python app.py ※")
        app.sniffer_started = True

# 在第一个请求到达时触发初始化
@app.before_request
def before_first_request():
    if not app._got_first_request:  # 使用正确属性名
        start_sniffer()

@app.route('/dns-requests')
def show_requests():
    """显示最近的DNS请求"""
    print(f"[API请求] 当前记录数: {len(DNS_HISTORY)}")  # 添加调试信息
    return jsonify({
        'requests': [dict(fields) for fields in DNS_HISTORY]
    })



# 修改初始化方式（放在文件末尾）
if __name__ == '__main__':
    # 先启动抓包器再运行Flask
    start_sniffer()
    app.run(threaded=True)