from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import json
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
import threading
import time
import logging

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# 存储最新的数据包信息
latest_packets = []
is_capturing = False
capture_thread = None

def packet_callback(packet):
    """处理捕获的数据包"""
    try:
        logger.debug(f"Processing packet: {packet.summary()}")
        
        if IP in packet:
            packet_info = {
                "source": packet[IP].src,
                "destination": packet[IP].dst,
                "protocol": "Unknown",
                "payload_length": len(packet[Raw].load) if Raw in packet else 0,
                "content_detected": False,
                "ttl": packet[IP].ttl,
                "version": packet[IP].version,
                "id": packet[IP].id,
                "flags": str(packet[IP].flags),
                "frag": packet[IP].frag,
                "len": packet[IP].len
            }

            # 识别协议
            if TCP in packet:
                logger.debug(f"TCP packet detected: sport={packet[TCP].sport}, dport={packet[TCP].dport}")
                packet_info.update({
                    "sport": packet[TCP].sport,
                    "dport": packet[TCP].dport,
                    "seq": packet[TCP].seq,
                    "ack": packet[TCP].ack,
                    "flags": str(packet[TCP].flags),
                    "window": packet[TCP].window
                })
                
                # HTTP协议解析
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    logger.debug("HTTP packet detected")
                    packet_info["protocol"] = "HTTP"
                    if Raw in packet:
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            if "HTTP/" in payload or any(method in payload for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']):
                                packet_info["content_detected"] = True
                                lines = payload.split('\r\n')
                                if len(lines) > 0:
                                    request_line = lines[0].split()
                                    if len(request_line) >= 3:
                                        packet_info["http_method"] = request_line[0]
                                        packet_info["http_path"] = request_line[1]
                                        packet_info["http_version"] = request_line[2]
                                    
                                    # 解析头部
                                    packet_info["http_headers"] = {}
                                    for line in lines[1:]:
                                        if ':' in line:
                                            key, value = line.split(':', 1)
                                            packet_info["http_headers"][key.strip()] = value.strip()
                                    
                                    # 解析请求体
                                    if '\r\n\r\n' in payload:
                                        body = payload.split('\r\n\r\n', 1)[1]
                                        if body:
                                            packet_info["http_body"] = body
                                
                                logger.debug(f"HTTP details: {packet_info}")
                        except Exception as e:
                            logger.error(f"Error parsing HTTP: {e}")
                
                # TLS协议解析
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    logger.debug("TLS packet detected")
                    packet_info["protocol"] = "TLS"
                    if Raw in packet:
                        try:
                            payload = packet[Raw].load
                            if len(payload) > 5:
                                content_type = payload[0]
                                version = payload[1:3]
                                length = int.from_bytes(payload[3:5], byteorder='big')
                                
                                packet_info["tls_content_type"] = content_type
                                packet_info["tls_version"] = f"{version[0]}.{version[1]}"
                                packet_info["tls_length"] = length
                                
                                # TLS 1.3 握手消息
                                if content_type == 22:  # Handshake
                                    if len(payload) > 5:
                                        handshake_type = payload[5]
                                        packet_info["tls_handshake_type"] = handshake_type
                                        
                                        if handshake_type == 1:  # Client Hello
                                            packet_info["tls_client_hello"] = True
                                            # 解析支持的密码套件
                                            if len(payload) > 43:
                                                cipher_suites_length = int.from_bytes(payload[43:45], byteorder='big')
                                                cipher_suites = []
                                                for i in range(0, cipher_suites_length, 2):
                                                    if i + 1 < cipher_suites_length:
                                                        cipher_suite = int.from_bytes(payload[45+i:47+i], byteorder='big')
                                                        cipher_suites.append(cipher_suite)
                                                packet_info["tls_cipher_suites"] = cipher_suites
                                        
                                        elif handshake_type == 2:  # Server Hello
                                            packet_info["tls_server_hello"] = True
                                            # 解析选中的密码套件
                                            if len(payload) > 43:
                                                cipher_suite = int.from_bytes(payload[43:45], byteorder='big')
                                                packet_info["tls_selected_cipher_suite"] = cipher_suite
                                
                                # TLS 1.3 应用数据
                                elif content_type == 23:  # Application Data
                                    packet_info["tls_application_data"] = True
                                    packet_info["tls_encrypted_data"] = payload[5:].hex()
                                
                                logger.debug(f"TLS details: {packet_info}")
                        except Exception as e:
                            logger.error(f"Error parsing TLS: {e}")
                
                # SSH协议解析
                elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                    logger.debug("SSH packet detected")
                    packet_info["protocol"] = "SSH"
                    if Raw in packet:
                        try:
                            payload = packet[Raw].load
                            if len(payload) > 0:
                                # SSH 版本交换
                                if b'SSH-' in payload:
                                    lines = payload.split(b'\n')
                                    if len(lines) > 0:
                                        packet_info["ssh_version"] = lines[0].decode('utf-8', errors='ignore')
                                    if len(lines) > 1:
                                        packet_info["ssh_software"] = lines[1].decode('utf-8', errors='ignore')
                                # SSH 密钥交换
                                elif len(payload) > 5:
                                    packet_info["ssh_msg_code"] = payload[0]
                                    packet_info["ssh_packet_length"] = int.from_bytes(payload[1:5], byteorder='big')
                                
                                logger.debug(f"SSH details: {packet_info}")
                        except Exception as e:
                            logger.error(f"Error parsing SSH: {e}")
                
                # SMB协议解析
                elif packet[TCP].dport == 445 or packet[TCP].sport == 445:
                    logger.debug("SMB packet detected")
                    packet_info["protocol"] = "SMB"
                    if Raw in packet:
                        try:
                            payload = packet[Raw].load
                            if len(payload) > 4:
                                packet_info["smb_command"] = payload[4]
                                packet_info["smb_status"] = int.from_bytes(payload[5:7], byteorder='little')
                                packet_info["smb_flags"] = int.from_bytes(payload[7:9], byteorder='little')
                                
                                # SMB 命令类型
                                smb_commands = {
                                    0x72: "SMB_COM_NEGOTIATE",
                                    0x73: "SMB_COM_SESSION_SETUP_ANDX",
                                    0x75: "SMB_COM_TREE_CONNECT_ANDX",
                                    0xa2: "SMB_COM_NT_CREATE_ANDX",
                                    0x2e: "SMB_COM_READ_ANDX",
                                    0x2f: "SMB_COM_WRITE_ANDX",
                                    0x04: "SMB_COM_CLOSE",
                                    0x06: "SMB_COM_DELETE",
                                    0x0c: "SMB_COM_LOGOFF_ANDX"
                                }
                                packet_info["smb_command_name"] = smb_commands.get(payload[4], "Unknown")
                                
                                logger.debug(f"SMB details: {packet_info}")
                        except Exception as e:
                            logger.error(f"Error parsing SMB: {e}")
            
            # UDP协议解析
            elif UDP in packet:
                logger.debug(f"UDP packet detected: sport={packet[UDP].sport}, dport={packet[UDP].dport}")
                packet_info.update({
                    "sport": packet[UDP].sport,
                    "dport": packet[UDP].dport,
                    "len": packet[UDP].len
                })
                
                # DNS协议解析
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    logger.debug("DNS packet detected")
                    packet_info["protocol"] = "DNS"
                    if DNS in packet:
                        packet_info["dns_id"] = packet[DNS].id
                        packet_info["dns_qr"] = "Query" if packet[DNS].qr == 0 else "Response"
                        packet_info["dns_opcode"] = packet[DNS].opcode
                        packet_info["dns_rcode"] = packet[DNS].rcode
                        
                        # DNS 查询
                        if packet[DNS].qd:
                            packet_info["dns_qname"] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                            packet_info["dns_qtype"] = packet[DNS].qd.qtype
                            
                            # DNS 查询类型
                            qtypes = {
                                1: "A",
                                2: "NS",
                                5: "CNAME",
                                6: "SOA",
                                15: "MX",
                                16: "TXT",
                                28: "AAAA"
                            }
                            packet_info["dns_qtype_name"] = qtypes.get(packet[DNS].qd.qtype, "Unknown")
                        
                        # DNS 应答
                        if packet[DNS].an:
                            packet_info["dns_answers"] = []
                            for i in range(packet[DNS].ancount):
                                if i < len(packet[DNS].an):
                                    answer = packet[DNS].an[i]
                                    answer_info = {
                                        "name": answer.rdata.decode('utf-8', errors='ignore') if isinstance(answer.rdata, bytes) else str(answer.rdata),
                                        "type": answer.type,
                                        "ttl": answer.ttl
                                    }
                                    packet_info["dns_answers"].append(answer_info)
                        
                        logger.debug(f"DNS details: {packet_info}")
            
            # ICMP协议解析
            elif ICMP in packet:
                logger.debug("ICMP packet detected")
                packet_info.update({
                    "type": packet[ICMP].type,
                    "code": packet[ICMP].code,
                    "id": packet[ICMP].id,
                    "seq": packet[ICMP].seq
                })
                packet_info["protocol"] = "ICMP"
                
                # ICMP 类型描述
                icmp_types = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    4: "Source Quench",
                    5: "Redirect Message",
                    8: "Echo Request",
                    11: "Time Exceeded",
                    12: "Parameter Problem",
                    13: "Timestamp Request",
                    14: "Timestamp Reply"
                }
                packet_info["icmp_type_desc"] = icmp_types.get(packet[ICMP].type, "Unknown")
                
                # ICMP 代码描述
                icmp_codes = {
                    3: {
                        0: "Network Unreachable",
                        1: "Host Unreachable",
                        2: "Protocol Unreachable",
                        3: "Port Unreachable",
                        4: "Fragmentation Needed",
                        5: "Source Route Failed"
                    }
                }
                if packet[ICMP].type in icmp_codes:
                    packet_info["icmp_code_desc"] = icmp_codes[packet[ICMP].type].get(packet[ICMP].code, "Unknown")
                
                logger.debug(f"ICMP details: {packet_info}")

            # 格式化输出
            output = format_json_output(packet_info["protocol"], packet_info)
            
            # 添加到最新数据包列表
            latest_packets.append(output)
            if len(latest_packets) > 1000:  # 限制存储的数据包数量
                latest_packets.pop(0)
            
            # 广播到所有客户端
            logger.debug(f"Broadcasting packet: {output}")
            broadcast_packet(output)
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def start_capture():
    """开始捕获数据包"""
    global is_capturing, capture_thread
    if not is_capturing:
        logger.info("Starting packet capture")
        is_capturing = True
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()

def stop_capture():
    """停止捕获数据包"""
    global is_capturing
    logger.info("Stopping packet capture")
    is_capturing = False

def capture_packets():
    """数据包捕获线程"""
    while is_capturing:
        try:
            logger.debug("Starting packet capture...")
            # 使用更详细的过滤器来捕获所有相关协议
            sniff(
                prn=packet_callback,
                store=0,
                count=1,
                filter="tcp or udp or icmp",  # 明确指定要捕获的协议
                iface=None  # 使用默认接口
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/packets')
def get_packets():
    return jsonify(latest_packets)

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

@socketio.on('start_capture')
def handle_start_capture():
    logger.info('Received start_capture event')
    start_capture()

@socketio.on('stop_capture')
def handle_stop_capture():
    logger.info('Received stop_capture event')
    stop_capture()

def broadcast_packet(packet_data):
    """广播数据包到所有连接的客户端"""
    try:
        socketio.emit('new_packet', packet_data)
    except Exception as e:
        logger.error(f"Error broadcasting packet: {e}")

def format_json_output(protocol, data):
    """格式化JSON输出"""
    output = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
        "protocol": protocol,
        "data": data
    }
    return output

if __name__ == '__main__':
    logger.info("Starting server...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 