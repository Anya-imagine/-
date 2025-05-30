#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主程序 - DNS流量捕获和分析工具
"""

# 添加当前目录到路径，以便导入analyzers包
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 首先导入field_manager
from analyzers.singleton import field_manager

# 然后导入其他模块
from detection import PacketParser, match
import logging
import argparse
import traceback
from datetime import datetime
import ipaddress
import time
import struct
import json
import hashlib
import socket
import binascii

from scapy.all import sniff, DNS, IP, UDP, BOOTP, DHCP, ICMP, wrpcap, rdpcap, TCP, Raw, IPv6
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import _TLSHandshake

from analyzers.session import Session
from analyzers.types import FieldObject

# 导入协议处理函数
from analyzers.dns import dns_parser, dns_tcp_parser, dns_udp_parser
from analyzers.dhcp import dhcp_parser
from analyzers.icmp import icmp_parser
from analyzers.http import http_parser
from analyzers.smb import smb_parser
from analyzers.ssh import ssh_parser
from analyzers.tls import tls_parser, format_tls_handshake_message, tls_is_grease_value

from dataclasses import dataclass, field
from typing import Dict, Any

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("FlowCapture")

# 初始化字段定义
def init_fields():
    """初始化所有字段定义"""
    logger.info("初始化字段定义...")
    
    # 通用字段
    field_manager.field_define(
        group="common",
        kind="str",
        expression="timestamp",
        display_name="Timestamp",
        es_name="timestamp",
        description="Packet timestamp"
    )
    
    field_manager.field_define(
        group="common",
        kind="str",
        expression="summary",
        display_name="Summary",
        es_name="summary",
        description="Packet summary"
    )
    
    field_manager.field_define(
        group="common",
        kind="ip",
        expression="src_ip",
        display_name="Source IP",
        es_name="src_ip",
        description="Source IP address"
    )
    
    field_manager.field_define(
        group="common",
        kind="ip",
        expression="dst_ip",
        display_name="Destination IP",
        es_name="dst_ip",
        description="Destination IP address"
    )
    
    field_manager.field_define(
        group="common",
        kind="int",
        expression="src_port",
        display_name="Source Port",
        es_name="src_port",
        description="Source port number"
    )
    
    field_manager.field_define(
        group="common",
        kind="int",
        expression="dst_port",
        display_name="Destination Port",
        es_name="dst_port",
        description="Destination port number"
    )
    
    field_manager.field_define(
        group="common",
        kind="str",
        expression="protocol",
        display_name="Protocol",
        es_name="protocol",
        description="Protocol type"
    )
    
    # DNS字段
    field_manager.field_define(
        group="dns",
        kind="str",
        expression="dns.query",
        display_name="DNS Query",
        es_name="dns_query",
        description="DNS query domain"
    )
    
    field_manager.field_define(
        group="dns",
        kind="str",
        expression="dns.response",
        display_name="DNS Response",
        es_name="dns_response",
        description="DNS response data"
    )
    
    # HTTP字段
    field_manager.field_define(
        group="http",
        kind="str",
        expression="http.method",
        display_name="HTTP Method",
        es_name="http_method",
        description="HTTP request method"
    )
    
    field_manager.field_define(
        group="http",
        kind="str",
        expression="http.url",
        display_name="HTTP URL",
        es_name="http_url",
        description="HTTP request URL"
    )
    
    # SMB字段
    field_manager.field_define(
        group="smb",
        kind="str",
        expression="smb.command",
        display_name="SMB Command",
        es_name="smb_command",
        description="SMB command type"
    )
    
    # TLS字段
    field_manager.field_define(
        group="tls",
        kind="str",
        expression="tls.version",
        display_name="TLS Version",
        es_name="tls_version",
        description="TLS protocol version"
    )
    
    field_manager.field_define(
        group="tls",
        kind="str",
        expression="tls.cipher",
        display_name="TLS Cipher",
        es_name="tls_cipher",
        description="TLS cipher suite"
    )
    
    logger.info("字段定义初始化完成")

# 修改 JsonStorageManager 类
class JsonStorageManager:
    """JSON存储管理器"""
    
    def __init__(self, output_dir="analysis_results"):
        self.output_dir = output_dir
        self.current_file = None
        self.ensure_output_dir()
        
    def ensure_output_dir(self):
        """确保输出目录存在"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
    def create_new_file(self):
        """创建新的JSON文件"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packet_analysis_{timestamp}.json"
        self.current_file = os.path.join(self.output_dir, filename)
        
        # 创建初始JSON结构
        initial_data = {
            "metadata": {
                "start_time": timestamp,
                "version": "1.0"
            },
            "packets": []
        }
        
        with open(self.current_file, 'w') as f:
            json.dump(initial_data, f, indent=2)
            
        logger.info(f"Created new JSON file: {self.current_file}")
        
    def append_packet(self, packet_data):
        """添加数据包到JSON文件"""
        if not self.current_file:
            self.create_new_file()
            
        try:
            # 读取现有数据
            with open(self.current_file, 'r') as f:
                data = json.load(f)
                
            # 格式化数据
            formatted_data = {
                "timestamp": packet_data.get("timestamp", ""),
                "protocol": packet_data.get("protocol", ""),
                "src_ip": packet_data.get("src_ip", ""),
                "dst_ip": packet_data.get("dst_ip", ""),
                "src_port": packet_data.get("src_port", ""),
                "dst_port": packet_data.get("dst_port", ""),
                "summary": packet_data.get("summary", "")
            }
            
            # 添加协议特定字段
            protocol = packet_data.get("protocol", "")
            if protocol == "DNS":
                formatted_data.update({
                    "dns_query": packet_data.get("dns.query", ""),
                    "dns_response": packet_data.get("dns.response", "")
                })
            elif protocol == "HTTP":
                formatted_data.update({
                    "http_method": packet_data.get("http.method", ""),
                    "http_url": packet_data.get("http.url", "")
                })
            elif protocol == "SMB":
                formatted_data.update({
                    "smb_command": packet_data.get("smb.command", "")
                })
            elif protocol == "TLS":
                formatted_data.update({
                    "tls_version": packet_data.get("tls.version", ""),
                    "tls_cipher": packet_data.get("tls.cipher", "")
                })
            
            # 添加处理后的数据
            data["packets"].append(formatted_data)
            
            # 写回文件
            with open(self.current_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error appending packet to JSON: {str(e)}")
            logger.error(traceback.format_exc())

# 修改 packet_callback 函数
def packet_callback(packet, json_storage):
    """数据包回调处理函数"""
    try:
        print("\n=== New Packet ===")
        print(f"Packet type: {packet.type}")
        print(f"Has IP: {IP in packet}")
        print(f"Has TCP: {TCP in packet}")
        print(f"Has Raw: {Raw in packet}")
        
        # 获取基本字段
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
        src_ip = packet[IP].src if IP in packet else None
        dst_ip = packet[IP].dst if IP in packet else None
        src_port = packet[TCP].sport if TCP in packet else None
        dst_port = packet[TCP].dport if TCP in packet else None
        
        print(f"Source: {src_ip}:{src_port}")
        print(f"Destination: {dst_ip}:{dst_port}")
        
        # 创建会话对象
        session = Session()
        
        # 处理TCP数据包
        if TCP in packet:
            print("\n=== TCP Packet ===")
            print(f"Source: {src_ip}:{src_port}")
            print(f"Destination: {dst_ip}:{dst_port}")
            
            if Raw in packet:
                raw_data = packet[Raw].load
                print(f"Raw data length: {len(raw_data)}")
                print(f"Raw data preview: {raw_data[:100]}")
                
                # 检查是否是HTTP流量
                if dst_port == 80 or src_port == 80:
                    print("\n=== HTTP Packet ===")
                    print(f"Source: {src_ip}:{src_port}")
                    print(f"Destination: {dst_ip}:{dst_port}")
                    print(f"Payload length: {len(raw_data)}")
                    
                    try:
                        http_text = raw_data.decode('utf-8', errors='ignore')
                        print(f"Raw content: {http_text[:200]}")  # 显示更多内容
                        
                        # 检查HTTP方法或响应
                        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
                        http_responses = ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']
                        
                        # 检查是否是HTTP请求
                        is_http_request = any(method in http_text.split('\r\n')[0] for method in http_methods)
                        # 检查是否是HTTP响应
                        is_http_response = any(response in http_text.split('\r\n')[0] for response in http_responses)
                        
                        if is_http_request or is_http_response:
                            print("HTTP content detected!")
                            print(f"First line: {http_text.split('\r\n')[0]}")
                            
                            # Create session
                            session = Session()
                            session.fields.update({
                                'timestamp': timestamp,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'protocol': 'HTTP',
                                'summary': f"HTTP {http_text.split('\r\n')[0]}"
                            })
                            
                            # Store to JSON
                            json_storage = JsonStorageManager()
                            json_storage.append_packet(session.fields)
                        else:
                            print("Not HTTP content")
                    except Exception as e:
                        print(f"Error parsing HTTP data: {e}")
            
            # 检查是否是TLS流量
            elif TLS in packet:
                # ... existing TLS code ...
                pass
        
        # 处理DNS流量
        elif DNS in packet:
            session.fields["protocol"] = "DNS"
            session.add_protocol("dns")
            
            print("\n" + "="*65)
            print("DNS Packet Analysis")
            print("="*65)
            
            # 基本信息
            print("\n[Basic Information]")
            print("-"*65)
            print(f"Source IP: {src_ip}:{src_port}")
            print(f"Destination IP: {dst_ip}:{dst_port}")
            print("-"*65)
            
            # DNS查询信息
            print("\n[DNS Query]")
            print("-"*65)
            if packet[DNS].qr == 0:  # 查询包
                print("Type: Query")
                if packet[DNS].qd:
                    qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                    qtype = packet[DNS].qd.qtype
                    qclass = packet[DNS].qd.qclass
                    print(f"Query Name: {qname}")
                    print(f"Query Type: {qtype}")
                    print(f"Query Class: {qclass}")
                    
                    # 存储查询信息到session
                    session.fields["dns.query"] = qname
                    session.fields["dns.qtype"] = qtype
                    session.fields["dns.qclass"] = qclass
            else:  # 响应包
                print("Type: Response")
                if packet[DNS].an:
                    print("\nAnswers:")
                    answers = []
                    for i, answer in enumerate(packet[DNS].an):
                        answer_info = {
                            "name": answer.rrname.decode('utf-8', errors='ignore'),
                            "type": answer.type,
                            "class": answer.rclass,
                            "ttl": answer.ttl
                        }
                        
                        print(f"\nAnswer {i+1}:")
                        print(f"  Name: {answer_info['name']}")
                        print(f"  Type: {answer_info['type']}")
                        print(f"  Class: {answer_info['class']}")
                        print(f"  TTL: {answer_info['ttl']}")
                        
                        if answer.type == 1:  # A记录
                            answer_info["ip"] = answer.rdata
                            print(f"  IP: {answer.rdata}")
                        elif answer.type == 5:  # CNAME记录
                            answer_info["cname"] = answer.rdata.decode('utf-8', errors='ignore')
                            print(f"  CNAME: {answer_info['cname']}")
                        elif answer.type == 15:  # MX记录
                            answer_info["mx"] = answer.rdata.decode('utf-8', errors='ignore')
                            print(f"  MX: {answer_info['mx']}")
                        elif answer.type == 16:  # TXT记录
                            answer_info["txt"] = answer.rdata.decode('utf-8', errors='ignore')
                            print(f"  TXT: {answer_info['txt']}")
                        elif answer.type == 28:  # AAAA记录
                            answer_info["ipv6"] = answer.rdata
                            print(f"  IPv6: {answer.rdata}")
                        
                        answers.append(answer_info)
                    
                    # 存储答案信息到session
                    session.fields["dns.answers"] = answers
            
            # DNS头部信息
            print("\n[DNS Header]")
            print("-"*65)
            print(f"Transaction ID: 0x{packet[DNS].id:04x}")
            print(f"Flags: 0x{packet[DNS].flags:04x}")
            print(f"Questions: {packet[DNS].qdcount}")
            print(f"Answer RRs: {packet[DNS].ancount}")
            print(f"Authority RRs: {packet[DNS].nscount}")
            print(f"Additional RRs: {packet[DNS].arcount}")
            
            # 存储头部信息到session
            session.fields["dns.id"] = packet[DNS].id
            session.fields["dns.flags"] = packet[DNS].flags
            session.fields["dns.qdcount"] = packet[DNS].qdcount
            session.fields["dns.ancount"] = packet[DNS].ancount
            session.fields["dns.nscount"] = packet[DNS].nscount
            session.fields["dns.arcount"] = packet[DNS].arcount
            
            # 调用DNS解析器
            dns_parser(session, 0, bytes(packet[DNS]), len(packet[DNS]), {
                'src_ip': src_ip,
                'dst_ip': dst_ip
            })
            
            # 打印session中的所有DNS相关字段
            print("\n[Session Fields]")
            for key, value in session.fields.items():
                if key.startswith("dns."):
                    print(f"{key}: {value}")
            
            print("-"*65)
            print("\n" + "="*65 + "\n")
            
            # 获取处理后的数据
            result = session.get_readable_fields()
            
            # 打印调试信息
            print("\n=== Packet Info ===")
            print(f"Timestamp: {result.get('timestamp', '')}")
            print(f"Protocol: {result.get('protocol', '')}")
            print(f"Source: {result.get('src_ip', '')}:{result.get('src_port', '')}")
            print(f"Destination: {result.get('dst_ip', '')}:{result.get('dst_port', '')}")
            print(f"Summary: {result.get('summary', '')}")
            
            # 打印DNS特定字段
            if "dns" in result.get('protocol', '').lower():
                print("\nDNS Specific Fields:")
                print(f"Query: {field_manager.field_str_get('dns.query', session)}")
                print(f"Query Type: {field_manager.field_str_get('dns.qtype', session)}")
                print(f"Query Class: {field_manager.field_str_get('dns.qclass', session)}")
                print(f"Answers: {field_manager.field_str_get('dns.answers', session)}")
                print(f"Transaction ID: {field_manager.field_str_get('dns.id', session)}")
                print(f"Flags: {field_manager.field_str_get('dns.flags', session)}")
            
            print("==================\n")
            
        # 处理DHCP流量
        elif DHCP in packet or (UDP in packet and (packet[UDP].sport in [67, 68] or packet[UDP].dport in [67, 68])):
            session.fields["protocol"] = "DHCP"
            session.add_protocol("dhcp")
            dhcp_parser(session, 0, bytes(packet[DHCP]), len(packet[DHCP]), {})
            
        # 处理ICMP流量
        elif ICMP in packet:
            session.fields["protocol"] = "ICMP"
            session.add_protocol("icmp")
            icmp_parser(session, 0, bytes(packet[ICMP]), len(packet[ICMP]), {})
            
        # 如果json_storage不为None，则保存结果
        if json_storage is not None:
            json_storage.append_packet(session.fields)
            
    except Exception as e:
        print(f"处理数据包时出错: {e}")
        print(f"Error details: {traceback.format_exc()}")
        return

@dataclass
class Session:
    fields: Dict[str, Any] = field(default_factory=dict)
    protocols: set = field(default_factory=set)
    
    def add_protocol(self, protocol: str):
        self.protocols.add(protocol)
        
    def has_protocol(self, protocol: str) -> bool:
        return protocol in self.protocols

def format_json_output(protocol, data):
    """格式化JSON输出"""
    output = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
        "protocol": protocol,
        "data": data
    }
    return json.dumps(output, indent=2)

def main():
    # Create raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    print("Starting packet capture...")
    print("Press Ctrl+C to stop")
    print()
    
    try:
        while True:
            # Receive packet
            packet, addr = s.recvfrom(65535)
            
            # Parse Ethernet header
            eth_header = struct.unpack('!6s6sH', packet[:14])
            eth_type = eth_header[2]
            
            # Check if it's an IP packet
            if eth_type != 0x0800:  # 0x0800 is IPv4
                continue
                
            # Parse IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
            ip_version = ip_header[0] >> 4
            ip_header_length = (ip_header[0] & 0x0F) * 4
            ip_protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Check if it's TCP
            if ip_protocol == 6:  # 6 is TCP
                # Parse TCP header
                tcp_header = struct.unpack('!HHLLBBHHH', packet[14+ip_header_length:14+ip_header_length+20])
                src_port = tcp_header[0]
                dst_port = tcp_header[1]
                seq_num = tcp_header[2]
                ack_num = tcp_header[3]
                tcp_flags = tcp_header[5]
                tcp_header_length = (tcp_header[4] >> 4) * 4
                tcp_payload = packet[14+ip_header_length+tcp_header_length:]

                # 检查是否是SMB流量 (端口445)
                if dst_port == 445 or src_port == 445:
                    try:
                        smb_data = {
                            "source": f"{src_ip}:{src_port}",
                            "destination": f"{dst_ip}:{dst_port}",
                            "payload_length": len(tcp_payload)
                        }
                        
                        if len(tcp_payload) > 0:
                            smb_data["content_detected"] = True
                            smb_data["raw_content_preview"] = tcp_payload[:200].hex()
                            
                            if len(tcp_payload) >= 4:
                                smb_command = tcp_payload[4]
                                command_names = {
                                    0x72: "SMB_COM_NEGOTIATE",
                                    0x73: "SMB_COM_SESSION_SETUP_ANDX",
                                    0x75: "SMB_COM_TREE_CONNECT_ANDX",
                                    0x2E: "SMB_COM_OPEN_ANDX",
                                    0x2F: "SMB_COM_READ_ANDX",
                                    0x30: "SMB_COM_WRITE_ANDX",
                                    0x04: "SMB_COM_CLOSE",
                                    0x25: "SMB_COM_TRANSACTION",
                                    0x2D: "SMB_COM_ECHO"
                                }
                                smb_data["command"] = command_names.get(smb_command, f"Unknown Command (0x{smb_command:02X})")
                                
                                # 解析SMB头部
                                if len(tcp_payload) >= 32:
                                    smb_data["header"] = {
                                        "protocol_id": tcp_payload[0:4].hex(),
                                        "command": smb_data["command"],
                                        "status": struct.unpack('!I', tcp_payload[5:9])[0],
                                        "flags": struct.unpack('!H', tcp_payload[9:11])[0],
                                        "flags2": struct.unpack('!H', tcp_payload[11:13])[0],
                                        "pid_high": struct.unpack('!H', tcp_payload[13:15])[0],
                                        "signature": tcp_payload[15:23].hex(),
                                        "reserved": struct.unpack('!H', tcp_payload[23:25])[0],
                                        "tid": struct.unpack('!H', tcp_payload[25:27])[0],
                                        "pid_low": struct.unpack('!H', tcp_payload[27:29])[0],
                                        "uid": struct.unpack('!H', tcp_payload[29:31])[0],
                                        "mid": struct.unpack('!H', tcp_payload[31:33])[0]
                                    }
                        
                        print(format_json_output("SMB", smb_data))
                    except Exception as e:
                        print(format_json_output("SMB_ERROR", {"error": str(e)}))

                # 检查是否是SSH流量 (端口22)
                elif dst_port == 22 or src_port == 22:
                    try:
                        ssh_data = {
                            "source": f"{src_ip}:{src_port}",
                            "destination": f"{dst_ip}:{dst_port}",
                            "payload_length": len(tcp_payload)
                        }
                        
                        if len(tcp_payload) > 0:
                            ssh_data["content_detected"] = True
                            
                            if tcp_payload.startswith(b'SSH-'):
                                version = tcp_payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                                ssh_data["version"] = version
                                ssh_data["version_exchange"] = True
                                
                                # 解析SSH版本字符串
                                version_parts = version.split('-')
                                if len(version_parts) >= 2:
                                    ssh_data["version_details"] = {
                                        "protocol": version_parts[0],
                                        "version": version_parts[1],
                                        "software": '-'.join(version_parts[2:]) if len(version_parts) > 2 else None
                                    }
                            
                            elif len(tcp_payload) >= 6:
                                msg_type = tcp_payload[5]
                                msg_types = {
                                    1: "SSH_MSG_DISCONNECT",
                                    2: "SSH_MSG_IGNORE",
                                    3: "SSH_MSG_UNIMPLEMENTED",
                                    4: "SSH_MSG_DEBUG",
                                    5: "SSH_MSG_SERVICE_REQUEST",
                                    6: "SSH_MSG_SERVICE_ACCEPT",
                                    20: "SSH_MSG_KEXINIT",
                                    21: "SSH_MSG_NEWKEYS",
                                    30: "SSH_MSG_KEXDH_INIT",
                                    31: "SSH_MSG_KEXDH_REPLY",
                                    50: "SSH_MSG_USERAUTH_REQUEST",
                                    51: "SSH_MSG_USERAUTH_FAILURE",
                                    52: "SSH_MSG_USERAUTH_SUCCESS",
                                    53: "SSH_MSG_USERAUTH_BANNER",
                                    80: "SSH_MSG_CHANNEL_OPEN",
                                    91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
                                    92: "SSH_MSG_CHANNEL_OPEN_FAILURE",
                                    93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",
                                    94: "SSH_MSG_CHANNEL_DATA",
                                    95: "SSH_MSG_CHANNEL_EXTENDED_DATA",
                                    96: "SSH_MSG_CHANNEL_EOF",
                                    97: "SSH_MSG_CHANNEL_CLOSE",
                                    98: "SSH_MSG_CHANNEL_REQUEST",
                                    99: "SSH_MSG_CHANNEL_SUCCESS",
                                    100: "SSH_MSG_CHANNEL_FAILURE"
                                }
                                ssh_data["message_type"] = msg_types.get(msg_type, f"Unknown Message Type (0x{msg_type:02X})")
                                
                                # 解析SSH消息头部
                                if len(tcp_payload) >= 6:
                                    ssh_data["message_header"] = {
                                        "packet_length": struct.unpack('!I', tcp_payload[0:4])[0],
                                        "padding_length": tcp_payload[4],
                                        "message_type": ssh_data["message_type"]
                                    }
                        
                        print(format_json_output("SSH", ssh_data))
                    except Exception as e:
                        print(format_json_output("SSH_ERROR", {"error": str(e)}))

                # 检查是否是HTTP流量 (端口80)
                elif dst_port == 80 or src_port == 80:
                    try:
                        http_data = {
                            "source": f"{src_ip}:{src_port}",
                            "destination": f"{dst_ip}:{dst_port}",
                            "payload_length": len(tcp_payload)
                        }
                        
                        if len(tcp_payload) > 0:
                            http_text = tcp_payload.decode('utf-8', errors='ignore')
                            http_data["raw_content"] = http_text[:200]
                            
                            http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
                            http_responses = ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']
                            
                            first_line = http_text.split('\r\n')[0]
                            is_http_request = any(method in first_line for method in http_methods)
                            is_http_response = any(response in first_line for response in http_responses)
                            
                            if is_http_request or is_http_response:
                                http_data["content_detected"] = True
                                http_data["first_line"] = first_line
                                
                                # 解析HTTP头部
                                headers = {}
                                body = ""
                                header_end = http_text.find('\r\n\r\n')
                                if header_end != -1:
                                    header_text = http_text[:header_end]
                                    body = http_text[header_end + 4:]
                                    
                                    for line in header_text.split('\r\n')[1:]:
                                        if ':' in line:
                                            key, value = line.split(':', 1)
                                            headers[key.strip()] = value.strip()
                                
                                http_data["headers"] = headers
                                http_data["body"] = body[:200] if body else None
                                
                                # 解析HTTP请求/响应行
                                if is_http_request:
                                    parts = first_line.split(' ')
                                    if len(parts) >= 3:
                                        http_data["request"] = {
                                            "method": parts[0],
                                            "path": parts[1],
                                            "version": parts[2]
                                        }
                                else:
                                    parts = first_line.split(' ')
                                    if len(parts) >= 3:
                                        http_data["response"] = {
                                            "version": parts[0],
                                            "status_code": int(parts[1]),
                                            "status_message": ' '.join(parts[2:])
                                        }
                        
                        print(format_json_output("HTTP", http_data))
                    except Exception as e:
                        print(format_json_output("HTTP_ERROR", {"error": str(e)}))

                # 检查是否是DNS over TCP流量 (端口53)
                elif src_port == 53 or dst_port == 53:
                    try:
                        dns_data = {
                            "source": f"{src_ip}:{src_port}",
                            "destination": f"{dst_ip}:{dst_port}",
                            "payload_length": len(tcp_payload),
                            "sequence_number": seq_num,
                            "acknowledgment_number": ack_num,
                            "flags": {
                                "syn": bool(tcp_flags & 0x02),
                                "ack": bool(tcp_flags & 0x10),
                                "fin": bool(tcp_flags & 0x01),
                                "rst": bool(tcp_flags & 0x04),
                                "psh": bool(tcp_flags & 0x08)
                            }
                        }
                        
                        if len(tcp_payload) >= 12:
                            dns_header = struct.unpack('!HHHHHH', tcp_payload[:12])
                            dns_data.update({
                                "transaction_id": f"0x{dns_header[0]:04x}",
                                "flags": f"0x{dns_header[1]:04x}",
                                "questions": dns_header[2],
                                "answer_rrs": dns_header[3],
                                "authority_rrs": dns_header[4],
                                "additional_rrs": dns_header[5]
                            })
                            
                            # 解析DNS标志
                            flags = dns_header[1]
                            dns_data["flags_details"] = {
                                "qr": bool(flags & 0x8000),  # Query/Response
                                "opcode": (flags & 0x7800) >> 11,  # Operation Code
                                "aa": bool(flags & 0x0400),  # Authoritative Answer
                                "tc": bool(flags & 0x0200),  # Truncated
                                "rd": bool(flags & 0x0100),  # Recursion Desired
                                "ra": bool(flags & 0x0080),  # Recursion Available
                                "z": (flags & 0x0070) >> 4,  # Reserved
                                "rcode": flags & 0x000F  # Response Code
                            }
                            
                            # 解析DNS问题部分
                            if dns_header[2] > 0:
                                questions = []
                                offset = 12
                                for i in range(dns_header[2]):
                                    if offset >= len(tcp_payload):
                                        break
                                    
                                    # 解析域名
                                    domain_parts = []
                                    while offset < len(tcp_payload):
                                        length = tcp_payload[offset]
                                        if length == 0:
                                            offset += 1
                                            break
                                        if length >= 0xC0:  # DNS压缩
                                            ptr = ((length & 0x3F) << 8) | tcp_payload[offset + 1]
                                            offset += 2
                                            break
                                        offset += 1
                                        if offset + length > len(tcp_payload):
                                            break
                                        domain_parts.append(tcp_payload[offset:offset+length].decode('utf-8', errors='ignore'))
                                        offset += length
                                    domain = '.'.join(domain_parts)
                                    
                                    # 解析类型和类
                                    if offset + 4 > len(tcp_payload):
                                        break
                                    qtype, qclass = struct.unpack('!HH', tcp_payload[offset:offset+4])
                                    offset += 4
                                    
                                    questions.append({
                                        "name": domain,
                                        "type": qtype,
                                        "class": qclass
                                    })
                                
                                dns_data["questions"] = questions
                            
                            # 解析DNS回答部分
                            if dns_header[3] > 0:
                                answers = []
                                for i in range(dns_header[3]):
                                    if offset >= len(tcp_payload):
                                        break
                                    
                                    # 解析域名
                                    domain_parts = []
                                    while offset < len(tcp_payload):
                                        length = tcp_payload[offset]
                                        if length == 0:
                                            offset += 1
                                            break
                                        if length >= 0xC0:  # DNS压缩
                                            ptr = ((length & 0x3F) << 8) | tcp_payload[offset + 1]
                                            offset += 2
                                            break
                                        offset += 1
                                        if offset + length > len(tcp_payload):
                                            break
                                        domain_parts.append(tcp_payload[offset:offset+length].decode('utf-8', errors='ignore'))
                                        offset += length
                                    domain = '.'.join(domain_parts)
                                    
                                    # 解析记录头
                                    if offset + 10 > len(tcp_payload):
                                        break
                                    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', tcp_payload[offset:offset+10])
                                    offset += 10
                                    
                                    # 解析记录数据
                                    if offset + rdlength > len(tcp_payload):
                                        break
                                    rdata = tcp_payload[offset:offset+rdlength]
                                    offset += rdlength
                                    
                                    answer = {
                                        "name": domain,
                                        "type": rtype,
                                        "class": rclass,
                                        "ttl": ttl,
                                        "rdlength": rdlength
                                    }
                                    
                                    # 根据记录类型解析数据
                                    try:
                                        if rtype == 1:  # A记录
                                            if len(rdata) == 4:
                                                answer["ip"] = socket.inet_ntoa(rdata)
                                        elif rtype == 5:  # CNAME记录
                                            answer["cname"] = '.'.join([rdata[i:i+1].decode('utf-8', errors='ignore') for i in range(0, len(rdata), 1)])
                                        elif rtype == 15:  # MX记录
                                            if len(rdata) >= 2:
                                                preference = struct.unpack('!H', rdata[:2])[0]
                                                mx = '.'.join([rdata[i:i+1].decode('utf-8', errors='ignore') for i in range(2, len(rdata), 1)])
                                                answer["mx"] = mx
                                                answer["preference"] = preference
                                        elif rtype == 16:  # TXT记录
                                            answer["txt"] = rdata.decode('utf-8', errors='ignore')
                                        elif rtype == 28:  # AAAA记录
                                            if len(rdata) == 16:
                                                answer["ipv6"] = socket.inet_ntop(socket.AF_INET6, rdata)
                                        else:
                                            answer["raw_data"] = rdata.hex()
                                    except Exception as e:
                                        answer["parse_error"] = str(e)
                                        answer["raw_data"] = rdata.hex()
                                    
                                    answers.append(answer)
                                
                                dns_data["answers"] = answers
                        
                        print(format_json_output("DNS_TCP", dns_data))
                    except Exception as e:
                        print(format_json_output("DNS_TCP_ERROR", {"error": str(e)}))

                # 检查是否是TLS流量 (端口443)
                elif dst_port == 443 or src_port == 443:
                    try:
                        tls_data = {
                            "source": f"{src_ip}:{src_port}",
                            "destination": f"{dst_ip}:{dst_port}",
                            "payload_length": len(tcp_payload)
                        }
                        
                        if len(tcp_payload) > 0:
                            tls_data["content_detected"] = True
                            
                            # 解析TLS记录头
                            if len(tcp_payload) >= 5:
                                content_type = tcp_payload[0]
                                version = struct.unpack('!H', tcp_payload[1:3])[0]
                                length = struct.unpack('!H', tcp_payload[3:5])[0]
                                
                                tls_data["record_header"] = {
                                    "content_type": {
                                        20: "Change Cipher Spec",
                                        21: "Alert",
                                        22: "Handshake",
                                        23: "Application Data"
                                    }.get(content_type, f"Unknown ({content_type})"),
                                    "version": f"0x{version:04x}",
                                    "length": length
                                }

                                # 检查是否是TLS 1.3
                                is_tls13 = version == 0x0304
                                
                                # 处理握手消息
                                if content_type == 22 or (is_tls13 and content_type == 23):  # Handshake or TLS 1.3 Application Data
                                    # 对于TLS 1.3的Application Data，需要检查内部消息类型
                                    if is_tls13 and content_type == 23:
                                        # 检查是否是加密的握手消息
                                        if len(tcp_payload) >= 6:
                                            inner_type = tcp_payload[5]
                                            if inner_type in [1, 2, 11, 16]:  # 握手消息类型
                                                content_type = 22  # 将其视为握手消息
                                    
                                    if content_type == 22 and len(tcp_payload) >= 6:
                                        handshake_type = tcp_payload[5]
                                        tls_data["handshake"] = {
                                            "type": {
                                                1: "Client Hello",
                                                2: "Server Hello",
                                                11: "Certificate",
                                                16: "Client Key Exchange"
                                            }.get(handshake_type, f"Unknown ({handshake_type})")
                                        }
                                        
                                        # 解析Client Hello
                                        if handshake_type == 1 and len(tcp_payload) >= 6:
                                            client_hello = {
                                                "version": f"0x{struct.unpack('!H', tcp_payload[6:8])[0]:04x}",
                                                "random": tcp_payload[8:40].hex(),
                                                "session_id_length": tcp_payload[40]
                                            }
                                            
                                            # 计算TLS指纹 (从Client Hello开始)
                                            fingerprint = hashlib.sha256(tcp_payload[5:]).hexdigest()
                                            client_hello["fingerprint"] = fingerprint
                                            
                                            offset = 41
                                            if client_hello["session_id_length"] > 0:
                                                client_hello["session_id"] = tcp_payload[offset:offset+client_hello["session_id_length"]].hex()
                                                offset += client_hello["session_id_length"]
                                            
                                            # 解析密码套件
                                            if offset + 2 <= len(tcp_payload):
                                                cipher_suites_length = struct.unpack('!H', tcp_payload[offset:offset+2])[0]
                                                offset += 2
                                                
                                                if offset + cipher_suites_length <= len(tcp_payload):
                                                    cipher_suites = []
                                                    for i in range(0, cipher_suites_length, 2):
                                                        if offset + i + 2 <= len(tcp_payload):
                                                            cipher_suite = struct.unpack('!H', tcp_payload[offset+i:offset+i+2])[0]
                                                            cipher_name = {
                                                                0x0001: "TLS_RSA_WITH_NULL_MD5",
                                                                0x0002: "TLS_RSA_WITH_NULL_SHA",
                                                                0x0004: "TLS_RSA_WITH_RC4_128_MD5",
                                                                0x0005: "TLS_RSA_WITH_RC4_128_SHA",
                                                                0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                                                0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                                0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
                                                                0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
                                                                0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
                                                                0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
                                                                0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
                                                                0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                                                0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                                                0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                                0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                                0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                                                                0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                                                                0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                                                                0x1301: "TLS_AES_128_GCM_SHA256",
                                                                0x1302: "TLS_AES_256_GCM_SHA384",
                                                                0x1303: "TLS_CHACHA20_POLY1305_SHA256"
                                                            }.get(cipher_suite, f"Unknown (0x{cipher_suite:04X})")
                                                            cipher_suites.append({
                                                                "id": f"0x{cipher_suite:04X}",
                                                                "name": cipher_name
                                                            })
                                                    client_hello["cipher_suites"] = cipher_suites
                                                    offset += cipher_suites_length
                                            
                                            # 解析压缩方法
                                            if offset + 1 <= len(tcp_payload):
                                                compression_methods_length = tcp_payload[offset]
                                                offset += 1
                                                
                                                if offset + compression_methods_length <= len(tcp_payload):
                                                    compression_methods = []
                                                    for i in range(compression_methods_length):
                                                        if offset + i < len(tcp_payload):
                                                            method = tcp_payload[offset + i]
                                                            compression_methods.append({
                                                                "id": method,
                                                                "name": "NULL" if method == 0 else f"Unknown ({method})"
                                                            })
                                                    client_hello["compression_methods"] = compression_methods
                                                    offset += compression_methods_length
                                            
                                            # 解析扩展
                                            if offset + 2 <= len(tcp_payload):
                                                extensions_length = struct.unpack('!H', tcp_payload[offset:offset+2])[0]
                                                offset += 2
                                                
                                                if offset + extensions_length <= len(tcp_payload):
                                                    extensions = []
                                                    while offset + 4 <= len(tcp_payload):
                                                        ext_type = struct.unpack('!H', tcp_payload[offset:offset+2])[0]
                                                        ext_length = struct.unpack('!H', tcp_payload[offset+2:offset+4])[0]
                                                        offset += 4
                                                        
                                                        if offset + ext_length > len(tcp_payload):
                                                            break
                                                        
                                                        ext_data = tcp_payload[offset:offset+ext_length]
                                                        extension = {
                                                            "type": {
                                                                0: "server_name",
                                                                5: "status_request",
                                                                10: "supported_groups",
                                                                11: "ec_point_formats",
                                                                13: "signature_algorithms",
                                                                16: "application_layer_protocol_negotiation",
                                                                23: "extended_master_secret",
                                                                35: "session_tickets",
                                                                43: "supported_versions",
                                                                45: "psk_key_exchange_modes",
                                                                51: "key_share"
                                                            }.get(ext_type, f"Unknown ({ext_type})"),
                                                            "length": ext_length
                                                        }
                                                        
                                                        # 解析特定扩展的数据
                                                        if ext_type == 0:  # server_name
                                                            if len(ext_data) >= 5:
                                                                name_type = ext_data[0]
                                                                name_length = struct.unpack('!H', ext_data[1:3])[0]
                                                                if name_type == 0 and len(ext_data) >= 3 + name_length:
                                                                    extension["server_name"] = ext_data[3:3+name_length].decode('utf-8', errors='ignore')
                                                        elif ext_type == 10:  # supported_groups
                                                            if len(ext_data) >= 2:
                                                                groups_length = struct.unpack('!H', ext_data[0:2])[0]
                                                                if len(ext_data) >= 2 + groups_length:
                                                                    groups = []
                                                                    for i in range(0, groups_length, 2):
                                                                        if i + 2 <= groups_length:
                                                                            group = struct.unpack('!H', ext_data[2+i:4+i])[0]
                                                                            groups.append({
                                                                                "id": f"0x{group:04X}",
                                                                                "name": {
                                                                                    0x0017: "secp256r1",
                                                                                    0x0018: "secp384r1",
                                                                                    0x0019: "secp521r1",
                                                                                    0x001D: "x25519",
                                                                                    0x001E: "x448"
                                                                                }.get(group, f"Unknown ({group})")
                                                                            })
                                                                    extension["supported_groups"] = groups
                                                        elif ext_type == 13:  # signature_algorithms
                                                            if len(ext_data) >= 2:
                                                                sig_length = struct.unpack('!H', ext_data[0:2])[0]
                                                                if len(ext_data) >= 2 + sig_length:
                                                                    algorithms = []
                                                                    for i in range(0, sig_length, 2):
                                                                        if i + 2 <= sig_length:
                                                                            sig = struct.unpack('!H', ext_data[2+i:4+i])[0]
                                                                            algorithms.append({
                                                                                "id": f"0x{sig:04X}",
                                                                                "name": {
                                                                                    0x0401: "rsa_pkcs1_sha256",
                                                                                    0x0501: "rsa_pkcs1_sha384",
                                                                                    0x0601: "rsa_pkcs1_sha512",
                                                                                    0x0403: "ecdsa_secp256r1_sha256",
                                                                                    0x0503: "ecdsa_secp384r1_sha384",
                                                                                    0x0603: "ecdsa_secp521r1_sha512",
                                                                                    0x0804: "rsa_pss_rsae_sha256",
                                                                                    0x0805: "rsa_pss_rsae_sha384",
                                                                                    0x0806: "rsa_pss_rsae_sha512"
                                                                                }.get(sig, f"Unknown ({sig})")
                                                                            })
                                                                    extension["signature_algorithms"] = algorithms
                                                        
                                                        extensions.append(extension)
                                                        offset += ext_length
                                                    
                                                    client_hello["extensions"] = extensions
                                            
                                            tls_data["handshake"]["client_hello"] = client_hello
                                        
                                        # 解析Server Hello
                                        elif handshake_type == 2 and len(tcp_payload) >= 6:
                                            server_hello = {
                                                "version": f"0x{struct.unpack('!H', tcp_payload[6:8])[0]:04x}",
                                                "random": tcp_payload[8:40].hex(),
                                                "session_id_length": tcp_payload[40]
                                            }
                                            
                                            offset = 41
                                            if server_hello["session_id_length"] > 0:
                                                server_hello["session_id"] = tcp_payload[offset:offset+server_hello["session_id_length"]].hex()
                                                offset += server_hello["session_id_length"]
                                            
                                            # 解析选中的密码套件
                                            if offset + 2 <= len(tcp_payload):
                                                cipher_suite = struct.unpack('!H', tcp_payload[offset:offset+2])[0]
                                                offset += 2
                                                server_hello["selected_cipher_suite"] = {
                                                    "id": f"0x{cipher_suite:04X}",
                                                    "name": {
                                                        0x0001: "TLS_RSA_WITH_NULL_MD5",
                                                        0x0002: "TLS_RSA_WITH_NULL_SHA",
                                                        0x0004: "TLS_RSA_WITH_RC4_128_MD5",
                                                        0x0005: "TLS_RSA_WITH_RC4_128_SHA",
                                                        0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                                        0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
                                                        0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
                                                        0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
                                                        0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
                                                        0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
                                                        0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
                                                        0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                                        0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                                        0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                        0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                        0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                                                        0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                                                        0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                                                        0x1301: "TLS_AES_128_GCM_SHA256",
                                                        0x1302: "TLS_AES_256_GCM_SHA384",
                                                        0x1303: "TLS_CHACHA20_POLY1305_SHA256"
                                                    }.get(cipher_suite, f"Unknown (0x{cipher_suite:04X})")
                                                }
                                            
                                            # 解析压缩方法
                                            if offset + 1 <= len(tcp_payload):
                                                compression_method = tcp_payload[offset]
                                                server_hello["compression_method"] = {
                                                    "id": compression_method,
                                                    "name": "NULL" if compression_method == 0 else f"Unknown ({compression_method})"
                                                }
                                                offset += 1
                                            
                                            # 解析扩展
                                            if offset + 2 <= len(tcp_payload):
                                                extensions_length = struct.unpack('!H', tcp_payload[offset:offset+2])[0]
                                                offset += 2
                                                
                                                if offset + extensions_length <= len(tcp_payload):
                                                    extensions = []
                                                    while offset + 4 <= len(tcp_payload):
                                                        ext_type = struct.unpack('!H', tcp_payload[offset:offset+2])[0]
                                                        ext_length = struct.unpack('!H', tcp_payload[offset+2:offset+4])[0]
                                                        offset += 4
                                                        
                                                        if offset + ext_length > len(tcp_payload):
                                                            break
                                                        
                                                        ext_data = tcp_payload[offset:offset+ext_length]
                                                        extension = {
                                                            "type": {
                                                                0: "server_name",
                                                                5: "status_request",
                                                                10: "supported_groups",
                                                                11: "ec_point_formats",
                                                                13: "signature_algorithms",
                                                                16: "application_layer_protocol_negotiation",
                                                                23: "extended_master_secret",
                                                                35: "session_tickets",
                                                                43: "supported_versions",
                                                                45: "psk_key_exchange_modes",
                                                                51: "key_share"
                                                            }.get(ext_type, f"Unknown ({ext_type})"),
                                                            "length": ext_length
                                                        }
                                                        
                                                        # 解析特定扩展的数据
                                                        if ext_type == 10:  # supported_groups
                                                            if len(ext_data) >= 2:
                                                                groups_length = struct.unpack('!H', ext_data[0:2])[0]
                                                                if len(ext_data) >= 2 + groups_length:
                                                                    groups = []
                                                                    for i in range(0, groups_length, 2):
                                                                        if i + 2 <= groups_length:
                                                                            group = struct.unpack('!H', ext_data[2+i:4+i])[0]
                                                                            groups.append({
                                                                                "id": f"0x{group:04X}",
                                                                                "name": {
                                                                                    0x0017: "secp256r1",
                                                                                    0x0018: "secp384r1",
                                                                                    0x0019: "secp521r1",
                                                                                    0x001D: "x25519",
                                                                                    0x001E: "x448"
                                                                                }.get(group, f"Unknown ({group})")
                                                                            })
                                                                    extension["supported_groups"] = groups
                                                        elif ext_type == 43:  # supported_versions
                                                            if len(ext_data) >= 2:
                                                                version_length = ext_data[0]
                                                                if len(ext_data) >= 1 + version_length:
                                                                    versions = []
                                                                    for i in range(version_length):
                                                                        if i + 1 <= version_length:
                                                                            version = struct.unpack('!H', ext_data[1+i*2:3+i*2])[0]
                                                                            versions.append(f"0x{version:04X}")
                                                                    extension["supported_versions"] = versions
                                                        
                                                        extensions.append(extension)
                                                        offset += ext_length
                                                    
                                                    server_hello["extensions"] = extensions
                                            
                                            tls_data["handshake"]["server_hello"] = server_hello
                                        
                                        # 解析Certificate消息
                                        elif handshake_type == 11 and len(tcp_payload) >= 6:
                                            cert_data = {
                                                "certificates_length": struct.unpack('!I', tcp_payload[6:10])[0]
                                            }
                                            
                                            offset = 10
                                            certificates = []
                                            
                                            while offset + 3 <= len(tcp_payload):
                                                cert_length = struct.unpack('!I', b'\x00' + tcp_payload[offset:offset+3])[0]
                                                offset += 3
                                                
                                                if offset + cert_length > len(tcp_payload):
                                                    break
                                                
                                                cert_data = tcp_payload[offset:offset+cert_length]
                                                certificates.append({
                                                    "length": cert_length,
                                                    "data": cert_data.hex()
                                                })
                                                offset += cert_length
                                            
                                            tls_data["handshake"]["certificates"] = certificates
                                        
                                        # 解析Client Key Exchange消息
                                        elif handshake_type == 16 and len(tcp_payload) >= 6:
                                            key_exchange = {
                                                "public_key_length": tcp_payload[6]
                                            }
                                            
                                            if key_exchange["public_key_length"] > 0 and len(tcp_payload) >= 7 + key_exchange["public_key_length"]:
                                                key_exchange["public_key"] = tcp_payload[7:7+key_exchange["public_key_length"]].hex()
                                            
                                            tls_data["handshake"]["client_key_exchange"] = key_exchange
                        
                        print(format_json_output("TLS", tls_data))
                    except Exception as e:
                        print(format_json_output("TLS_ERROR", {"error": str(e)}))

            # 检查是否是ICMP
            elif ip_protocol == 1:  # 1 is ICMP
                try:
                    icmp_header = struct.unpack('!BBHHH', packet[14+ip_header_length:14+ip_header_length+8])
                    icmp_type = icmp_header[0]
                    icmp_code = icmp_header[1]
                    icmp_checksum = icmp_header[2]
                    icmp_id = icmp_header[3]
                    icmp_seq = icmp_header[4]
                    
                    icmp_data = {
                        "source": src_ip,
                        "destination": dst_ip,
                        "type": icmp_type,
                        "code": icmp_code,
                        "checksum": f"0x{icmp_checksum:04x}"
                    }
                    
                    icmp_types = {
                        0: "Echo Reply",
                        3: "Destination Unreachable",
                        4: "Source Quench",
                        5: "Redirect Message",
                        8: "Echo Request",
                        9: "Router Advertisement",
                        10: "Router Solicitation",
                        11: "Time Exceeded",
                        12: "Parameter Problem",
                        13: "Timestamp",
                        14: "Timestamp Reply",
                        15: "Information Request",
                        16: "Information Reply"
                    }
                    
                    icmp_data["type_name"] = icmp_types.get(icmp_type, f"Unknown Type ({icmp_type})")
                    
                    if icmp_type in [0, 8]:
                        icmp_data.update({
                            "id": icmp_id,
                            "sequence": icmp_seq
                        })
                    
                    print(format_json_output("ICMP", icmp_data))
                except Exception as e:
                    print(format_json_output("ICMP_ERROR", {"error": str(e)}))

            # 检查是否是DNS (UDP)
            elif ip_protocol == 17:  # 17 is UDP
                udp_header = struct.unpack('!HHHH', packet[14+ip_header_length:14+ip_header_length+8])
                src_port = udp_header[0]
                dst_port = udp_header[1]
                
                if src_port == 53 or dst_port == 53:
                    try:
                        udp_payload = packet[14+ip_header_length+8:]
                        dns_data = {
                            "source": f"{src_ip}:{src_port}",
                            "destination": f"{dst_ip}:{dst_port}",
                            "payload_length": len(udp_payload)
                        }
                        
                        if len(udp_payload) >= 12:
                            dns_header = struct.unpack('!HHHHHH', udp_payload[:12])
                            dns_data.update({
                                "transaction_id": f"0x{dns_header[0]:04x}",
                                "flags": f"0x{dns_header[1]:04x}",
                                "questions": dns_header[2],
                                "answer_rrs": dns_header[3],
                                "authority_rrs": dns_header[4],
                                "additional_rrs": dns_header[5]
                            })
                            
                            # 解析DNS标志
                            flags = dns_header[1]
                            dns_data["flags_details"] = {
                                "qr": bool(flags & 0x8000),  # Query/Response
                                "opcode": (flags & 0x7800) >> 11,  # Operation Code
                                "aa": bool(flags & 0x0400),  # Authoritative Answer
                                "tc": bool(flags & 0x0200),  # Truncated
                                "rd": bool(flags & 0x0100),  # Recursion Desired
                                "ra": bool(flags & 0x0080),  # Recursion Available
                                "z": (flags & 0x0070) >> 4,  # Reserved
                                "rcode": flags & 0x000F  # Response Code
                            }
                            
                            # 解析DNS问题部分
                            if dns_header[2] > 0:
                                questions = []
                                offset = 12
                                for i in range(dns_header[2]):
                                    if offset >= len(udp_payload):
                                        break
                                    
                                    # 解析域名
                                    domain_parts = []
                                    while offset < len(udp_payload):
                                        length = udp_payload[offset]
                                        if length == 0:
                                            offset += 1
                                            break
                                        if length >= 0xC0:  # DNS压缩
                                            ptr = ((length & 0x3F) << 8) | udp_payload[offset + 1]
                                            offset += 2
                                            break
                                        offset += 1
                                        if offset + length > len(udp_payload):
                                            break
                                        domain_parts.append(udp_payload[offset:offset+length].decode('utf-8', errors='ignore'))
                                        offset += length
                                    domain = '.'.join(domain_parts)
                                    
                                    # 解析类型和类
                                    if offset + 4 > len(udp_payload):
                                        break
                                    qtype, qclass = struct.unpack('!HH', udp_payload[offset:offset+4])
                                    offset += 4
                                    
                                    questions.append({
                                        "name": domain,
                                        "type": qtype,
                                        "class": qclass
                                    })
                                
                                dns_data["questions"] = questions
                            
                            # 解析DNS回答部分
                            if dns_header[3] > 0:
                                answers = []
                                for i in range(dns_header[3]):
                                    if offset >= len(udp_payload):
                                        break
                                    
                                    # 解析域名
                                    domain_parts = []
                                    while offset < len(udp_payload):
                                        length = udp_payload[offset]
                                        if length == 0:
                                            offset += 1
                                            break
                                        if length >= 0xC0:  # DNS压缩
                                            ptr = ((length & 0x3F) << 8) | udp_payload[offset + 1]
                                            offset += 2
                                            break
                                        offset += 1
                                        if offset + length > len(udp_payload):
                                            break
                                        domain_parts.append(udp_payload[offset:offset+length].decode('utf-8', errors='ignore'))
                                        offset += length
                                    domain = '.'.join(domain_parts)
                                    
                                    # 解析记录头
                                    if offset + 10 > len(udp_payload):
                                        break
                                    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', udp_payload[offset:offset+10])
                                    offset += 10
                                    
                                    # 解析记录数据
                                    if offset + rdlength > len(udp_payload):
                                        break
                                    rdata = udp_payload[offset:offset+rdlength]
                                    offset += rdlength
                                    
                                    answer = {
                                        "name": domain,
                                        "type": rtype,
                                        "class": rclass,
                                        "ttl": ttl,
                                        "rdlength": rdlength
                                    }
                                    
                                    # 根据记录类型解析数据
                                    try:
                                        if rtype == 1:  # A记录
                                            if len(rdata) == 4:
                                                answer["ip"] = socket.inet_ntoa(rdata)
                                        elif rtype == 5:  # CNAME记录
                                            answer["cname"] = '.'.join([rdata[i:i+1].decode('utf-8', errors='ignore') for i in range(0, len(rdata), 1)])
                                        elif rtype == 15:  # MX记录
                                            if len(rdata) >= 2:
                                                preference = struct.unpack('!H', rdata[:2])[0]
                                                mx = '.'.join([rdata[i:i+1].decode('utf-8', errors='ignore') for i in range(2, len(rdata), 1)])
                                                answer["mx"] = mx
                                                answer["preference"] = preference
                                        elif rtype == 16:  # TXT记录
                                            answer["txt"] = rdata.decode('utf-8', errors='ignore')
                                        elif rtype == 28:  # AAAA记录
                                            if len(rdata) == 16:
                                                answer["ipv6"] = socket.inet_ntop(socket.AF_INET6, rdata)
                                        else:
                                            answer["raw_data"] = rdata.hex()
                                    except Exception as e:
                                        answer["parse_error"] = str(e)
                                        answer["raw_data"] = rdata.hex()
                                    
                                    answers.append(answer)
                                
                                dns_data["answers"] = answers
                        
                        print(format_json_output("DNS", dns_data))
                    except Exception as e:
                        print(format_json_output("DNS_ERROR", {"error": str(e)}))

    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        s.close()

if __name__ == "__main__":
    main()
