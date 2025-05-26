#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主程序 - DNS流量捕获和分析工具
"""

from detection import PacketParser, match

import os
import sys
import logging
import argparse
import traceback
from datetime import datetime
import ipaddress
import time
import struct
import json
import hashlib

# 添加当前目录到路径，以便导入analyzers包
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scapy.all import sniff, DNS, IP, UDP, BOOTP, DHCP, ICMP, wrpcap, rdpcap, TCP, Raw, IPv6
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import _TLSHandshake

from analyzers.session import Session
from analyzers.types import FieldObject

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("FlowCapture")

# 导入DNS模块和scapy
from analyzers import dns
from analyzers import dhcp  # 添加DHCP模块导入
from analyzers import icmp  # 添加ICMP模块导入
from analyzers import http  # 添加HTTP模块导入
from analyzers import smb   # 添加SMB模块导入
from analyzers import socks  # 添加SOCKS模块导入
from analyzers import ssh   # 添加SSH模块导入
from analyzers import tls   # 添加TLS模块导入
from analyzers.session import Session
from analyzers.types import FieldObject

# DNS协议解析统计
dns_packets_count = 0
dns_queries_count = 0
dns_responses_count = 0
dns_domains = set()
dns_response_codes = {}
dns_ips = set()

# DHCP协议解析统计
dhcp_packets_count = 0
dhcp_discover_count = 0
dhcp_offer_count = 0
dhcp_request_count = 0
dhcp_ack_count = 0
dhcp_nak_count = 0
dhcp_release_count = 0
dhcp_decline_count = 0
dhcp_inform_count = 0
dhcp_macs = set()
dhcp_ips = set()
dhcp_msg_types = {}

# ICMP协议解析统计
icmp_packets_count = 0
icmp_echo_request_count = 0
icmp_echo_reply_count = 0
icmp_dest_unreachable_count = 0
icmp_time_exceeded_count = 0
icmp_redirect_count = 0
icmp_source_quench_count = 0
icmp_parameter_problem_count = 0
icmp_timestamp_request_count = 0
icmp_timestamp_reply_count = 0
icmp_info_request_count = 0
icmp_info_reply_count = 0
icmp_address_mask_request_count = 0
icmp_address_mask_reply_count = 0
icmp_hosts = set()
icmp_types = {}

# HTTP协议解析统计
http_packets_count = 0
http_get_count = 0
http_post_count = 0
http_put_count = 0
http_delete_count = 0
http_head_count = 0
http_options_count = 0
http_connect_count = 0
http_trace_count = 0
http_patch_count = 0
http_1xx_count = 0
http_2xx_count = 0
http_3xx_count = 0
http_4xx_count = 0
http_5xx_count = 0
http_hosts = set()
http_user_agents = set()
http_content_types = set()
http_urls = set()

# SMB协议解析统计
smb_packets_count = 0
smb1_packets_count = 0
smb2_packets_count = 0
smb_commands = {}
smb_status_codes = {}
smb_dialects = set()
smb_shares = set()
smb_users = set()
smb_hosts = set()
smb_files = set()

# SOCKS协议解析统计
socks_packets_count = 0
socks4_packets_count = 0
socks5_packets_count = 0
socks_hosts = set()
socks_users = set()
socks_ips = set()
socks_ports = set()
socks_auth_count = 0
socks_version_counts = {}

# SSH协议解析统计
ssh_packets_count = 0
ssh_client_versions = set()
ssh_server_versions = set()
ssh_kex_methods = set()
ssh_auth_methods = set()
ssh_cipher_client = set()
ssh_cipher_server = set()
ssh_mac_client = set()
ssh_mac_server = set()
ssh_hosts = set()
ssh_usernames = set()
ssh_kex_count = 0
ssh_auth_count = 0

# TLS协议解析统计
tls_packets_count = 0
tls_client_hello_count = 0
tls_server_hello_count = 0
tls_certificate_count = 0
tls_handshake_count = 0
tls_alert_count = 0
tls_application_data_count = 0
tls_versions = set()
tls_cipher_suites = set()
tls_extensions = set()
tls_hosts = set()
tls_ja3_fingerprints = set()
tls_ja3s_fingerprints = set()
tls_ja4_fingerprints = set()
tls_client_count = 0
tls_server_count = 0

# TLS常量定义
TLS_STAGE_INIT = 0
TLS_STAGE_CLIENT_HELLO = 1
TLS_STAGE_SERVER_HELLO = 2
TLS_STAGE_CERTIFICATE = 3
TLS_STAGE_SERVER_DONE = 4
TLS_STAGE_CLIENT_KEY_EXCHANGE = 5
TLS_STAGE_CHANGE_CIPHER = 6
TLS_STAGE_APPLICATION = 7
TLS_STAGE_ALERT = 8
TLS_STAGE_CLOSED = 9

TLS_STAGE_NAMES = {
    TLS_STAGE_INIT: "初始化",
    TLS_STAGE_CLIENT_HELLO: "客户端握手请求",
    TLS_STAGE_SERVER_HELLO: "服务器握手响应",
    TLS_STAGE_CERTIFICATE: "证书交换",
    TLS_STAGE_SERVER_DONE: "服务器握手完成",
    TLS_STAGE_CLIENT_KEY_EXCHANGE: "客户端密钥交换",
    TLS_STAGE_CHANGE_CIPHER: "加密算法变更",
    TLS_STAGE_APPLICATION: "应用数据",
    TLS_STAGE_ALERT: "警告",
    TLS_STAGE_CLOSED: "连接关闭"
}

# 跟踪TLS连接状态
tls_connections = {}

run_match = match.RuleMatch()

# 添加ICMP对象类，类似于DNS中的Dns类
class Icmp:
    """ICMP对象类，用于存储ICMP数据包信息"""
    def __init__(self, type_id=0, code_id=0):
        self.type = type_id
        self.type_name = ""
        self.code = code_id
        self.src_ip = ""
        self.dst_ip = ""
        self.id = 0
        self.seq = 0
        self.timestamp = ""
        self.payload = b''
        
    def __str__(self):
        return f"ICMP类型:{self.type_name}({self.type}), 代码:{self.code}, ID:{self.id}, SEQ:{self.seq}"

# 添加HTTP对象类，用于存储HTTP数据包信息
class Http:
    """HTTP对象类，用于存储HTTP数据包信息"""
    def __init__(self):
        # 通用属性
        self.is_request = True
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.timestamp = ""
        
        # 请求特有属性
        self.method = ""
        self.uri = ""
        self.version = ""
        self.host = ""
        self.user_agent = ""
        self.content_type = ""
        self.content_length = 0
        self.headers = {}
        
        # 响应特有属性
        self.status_code = 0
        self.status_message = ""
        self.server = ""
        
        # 内容
        self.body = b''
        
    def __str__(self):
        if self.is_request:
            return f"HTTP请求: {self.method} {self.uri} {self.version}, 主机: {self.host}"
        else:
            return f"HTTP响应: {self.version} {self.status_code} {self.status_message}"

# 添加TLS对象类，用于存储TLS数据包信息
class Tls:
    """TLS对象类，用于存储TLS数据包信息"""
    def __init__(self):
        # 通用属性
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.timestamp = ""
        
        # TLS记录层
        self.record_type = 0
        self.record_version = 0
        self.record_length = 0
        
        # TLS握手层
        self.handshake_type = 0
        self.handshake_length = 0
        self.is_client_hello = False
        self.is_server_hello = False
        
        # 版本信息
        self.version = 0
        self.version_str = ""
        
        # 密码套件
        self.cipher_suite = 0
        self.cipher_suite_str = ""
        
        # 扩展信息
        self.extensions = []
        
        # 指纹信息
        self.ja3 = ""
        self.ja3s = ""
        self.ja4 = ""
        self.ja4_raw = ""
        
        # 原始数据
        self.payload = b''
        
    def __str__(self):
        if self.is_client_hello:
            return f"TLS客户端握手: 版本={self.version_str}, JA3={self.ja3}"
        elif self.is_server_hello:
            return f"TLS服务器握手: 版本={self.version_str}, 密码套件={self.cipher_suite_str}, JA3S={self.ja3s}"
        else:
            return f"TLS数据包: 记录类型={self.record_type}, 版本={self.version_str}"

def process_dns_packet(packet):
    """处理捕获的DNS数据包"""
    global dns_packets_count, dns_queries_count, dns_responses_count, dns_domains, dns_response_codes, dns_ips
    
    # 增加包计数
    dns_packets_count += 1
    
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        
        # 创建会话对象
        session = Session()
        logger.debug("创建会话对象用于DNS分析")
        
        # 提取IP信息(如果有)
        src_ip = None
        dst_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            logger.debug(f"IP层信息: 源={src_ip}, 目标={dst_ip}")
            
        # 提取DNS查询/响应信息
        if dns_layer.qr == 0:  # DNS查询
            dns_queries_count += 1
            
            if dns_layer.qd and dns_layer.qd.qname:
                domain = dns_layer.qd.qname.decode('utf-8', errors='replace').rstrip('.')
                dns_domains.add(domain)
                logger.info(f"DNS查询: {domain}")
                
                # 创建DNS查询对象
                dns_query = dns.DnsQuery()
                dns_query.hostname = domain
                dns_query.packet_id = dns_layer.id
                logger.debug(f"DNS查询对象: 主机名={domain}, 包ID={dns_layer.id}")
                
                if dns_layer.qd.qtype:
                    dns_query.type_id = dns_layer.qd.qtype
                    logger.debug(f"DNS查询类型: {dns_layer.qd.qtype}")
                if dns_layer.qd.qclass:
                    dns_query.class_id = dns_layer.qd.qclass
                    logger.debug(f"DNS查询类: {dns_layer.qd.qclass}")
                if hasattr(dns_layer, 'opcode'):
                    dns_query.opcode_id = dns_layer.opcode
                    dns_query.opcode = dns.opcodes[dns_layer.opcode] if dns_layer.opcode < len(dns.opcodes) else str(dns_layer.opcode)
                    logger.debug(f"DNS操作码: {dns_query.opcode} ({dns_query.opcode_id})")
                
                # 创建DNS对象
                logger.debug("创建DNS对象")
                dns_obj = dns.Dns(rcode_id=0, headerFlags=0)
                dns_obj.query = dns_query
                
                # 添加到会话
                field_obj = FieldObject()
                field_obj.object = dns_obj
                field_obj.objcet = field_obj.object  # 适应dns_save函数的需求
                session.fields['dnsField'] = field_obj
                logger.debug("DNS对象添加到会话")
                
                # 输出DNS查询类型
                if hasattr(dns_layer.qd, 'qtype'):
                    qtype = dns_layer.qd.qtype
                    qtype_name = "UNKNOWN"
                    
                    # 查找DNS查询类型名称
                    for type_attr in dir(dns.DnsType):
                        if not type_attr.startswith('_') and type_attr.startswith('DNS_RR_'):
                            type_value = getattr(dns.DnsType, type_attr)
                            if isinstance(type_value, tuple) and len(type_value) > 0 and type_value[0] == qtype:
                                qtype_name = type_attr[7:]  # 去掉DNS_RR_前缀
                                break
                    
                    logger.info(f"  查询类型: {qtype_name} ({qtype})")
                
                # 使用DNS哈希函数处理域名
                hash_value = dns.dns_hash(domain)
                logger.debug(f"DNS哈希值 ({domain}): {hash_value}")
                
                # 检查域名是否为Punycode
                if "xn--" in domain:
                    logger.debug(f"发现Punycode域名: {domain}")
                    # 添加到特定会话字段用于测试
                    puny_obj = dns.Dns(rcode_id=0, headerFlags=0)
                    puny_query = dns.DnsQuery()
                    puny_query.hostname = domain
                    puny_obj.query = puny_query
                    field_obj_puny = FieldObject()
                    field_obj_puny.object = puny_obj
                    field_obj_puny.objcet = field_obj_puny.object
                    session.fields['dnsFieldPuny'] = field_obj_puny
                    
                    # 调用puny回调函数
                    puny_set = dns.dns_getcb_puny(session)
                    logger.debug(f"Punycode域名集合: {puny_set}")
                
                # 验证域名UTF8
                utf8_valid = dns.is_valid_utf8(domain)
                logger.debug(f"域名UTF8验证: {utf8_valid}")
                
        else:  # DNS响应
            dns_responses_count += 1
            
            # 提取响应代码
            rcode = dns_layer.rcode
            rcode_name = dns.rcodes[rcode] if rcode < len(dns.rcodes) else str(rcode)
            
            # 更新响应代码统计
            dns_response_codes[rcode_name] = dns_response_codes.get(rcode_name, 0) + 1
            
            logger.info(f"DNS响应: 代码={rcode_name}, 回答数量={dns_layer.ancount}")
            
            # 创建DNS对象
            logger.debug("创建DNS响应对象")
            # 使用正确的方式获取DNS包的标志
            # Scapy DNS包没有直接的flags属性，使用0代替，或者从其他属性构建
            header_flags = 0
            try:
                # 尝试手动构建标志位
                if hasattr(dns_layer, 'qr'):
                    header_flags |= (dns_layer.qr << 15)
                if hasattr(dns_layer, 'opcode'):
                    header_flags |= (dns_layer.opcode << 11)
                if hasattr(dns_layer, 'aa'):
                    header_flags |= (dns_layer.aa << 10)
                if hasattr(dns_layer, 'tc'):
                    header_flags |= (dns_layer.tc << 9)
                if hasattr(dns_layer, 'rd'):
                    header_flags |= (dns_layer.rd << 8)
                if hasattr(dns_layer, 'ra'):
                    header_flags |= (dns_layer.ra << 7)
                if hasattr(dns_layer, 'z'):
                    header_flags |= (dns_layer.z << 6)
                # rcode已经单独提取
                logger.debug(f"构建的DNS标志位: {bin(header_flags)}")
            except Exception as e:
                logger.debug(f"构建DNS标志位时出错: {e}，使用默认值0")
                
            dns_obj = dns.Dns(rcode_id=rcode, headerFlags=header_flags)
            dns_obj.rcode_id = rcode
            dns_obj.rcode = rcode_name
            
            # 如果有查询部分，添加查询信息
            if dns_layer.qd and dns_layer.qd.qname:
                domain = dns_layer.qd.qname.decode('utf-8', errors='replace').rstrip('.')
                logger.debug(f"DNS响应中的查询域名: {domain}")
                
                dns_query = dns.DnsQuery()
                dns_query.hostname = domain
                dns_query.packet_id = dns_layer.id
                
                if dns_layer.qd.qtype:
                    dns_query.type_id = dns_layer.qd.qtype
                if dns_layer.qd.qclass:
                    dns_query.class_id = dns_layer.qd.qclass
                
                dns_obj.query = dns_query
            
            # 处理DNS回答
            if dns_layer.an:
                logger.debug(f"处理DNS回答记录: {dns_layer.ancount}条")
                dns_obj.answers = dns.DnsAnswerHead()
                
                for i in range(dns_layer.ancount):
                    try:
                        an = dns_layer.an[i]
                        
                        # 检查必需的属性
                        if hasattr(an, 'rdata') and hasattr(an, 'type') and hasattr(an, 'ttl'):
                            # 创建回答对象
                            answer = dns.DnsAnswer(
                                ipA=0,  # 默认值，会根据记录类型更新
                                type_id=an.type,
                                ttl=an.ttl,
                                class_=an.class_ if hasattr(an, 'class_') else 1,
                                type_=an.type
                            )
                            answer.name = an.rrname.decode('utf-8', errors='replace').rstrip('.')
                            
                            # 根据不同的回答类型设置不同字段
                            if an.type == 1:  # A记录
                                answer.type_ = dns.DnsType.DNS_RR_A
                                if hasattr(an, 'rdata'):
                                    try:
                                        ip_str = an.rdata
                                        if isinstance(ip_str, bytes):
                                            ip_str = ip_str.decode('utf-8', errors='replace')
                                        logger.info(f"  A记录: {answer.name} -> {ip_str}")
                                        # 将IP字符串转换为整数表示
                                        ip = int(ipaddress.IPv4Address(ip_str))
                                        answer.ipA = ip
                                        
                                        # 保存IP地址到会话中，用于测试dns_save_ip_ghash
                                        if not hasattr(session, 'ip_dict'):
                                            session.ip_dict = {}
                                        session.ip_dict[ip_str] = 1
                                        dns_ips.add(ip)
                                    except Exception as e:
                                        logger.error(f"  无法解析A记录IP地址: {an.rdata}, 错误: {e}")
                            
                            elif an.type == 5:  # CNAME记录
                                answer.type_ = dns.DnsType.DNS_RR_CNAME
                                if hasattr(an, 'rdata'):
                                    cname = an.rdata
                                    if isinstance(cname, bytes):
                                        cname = cname.decode('utf-8', errors='replace').rstrip('.')
                                    logger.info(f"  CNAME记录: {answer.name} -> {cname}")
                                    answer.cname = cname
                                    logger.debug(f"处理CNAME记录: {answer.name} -> {cname}")
                            
                            elif an.type == 28:  # AAAA记录
                                answer.type_ = dns.DnsType.DNS_RR_AAAA
                                if hasattr(an, 'rdata'):
                                    try:
                                        ip_str = an.rdata
                                        if isinstance(ip_str, bytes):
                                            ip_str = ip_str.decode('utf-8', errors='replace')
                                        logger.info(f"  AAAA记录: {answer.name} -> {ip_str}")
                                        answer.ipAAAA = ipaddress.IPv6Address(ip_str)
                                        logger.debug(f"处理AAAA记录: {answer.name} -> {ip_str}")
                                    except Exception as e:
                                        logger.error(f"  无法解析AAAA记录IP地址: {an.rdata}, 错误: {e}")
                            
                            elif an.type == 15:  # MX记录
                                answer.type_ = dns.DnsType.DNS_RR_MX
                                if hasattr(an, 'rdata'):
                                    try:
                                        mx_data = an.rdata
                                        if isinstance(mx_data, bytes):
                                            mx_data = mx_data.decode('utf-8', errors='replace')
                                        logger.info(f"  MX记录: {answer.name} -> {mx_data}")
                                        answer.hostname = mx_data
                                        logger.debug(f"处理MX记录: {answer.name} -> {mx_data}")
                                    except Exception as e:
                                        logger.error(f"  无法解析MX记录: {an.rdata}, 错误: {e}")
                            
                            elif an.type == 2:  # NS记录
                                answer.type_ = dns.DnsType.DNS_RR_NS
                                if hasattr(an, 'rdata'):
                                    try:
                                        ns_data = an.rdata
                                        if isinstance(ns_data, bytes):
                                            ns_data = ns_data.decode('utf-8', errors='replace')
                                        logger.info(f"  NS记录: {answer.name} -> {ns_data}")
                                        answer.hostname = ns_data
                                        logger.debug(f"处理NS记录: {answer.name} -> {ns_data}")
                                    except Exception as e:
                                        logger.error(f"  无法解析NS记录: {an.rdata}, 错误: {e}")
                            
                            # 将回答添加到DNS对象
                            dns_obj.answers.push_tail(answer)
                            logger.debug(f"添加DNS回答到对象: 类型={answer.type_}, 名称={answer.name}")
                        else:
                            logger.error(f"  回答缺少必要属性: {dir(an)}")
                    
                    except Exception as e:
                        logger.error(f"  处理DNS回答时出错: {e}")
            
            # 添加到会话
            field_obj = FieldObject()
            field_obj.object = dns_obj
            field_obj.objcet = field_obj.object  # 适应dns_save函数的需求
            session.fields['dnsField'] = field_obj
            logger.debug("DNS响应对象添加到会话")
            
            # 如果有IP地址字典，尝试调用dns_save_ip_ghash
            if hasattr(session, 'ip_dict') and session.ip_dict:
                try:
                    from analyzers import BSB
                    bsb = BSB.BSB(bytearray(100), 100)
                    logger.debug(f"调用dns_save_ip_ghash保存IP: {session.ip_dict}")
                    dns.dns_save_ip_ghash(bsb, session, session.ip_dict, "dns_ips")
                    logger.debug(f"IP哈希保存结果大小: {bsb.ptr}字节")
                except Exception as e:
                    logger.error(f"保存IP哈希失败: {e}")
        
        # 调用dns_save保存DNS对象
        try:
            from analyzers import BSB
            bsb = BSB.BSB(bytearray(200), 200)
            logger.debug("调用dns_save保存DNS对象")
            
            # 确保field_obj.object中的所有属性值都是正确的类型
            if hasattr(dns_obj, 'rcode') and isinstance(dns_obj.rcode, str):
                # 如果rcode是字符串，尝试转换为整数
                try:
                    dns_obj.rcode = dns.rcodes.index(dns_obj.rcode)
                    logger.debug(f"将rcode从字符串转换为整数: {dns_obj.rcode}")
                except (ValueError, IndexError):
                    # 如果找不到，使用rcode_id
                    dns_obj.rcode = dns_obj.rcode_id
                    logger.debug(f"使用rcode_id作为rcode的值: {dns_obj.rcode}")
            
            # 检查其他可能导致类型错误的属性
            if hasattr(dns_obj, 'query') and hasattr(dns_obj.query, 'opcode') and isinstance(dns_obj.query.opcode, str):
                try:
                    dns_obj.query.opcode = dns.opcodes.index(dns_obj.query.opcode)
                    logger.debug(f"将opcode从字符串转换为整数: {dns_obj.query.opcode}")
                except (ValueError, IndexError):
                    # 如果找不到，使用opcode_id
                    dns_obj.query.opcode = dns_obj.query.opcode_id
                    logger.debug(f"使用opcode_id作为opcode的值: {dns_obj.query.opcode}")
            
            # 递归处理所有可能的字符串属性
            def convert_str_attributes(obj):
                """递归转换对象中的字符串属性为整数，以避免&操作错误"""
                if obj is None:
                    return
                
                # 处理常见属性
                for attr_name in ['rcode', 'opcode', 'type', 'class']:
                    if hasattr(obj, attr_name) and isinstance(getattr(obj, attr_name), str):
                        attr_id_name = f"{attr_name}_id"
                        if hasattr(obj, attr_id_name):
                            setattr(obj, attr_name, getattr(obj, attr_id_name))
                            logger.debug(f"转换属性 {attr_name} 为 {getattr(obj, attr_name)}")
                
                # 处理特殊属性
                if hasattr(obj, 'answers') and obj.answers:
                    # 遍历answers链表
                    current = obj.answers.t_head
                    while current:
                        convert_str_attributes(current)
                        current = getattr(current, 't_next', None)
                
                # 递归处理嵌套对象
                for attr_name in ['query', 'response']:
                    if hasattr(obj, attr_name) and getattr(obj, attr_name) is not None:
                        convert_str_attributes(getattr(obj, attr_name))
            
            # 在整个DNS对象上应用转换
            convert_str_attributes(dns_obj)
            
            # 修复field_obj的属性，确保同时有object和objcet
            field_obj.objcet = field_obj.object
            
            # 创建FieldObject
            field_obj = FieldObject()
            field_obj.object = dns_obj
            field_obj.objcet = dns_obj  # 兼容性写法
            field_obj.objects = {}  # 初始化objects字典
            
            # 尝试调用dns_save函数
            try:
                dns.Dns.dns = dns_obj  # 设置全局DNS对象
                dns.dns_save(bsb, field_obj, session)
                if not bsb.error:
                    logger.info(f"DNS对象保存结果大小: {bsb.ptr}字节")
                else:
                    logger.error("保存DNS对象时发生错误")
            except AttributeError as e:
                logger.error(f"保存DNS对象时缺少必要属性: {e}")
            except Exception as e:
                logger.error(f"保存DNS对象失败: {e}")
        except Exception as e:
            logger.error(f"保存DNS对象失败: {e}")
        
        # 使用各种回调函数来提取信息
        logger.debug("\n----- 调用DNS回调函数提取信息 -----")
        host_set = dns.dns_getcb_host(session)
        if host_set:
            logger.debug(f"主机集合: {host_set}")
        
        query_host_set = dns.dns_getcb_query_host(session)
        if query_host_set:
            logger.debug(f"查询主机集合: {query_host_set}")
        
        status_set = dns.dns_getcb_status(session)
        if status_set:
            logger.debug(f"状态码集合: {status_set}")
        
        query_type_set = dns.dns_getcb_query_type(session)
        if query_type_set:
            logger.debug(f"查询类型集合: {query_type_set}")
        
        query_class_set = dns.dns_getcb_query_class(session)
        if query_class_set:
            logger.debug(f"查询类集合: {query_class_set}")
        
        # 如果是响应，尝试提取名称服务器和邮件服务器
        if dns_layer.qr == 1:
            nameserver_set = dns.dns_getcb_host_nameserver(session)
            if nameserver_set:
                logger.debug(f"名称服务器集合: {nameserver_set}")
            
            mailserver_set = dns.dns_getcb_host_mailserver(session)
            if mailserver_set:
                logger.debug(f"邮件服务器集合: {mailserver_set}")
        
        # 将数据包原始数据提供给DNS解析器进行深度解析
        if hasattr(packet, 'raw_packet_cache') and packet.raw_packet_cache:
            raw_data = packet.raw_packet_cache
            logger.debug(f"处理原始数据包: {len(raw_data)}字节")
            
            # 如果是UDP包，定位到UDP数据部分
            if packet.haslayer(UDP):
                try:
                    udp_layer = packet[UDP]
                    udp_header_size = 8  # UDP头部大小为8字节
                    
                    # 创建metadata字典
                    metadata = {'src_ip': src_ip, 'dst_ip': dst_ip}
                    logger.debug(f"元数据: {metadata}")
                    
                    # 直接使用udp_layer偏移量来获取DNS数据
                    if hasattr(udp_layer, 'underlayer'):
                        # 尝试安全地获取数据
                        udp_payload_offset = 8  # UDP头部固定为8字节
                        
                        # 如果是IP包，可以尝试从IP header获取偏移
                        if hasattr(packet, 'IP'):
                            ip_header_len = packet[IP].ihl * 4
                            dns_data_offset = ip_header_len + udp_payload_offset
                            logger.debug(f"DNS数据偏移: IP头部={ip_header_len}, UDP头部={udp_payload_offset}")
                        else:
                            # 如果获取不到确切位置，尝试从UDP数据中提取
                            dns_data = bytes(udp_layer.payload)
                            logger.debug(f"从UDP负载提取DNS数据: {len(dns_data)}字节")
                            logger.debug(f"调用dns_parser解析UDP负载")
                            dns.dns_parser(session, 0, bytearray(dns_data), len(dns_data), metadata)
                            return
                        
                        # 获取DNS数据
                        dns_data = raw_data[dns_data_offset:]
                        logger.debug(f"从原始数据提取DNS部分: {len(dns_data)}字节")
                        
                        # 调用DNS解析器
                        logger.debug(f"调用dns_parser解析DNS数据")
                        dns.dns_parser(session, 0, bytearray(dns_data), len(dns_data), metadata)
                    else:
                        # 如果无法确定位置，直接尝试解析UDP负载
                        dns_data = bytes(udp_layer.payload)
                        logger.debug(f"使用UDP负载作为DNS数据: {len(dns_data)}字节")
                        logger.debug(f"调用dns_parser解析UDP负载")
                        dns.dns_parser(session, 0, bytearray(dns_data), len(dns_data), metadata)
                except Exception as e:
                    logger.debug(f"无法提取UDP数据包信息: {e}")
                    # 尝试直接从DNS层提取数据
                    try:
                        metadata = {'src_ip': src_ip, 'dst_ip': dst_ip}
                        dns_data = bytes(packet[DNS])
                        logger.debug(f"从DNS层提取数据: {len(dns_data)}字节")
                        logger.debug(f"调用dns_parser解析DNS层数据")
                        dns.dns_parser(session, 0, bytearray(dns_data), len(dns_data), metadata) 
                    except Exception as inner_e:
                        logger.debug(f"无法提取DNS数据: {inner_e}")
    
    # 定期输出统计信息
    if dns_packets_count % 10 == 0:
        show_stats()

def process_icmp_packet(packet):
    """处理捕获的ICMP数据包"""
    global icmp_packets_count, icmp_echo_request_count, icmp_echo_reply_count
    global icmp_dest_unreachable_count, icmp_time_exceeded_count, icmp_redirect_count
    global icmp_source_quench_count, icmp_parameter_problem_count, icmp_timestamp_request_count, icmp_timestamp_reply_count
    global icmp_info_request_count, icmp_info_reply_count, icmp_address_mask_request_count, icmp_address_mask_reply_count
    global icmp_hosts, icmp_types
    
    # 增加包计数
    icmp_packets_count += 1
    
    # 添加明显的ICMP流量检测提示
    logger.info("🔔 检测到ICMP流量！")
    
    # 创建会话对象
    session = Session()
    logger.debug("创建会话对象用于ICMP分析")
    
    # 提取IP信息
    src_ip = None
    dst_ip = None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        logger.debug(f"IP层信息: 源={src_ip}, 目标={dst_ip}")
        
        # 添加IP地址到集合
        icmp_hosts.add(src_ip)
        icmp_hosts.add(dst_ip)
    
    # 提取ICMP信息
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        
        # 获取ICMP类型和代码
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code
        
        # 更新ICMP类型统计
        icmp_type_name = f"类型{icmp_type}"
        if icmp_type == 0:
            icmp_type_name = "回显应答"
            icmp_echo_reply_count += 1
        elif icmp_type == 3:
            icmp_type_name = "目的不可达"
            icmp_dest_unreachable_count += 1
        elif icmp_type == 5:
            icmp_type_name = "重定向"
            icmp_redirect_count += 1
        elif icmp_type == 8:
            icmp_type_name = "回显请求"
            icmp_echo_request_count += 1
        elif icmp_type == 11:
            icmp_type_name = "超时"
            icmp_time_exceeded_count += 1
        elif icmp_type == 12:
            icmp_type_name = "源抑制"
            icmp_source_quench_count += 1
        elif icmp_type == 13:
            icmp_type_name = "参数问题"
            icmp_parameter_problem_count += 1
        elif icmp_type == 14:
            icmp_type_name = "时间戳请求"
            icmp_timestamp_request_count += 1
        elif icmp_type == 15:
            icmp_type_name = "时间戳响应"
            icmp_timestamp_reply_count += 1
        elif icmp_type == 16:
            icmp_type_name = "信息请求"
            icmp_info_request_count += 1
        elif icmp_type == 17:
            icmp_type_name = "信息响应"
            icmp_info_reply_count += 1
        elif icmp_type == 18:
            icmp_type_name = "地址掩码请求"
            icmp_address_mask_request_count += 1
        elif icmp_type == 19:
            icmp_type_name = "地址掩码响应"
            icmp_address_mask_reply_count += 1
        
        icmp_types[icmp_type_name] = icmp_types.get(icmp_type_name, 0) + 1
        
        
        logger.info(f"ICMP: 类型={icmp_type_name}({icmp_type}), 代码={icmp_code}, 源={src_ip}, 目标={dst_ip}")
        
        # 调用ICMP解析器
        try:
            # 创建元数据字典
            metadata = {'src_ip': src_ip, 'dst_ip': dst_ip}
            
            # 提取ICMP数据并创建适合解析器的格式
            icmp_raw_data = bytearray(bytes(icmp_layer))
            
            # 设置会话ICMP属性
            session.icmp_type = icmp_type
            session.icmp_code = icmp_code
            session.icmp_type_name = icmp_type_name
            session.icmp_src_ip = src_ip
            session.icmp_dst_ip = dst_ip
            session.icmp_timestamp = datetime.now().isoformat()
            
            # 创建一个包含必要属性的ICMP对象，只用于调用ICMP解析器
            class IcmpPacket:
                def __init__(self, type_value, code_value, data):
                    self.type = type_value
                    self.code = code_value
                    self.data = data
                    # 添加其他可能需要的ICMP属性
                    self.id = 0
                    self.seq = 0
                    if len(data) >= 4:  # 有足够的数据来提取ID和序列号
                        try:
                            self.id = (data[0] << 8) | data[1]
                            self.seq = (data[2] << 8) | data[3]
                        except:
                            pass
            
            # 创建ICMP包对象
            icmp_packet = IcmpPacket(icmp_type, icmp_code, icmp_raw_data)
            
            # 保存ID和序列号到会话
            session.icmp_id = icmp_packet.id
            session.icmp_seq = icmp_packet.seq
            
            # 如果是回显请求/应答，提取更多信息
            if icmp_type in [0, 8]:  # Echo Reply or Echo Request
                try:
                    # 提取有效载荷数据
                    if hasattr(icmp_layer, 'load'):
                        payload = bytes(icmp_layer.load)
                        if len(payload) > 0:
                            session.icmp_payload = payload
                            logger.debug(f"ICMP载荷: {len(payload)}字节")
                            
                            # 检查是否包含时间戳
                            if len(payload) >= 8:
                                # 尝试解析时间戳
                                try:
                                    timestamp_bytes = payload[:8]
                                    timestamp = int.from_bytes(timestamp_bytes, byteorder='big')
                                    session.icmp_raw_timestamp = timestamp
                                    logger.debug(f"ICMP时间戳: {timestamp}")
                                except Exception as e:
                                    logger.debug(f"解析时间戳失败: {e}")
                            
                            # 检查是否包含可打印字符
                            printable_chars = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in payload[:16])
                            logger.info(f"ICMP数据(前16字节): {printable_chars}")
                except Exception as e:
                    logger.debug(f"提取ICMP载荷失败: {e}")
            
            # 如果是目的不可达，提取具体原因
            elif icmp_type == 3:  # Destination Unreachable
                unreachable_reasons = {
                    0: "网络不可达",
                    1: "主机不可达",
                    2: "协议不可达",
                    3: "端口不可达",
                    4: "需要分片但设置了DF标志",
                    5: "源路由失败",
                    6: "目的网络未知",
                    7: "目的主机未知",
                    8: "源主机隔离",
                    9: "禁止访问目的网络",
                    10: "禁止访问目的主机",
                    11: "对特定服务类型，网络不可达",
                    12: "对特定服务类型，主机不可达",
                    13: "由于过滤，通信被管理员禁止",
                    14: "主机优先级冲突",
                    15: "优先级被切断"
                }
                reason = unreachable_reasons.get(icmp_code, f"未知原因({icmp_code})")
                session.icmp_unreachable_reason = reason
                logger.info(f"目的不可达原因: {reason}")
                
                # 尝试提取原始IP包信息
                try:
                    if hasattr(icmp_layer, 'payload'):
                        orig_ip = icmp_layer.payload
                        if hasattr(orig_ip, 'src') and hasattr(orig_ip, 'dst'):
                            session.orig_src_ip = orig_ip.src
                            session.orig_dst_ip = orig_ip.dst
                            logger.info(f"原始IP: 源={orig_ip.src}, 目标={orig_ip.dst}")
                except Exception as e:
                    logger.debug(f"提取原始IP失败: {e}")
            
            # 如果是超时，提取具体原因
            elif icmp_type == 11:  # Time Exceeded
                exceeded_reasons = {
                    0: "传输中TTL过期",
                    1: "分片重组超时"
                }
                reason = exceeded_reasons.get(icmp_code, f"未知原因({icmp_code})")
                session.icmp_exceeded_reason = reason
                logger.info(f"超时原因: {reason}")
                
                # 尝试提取原始IP包信息
                try:
                    if hasattr(icmp_layer, 'payload'):
                        orig_ip = icmp_layer.payload
                        if hasattr(orig_ip, 'src') and hasattr(orig_ip, 'dst'):
                            session.orig_src_ip = orig_ip.src
                            session.orig_dst_ip = orig_ip.dst
                            logger.info(f"原始IP: 源={orig_ip.src}, 目标={orig_ip.dst}")
                except Exception as e:
                    logger.debug(f"提取原始IP失败: {e}")
            
            # 如果是重定向，提取具体原因
            elif icmp_type == 5:  # Redirect
                redirect_reasons = {
                    0: "网络重定向",
                    1: "主机重定向",
                    2: "对特定服务类型的网络重定向",
                    3: "对特定服务类型的主机重定向"
                }
                reason = redirect_reasons.get(icmp_code, f"未知原因({icmp_code})")
                session.icmp_redirect_reason = reason
                logger.info(f"重定向原因: {reason}")
                
                # 提取新的网关地址
                try:
                    if hasattr(icmp_layer, 'gw'):
                        session.redirect_gateway = icmp_layer.gw
                        logger.info(f"重定向网关: {icmp_layer.gw}")
                except Exception as e:
                    logger.debug(f"提取重定向网关失败: {e}")
            
            # 调用ICMP解析器，只传递必要的参数
            try:
                icmp.icmp_parser(session, icmp_packet, icmp_raw_data, len(icmp_raw_data), metadata)
                logger.debug("ICMP解析器调用成功")
            except Exception as e:
                logger.debug(f"ICMP解析器调用失败，忽略并继续处理: {e}")
            
            # 调用ICMP回调函数从会话中提取信息
            icmp_type_set = icmp_getcb_type(session)
            if icmp_type_set:
                logger.info(f"ICMP类型集合: {icmp_type_set}")
            
            icmp_code_set = icmp_getcb_code(session)
            if icmp_code_set:
                logger.info(f"ICMP代码集合: {icmp_code_set}")
            
            icmp_hosts_set = icmp_getcb_hosts(session)
            if icmp_hosts_set:
                logger.info(f"ICMP主机集合: {icmp_hosts_set}")
            
            if icmp_type in [0, 8]:  # Echo Reply or Echo Request
                icmp_echo_info = icmp_getcb_echo_info(session)
                if icmp_echo_info:
                    logger.info(f"ICMP回显信息: {icmp_echo_info}")
            
        except Exception as e:
            logger.error(f"ICMP解析器调用失败: {e}")
            logger.debug(f"ICMP数据: 类型={icmp_type}, 代码={icmp_code}, 数据长度={len(bytes(icmp_layer))}")
    
    return session

# 修改ICMP回调函数，从会话对象中提取信息
def icmp_getcb_type(session):
    """从会话中提取ICMP类型信息"""
    result = set()
    try:
        if hasattr(session, 'icmp_type') and hasattr(session, 'icmp_type_name'):
            result.add(f"{session.icmp_type_name}({session.icmp_type})")
    except Exception as e:
        logger.debug(f"提取ICMP类型信息失败: {e}")
    return result

def icmp_getcb_code(session):
    """从会话中提取ICMP代码信息"""
    result = set()
    try:
        if hasattr(session, 'icmp_code'):
            result.add(str(session.icmp_code))
    except Exception as e:
        logger.debug(f"提取ICMP代码信息失败: {e}")
    return result

def icmp_getcb_hosts(session):
    """从会话中提取ICMP主机信息"""
    result = set()
    try:
        if hasattr(session, 'icmp_src_ip'):
            result.add(session.icmp_src_ip)
        if hasattr(session, 'icmp_dst_ip'):
            result.add(session.icmp_dst_ip)
        if hasattr(session, 'orig_src_ip'):
            result.add(session.orig_src_ip)
        if hasattr(session, 'orig_dst_ip'):
            result.add(session.orig_dst_ip)
        if hasattr(session, 'redirect_gateway'):
            result.add(session.redirect_gateway)
    except Exception as e:
        logger.debug(f"提取ICMP主机信息失败: {e}")
    return result

def icmp_getcb_echo_info(session):
    """从会话中提取ICMP回显信息"""
    result = {}
    try:
        if hasattr(session, 'icmp_id'):
            result['id'] = session.icmp_id
        if hasattr(session, 'icmp_seq'):
            result['seq'] = session.icmp_seq
        if hasattr(session, 'icmp_timestamp'):
            result['timestamp'] = session.icmp_timestamp
        if hasattr(session, 'icmp_raw_timestamp'):
            result['raw_timestamp'] = session.icmp_raw_timestamp
    except Exception as e:
        logger.debug(f"提取ICMP回显信息失败: {e}")
    return result

def process_http_packet(packet):
    """处理捕获的HTTP数据包"""
    global http_packets_count, http_request_count, http_response_count
    global http_methods, http_status_codes, http_hosts, http_user_agents, http_content_types
    
    # 增加包计数
    http_packets_count += 1
    
    # 创建会话对象
    session = Session()
    logger.debug("创建会话对象用于HTTP分析")
    
    # 提取IP信息
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        logger.debug(f"IP层信息: 源={src_ip}, 目标={dst_ip}")
    
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        logger.debug(f"TCP层信息: 源端口={src_port}, 目标端口={dst_port}")
    
    # 检查是否有Raw层
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        logger.debug(f"捕获HTTP数据包, 负载大小={len(payload)}字节")
        
        try:
            # 创建HTTP对象
            http_obj = Http()
            http_obj.payload = payload
            http_obj.src_ip = src_ip
            http_obj.dst_ip = dst_ip
            http_obj.src_port = src_port
            http_obj.dst_port = dst_port
            
            # 判断是请求还是响应
            if src_port == 80 or dst_port == 80:  # 假设80端口为HTTP
                if dst_port == 80:
                    http_obj.is_request = True
                    http_request_count += 1
                    logger.debug("判断为HTTP请求")
                else:
                    http_obj.is_request = False
                    http_response_count += 1
                    logger.debug("判断为HTTP响应")
                
                # 保存到会话
                session.http_obj = http_obj
                
                # 创建元数据
                metadata = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port
                }
                
                # 转换为适合解析器的格式
                http_data = bytearray(payload)
                
                # 创建HTTP信息对象
                http_info = http.HttpInfo()
                http_info.session = session
                
                # 调用HTTP解析器
                which = 0 if http_obj.is_request else 1  # 0表示请求，1表示响应
                http.http_parse(session, http_info, http_data, len(http_data), which)
                logger.debug("HTTP解析器调用成功")
                
                # 调用HTTP回调函数提取信息
                http_methods_set = http_getcb_methods(session)
                if http_methods_set:
                    logger.info(f"HTTP方法集合: {http_methods_set}")
                    
                http_status_set = http_getcb_status(session)
                if http_status_set:
                    logger.info(f"HTTP状态码集合: {http_status_set}")
                    
                http_hosts_set = http_getcb_hosts(session)
                if http_hosts_set:
                    logger.info(f"HTTP主机集合: {http_hosts_set}")
                    
                http_user_agents_set = http_getcb_user_agents(session)
                if http_user_agents_set:
                    logger.info(f"HTTP用户代理集合: {http_user_agents_set}")
                    
                http_content_types_set = http_getcb_content_types(session)
                if http_content_types_set:
                    logger.info(f"HTTP内容类型集合: {http_content_types_set}")
                
        except Exception as e:
            logger.debug(f"HTTP解析器调用失败: {e}")
    
    return session

# 添加HTTP回调函数，从会话对象中提取信息
def http_getcb_methods(session):
    """从会话中提取HTTP方法信息"""
    result = set()
    try:
        if hasattr(session, 'http_obj') and hasattr(session.http_obj, 'method') and session.http_obj.method:
            result.add(session.http_obj.method)
    except Exception as e:
        logger.debug(f"提取HTTP方法信息失败: {e}")
    return result

def http_getcb_status(session):
    """从会话中提取HTTP状态码信息"""
    result = set()
    try:
        if hasattr(session, 'http_obj') and hasattr(session.http_obj, 'status_code') and session.http_obj.status_code:
            result.add(str(session.http_obj.status_code))
    except Exception as e:
        logger.debug(f"提取HTTP状态码信息失败: {e}")
    return result

def http_getcb_hosts(session):
    """从会话中提取HTTP主机信息"""
    result = set()
    try:
        if hasattr(session, 'http_obj'):
            if hasattr(session.http_obj, 'host') and session.http_obj.host:
                result.add(session.http_obj.host)
            if hasattr(session.http_obj, 'dst_ip') and session.http_obj.dst_ip:
                result.add(session.http_obj.dst_ip)
    except Exception as e:
        logger.debug(f"提取HTTP主机信息失败: {e}")
    return result

def http_getcb_user_agents(session):
    """从会话中提取HTTP用户代理信息"""
    result = set()
    try:
        if hasattr(session, 'http_obj') and hasattr(session.http_obj, 'user_agent') and session.http_obj.user_agent:
            result.add(session.http_obj.user_agent)
    except Exception as e:
        logger.debug(f"提取HTTP用户代理信息失败: {e}")
    return result

def http_getcb_content_types(session):
    """从会话中提取HTTP内容类型信息"""
    result = set()
    try:
        if hasattr(session, 'http_obj') and hasattr(session.http_obj, 'content_type') and session.http_obj.content_type:
            result.add(session.http_obj.content_type)
    except Exception as e:
        logger.debug(f"提取HTTP内容类型信息失败: {e}")
    return result

def show_stats():
    """显示统计信息"""
    print("\n=== 流量统计信息 ===")
    
    # DNS统计
    print(f"\n== DNS流量 ==")
    print(f"DNS数据包: {dns_packets_count}")
    print(f"DNS查询: {dns_queries_count}")
    print(f"DNS响应: {dns_responses_count}")
    print(f"DNS域名: {len(dns_domains)}")
    print(f"DNS IP地址: {len(dns_ips)}")
    
    # DHCP统计
    print(f"\n== DHCP流量 ==")
    print(f"DHCP数据包: {dhcp_packets_count}")
    print(f"DHCP Discover: {dhcp_discover_count}")
    print(f"DHCP Offer: {dhcp_offer_count}")
    print(f"DHCP Request: {dhcp_request_count}")
    print(f"DHCP ACK: {dhcp_ack_count}")
    print(f"DHCP NAK: {dhcp_nak_count}")
    print(f"DHCP Release: {dhcp_release_count}")
    print(f"DHCP Decline: {dhcp_decline_count}")
    print(f"DHCP Inform: {dhcp_inform_count}")
    print(f"DHCP MAC地址: {len(dhcp_macs)}")
    print(f"DHCP IP地址: {len(dhcp_ips)}")
    
    # ICMP统计
    print(f"\n== ICMP流量 ==")
    print(f"ICMP数据包: {icmp_packets_count}")
    print(f"ICMP Echo请求: {icmp_echo_request_count}")
    print(f"ICMP Echo响应: {icmp_echo_reply_count}")
    print(f"ICMP目标不可达: {icmp_dest_unreachable_count}")
    print(f"ICMP时间超过: {icmp_time_exceeded_count}")
    print(f"ICMP重定向: {icmp_redirect_count}")
    print(f"ICMP源抑制: {icmp_source_quench_count}")
    print(f"ICMP参数问题: {icmp_parameter_problem_count}")
    print(f"ICMP时间戳请求: {icmp_timestamp_request_count}")
    print(f"ICMP时间戳响应: {icmp_timestamp_reply_count}")
    print(f"ICMP信息请求: {icmp_info_request_count}")
    print(f"ICMP信息响应: {icmp_info_reply_count}")
    print(f"ICMP地址掩码请求: {icmp_address_mask_request_count}")
    print(f"ICMP地址掩码响应: {icmp_address_mask_reply_count}")
    print(f"ICMP主机: {len(icmp_hosts)}")
    
    # HTTP统计
    print(f"\n== HTTP流量 ==")
    print(f"HTTP数据包: {http_packets_count}")
    print(f"HTTP GET请求: {http_get_count}")
    print(f"HTTP POST请求: {http_post_count}")
    print(f"HTTP PUT请求: {http_put_count}")
    print(f"HTTP DELETE请求: {http_delete_count}")
    print(f"HTTP HEAD请求: {http_head_count}")
    print(f"HTTP OPTIONS请求: {http_options_count}")
    print(f"HTTP CONNECT请求: {http_connect_count}")
    print(f"HTTP TRACE请求: {http_trace_count}")
    print(f"HTTP PATCH请求: {http_patch_count}")
    print(f"HTTP 1xx响应: {http_1xx_count}")
    print(f"HTTP 2xx响应: {http_2xx_count}")
    print(f"HTTP 3xx响应: {http_3xx_count}")
    print(f"HTTP 4xx响应: {http_4xx_count}")
    print(f"HTTP 5xx响应: {http_5xx_count}")
    print(f"HTTP主机: {len(http_hosts)}")
    print(f"HTTP URLs: {len(http_urls)}")
    print(f"HTTP用户代理: {len(http_user_agents)}")
    
    # SMB统计
    print(f"\n== SMB流量 ==")
    print(f"SMB数据包: {smb_packets_count}")
    print(f"SMB命令: {len(smb_commands)}")
    print(f"SMB状态码: {len(smb_status_codes)}")
    
    # SOCKS统计
    print(f"\n== SOCKS流量 ==")
    print(f"SOCKS数据包: {socks_packets_count}")
    print(f"SOCKS4数据包: {socks4_packets_count}")
    print(f"SOCKS5数据包: {socks5_packets_count}")
    print(f"SOCKS认证次数: {socks_auth_count}")
    print(f"SOCKS主机: {len(socks_hosts)}")
    print(f"SOCKS用户: {len(socks_users)}")
    print(f"SOCKS IP地址: {len(socks_ips)}")
    print(f"SOCKS端口: {len(socks_ports)}")
    
    # SSH统计
    print(f"\n== SSH流量 ==")
    print(f"SSH数据包: {ssh_packets_count}")
    print(f"SSH密钥交换次数: {ssh_kex_count}")
    print(f"SSH认证尝试次数: {ssh_auth_count}")
    print(f"SSH客户端版本: {len(ssh_client_versions)}")
    print(f"SSH服务器版本: {len(ssh_server_versions)}")
    print(f"SSH密钥交换方法: {len(ssh_kex_methods)}")
    print(f"SSH认证方法: {len(ssh_auth_methods)}")
    print(f"SSH客户端加密算法: {len(ssh_cipher_client)}")
    print(f"SSH服务器加密算法: {len(ssh_cipher_server)}")
    print(f"SSH客户端MAC算法: {len(ssh_mac_client)}")
    print(f"SSH服务器MAC算法: {len(ssh_mac_server)}")
    print(f"SSH主机: {len(ssh_hosts)}")
    print(f"SSH用户名: {len(ssh_usernames)}")
    
    # TLS统计
    print(f"\n== TLS流量 ==")
    print(f"TLS数据包: {tls_packets_count}")
    print(f"TLS客户端握手: {tls_client_hello_count}")
    print(f"TLS服务器握手: {tls_server_hello_count}")
    print(f"TLS证书交换: {tls_certificate_count}")
    print(f"TLS握手总数: {tls_handshake_count}")
    print(f"TLS警告消息: {tls_alert_count}")
    print(f"TLS应用数据: {tls_application_data_count}")
    print(f"TLS协议版本: {len(tls_versions)}")
    print(f"TLS密码套件: {len(tls_cipher_suites)}")
    print(f"TLS扩展: {len(tls_extensions)}")
    print(f"TLS JA3指纹: {len(tls_ja3_fingerprints)}")
    print(f"TLS JA3S指纹: {len(tls_ja3s_fingerprints)}")
    print(f"TLS JA4指纹: {len(tls_ja4_fingerprints)}")
    print(f"TLS主机: {len(tls_hosts)}")

def process_smb_packet(packet):
    """处理捕获的SMB数据包"""
    global smb_packets_count, smb1_packets_count, smb2_packets_count
    global smb_commands, smb_status_codes, smb_dialects, smb_shares, smb_users, smb_hosts, smb_files
    
    # 增加包计数
    smb_packets_count += 1
    
    # 创建会话对象
    session = Session()
    logger.debug("创建会话对象用于SMB分析")
    
    # 提取IP信息
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        logger.debug(f"IP层信息: 源={src_ip}, 目标={dst_ip}")
    
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        logger.debug(f"TCP层信息: 源端口={src_port}, 目标端口={dst_port}")
    
    # 检查是否有Raw层
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        logger.debug(f"捕获SMB数据包, 负载大小={len(payload)}字节, 前8字节: {payload[:8].hex()}")
        
        try:
            # NetBIOS会话服务检查
            if (src_port == 139 or dst_port == 139) and len(payload) > 8:
                # 尝试跳过NetBIOS头部查找SMB标识
                netbios_offset = 0
                for offset in range(4, min(16, len(payload)-4)):
                    if payload[offset:offset+4] == b'\xffSMB' or payload[offset:offset+4] == b'\xfeSMB':
                        netbios_offset = offset
                        payload = payload[offset:]  # 重新设置载荷起始点
                        logger.debug(f"跳过NetBIOS头部{netbios_offset}字节")
                        break
            
            # 初始化SMB识别标志
            is_smb1 = len(payload) >= 4 and payload[:4] == b'\xffSMB'
            is_smb2 = len(payload) >= 4 and payload[:4] == b'\xfeSMB'
            is_smb3_encrypted = False
            is_negotiate_packet = False
            is_ntlmssp_packet = False
            
            # 检查特殊协议头模式
            if len(payload) >= 4:
                first_four_bytes = payload[:4]
                hex_pattern = ''.join(f'{b:02x}' for b in first_four_bytes)
                
                # 检查特定的协议头模式
                if hex_pattern == '60480606':
                    is_smb3_encrypted = True
                    logger.info(f"检测到SMB3加密数据包: 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}")
                elif hex_pattern == '42400001':
                    is_negotiate_packet = True
                    logger.info(f"检测到SMB协商数据包: 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}")
                
                # 检查是否包含NTLMSSP认证字符串
                if len(payload) > 16:
                    ntlm_payload = payload.find(b'NTLMSSP')
                    if ntlm_payload != -1:
                        is_ntlmssp_packet = True
                        logger.info(f"检测到SMB认证包(NTLMSSP): 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}")
            
            if is_smb1:
                smb1_packets_count += 1
                logger.info(f"检测到SMB1数据包: 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}")
            elif is_smb2:
                smb2_packets_count += 1
                logger.info(f"检测到SMB2数据包: 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}")
            elif is_smb3_encrypted:
                smb2_packets_count += 1  # SMB3归类到SMB2计数
                smb_dialects.add("SMB 3.x (加密)")
                smb_commands["SMB3_ENCRYPTED"] = smb_commands.get("SMB3_ENCRYPTED", 0) + 1
            elif is_negotiate_packet:
                smb2_packets_count += 1  # 协商包通常是SMB2/3格式
                smb_commands["SMB_NEGOTIATE"] = smb_commands.get("SMB_NEGOTIATE", 0) + 1
            elif is_ntlmssp_packet:
                # NTLMSSP认证包
                smb_commands["SMB_NTLMSSP_AUTH"] = smb_commands.get("SMB_NTLMSSP_AUTH", 0) + 1
            else:
                # 不是标准SMB协议头，但我们已经在回调函数中确认了这是SMB流量
                logger.info(f"检测到非标准SMB数据包: 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}, 前4字节: {payload[:4].hex()}")
                # 尝试识别SMB2/3会话建立阶段的包
                if dst_port == 445 or src_port == 445:
                    smb_commands["SMB_UNKNOWN"] = smb_commands.get("SMB_UNKNOWN", 0) + 1
            
            # 创建SMB信息对象
            info = smb.SmbInfo()
            info.session = session
            
            # 设置附加信息（用于展示和统计）
            if is_smb3_encrypted:
                info.is_smb2 = True
                # 设置加密标志，如果SmbInfo类支持的话
                if hasattr(info, 'encrypted'):
                    info.encrypted = True
                info.command = smb.SmbCommand.SMB2_NEGOTIATE  # 假设是协商阶段
                info.dialect = "SMB 3.x (加密)"
            elif is_negotiate_packet:
                info.is_smb2 = True
                info.command = smb.SmbCommand.SMB2_NEGOTIATE
            elif is_ntlmssp_packet:
                info.is_smb2 = True  # 现代系统多用SMB2/3
                info.command = smb.SmbCommand.SMB2_SESSION_SETUP
                
            # 调用SMB解析器
            try:
                logger.debug("调用SMB解析器...")
                # 只对标准SMB包或可识别的变种调用解析器
                if is_smb1 or is_smb2:
                    smb.smb_parser(session, info, bytearray(payload), len(payload), 0)
                    logger.debug("SMB解析器调用成功")
                elif is_smb3_encrypted or is_negotiate_packet or is_ntlmssp_packet:
                    # 对于加密或特殊包，我们设置基本信息但不走详细解析
                    if is_smb3_encrypted:
                        logger.info("检测到SMB3加密数据包，跳过详细解析")
                        info.status = smb.NtStatus.STATUS_SUCCESS  # 使用已定义的成功状态
                    elif is_negotiate_packet:
                        logger.info("检测到SMB协商数据包，尝试提取基本信息")
                        info.status = 0x00000102  # PENDING状态码值
                    elif is_ntlmssp_packet:
                        logger.info("检测到SMB NTLMSSP认证数据包，提取认证信息")
                        info.status = 0xC0000016  # MORE_PROCESSING_REQUIRED状态码值
                        
                        # 尝试从NTLMSSP包中提取用户名和域名
                        try:
                            ntlm_offset = payload.find(b'NTLMSSP')
                            if ntlm_offset >= 0 and len(payload) > ntlm_offset + 32:
                                domain_offset = ntlm_offset + 20
                                # 简单示例，实际NTLM提取更复杂
                                if b'DOMAIN' in payload[ntlm_offset:ntlm_offset+200]:
                                    domain_start = payload.find(b'DOMAIN', ntlm_offset)
                                    if domain_start > 0:
                                        possible_domain = payload[domain_start:domain_start+20]
                                        printable_domain = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in possible_domain)
                                        info.domain = printable_domain
                                        smb_users.add(printable_domain)
                        except Exception as e:
                            logger.debug(f"提取NTLMSSP信息失败: {e}")
                
                # 提取命令信息
                if hasattr(info, 'command'):
                    cmd_str = smb.SmbCommand.to_str(info.command, info.is_smb2)
                    smb_commands[cmd_str] = smb_commands.get(cmd_str, 0) + 1
                    logger.info(f"SMB命令: {cmd_str}")
                
                # 提取状态信息
                if hasattr(info, 'status'):
                    status_str = smb.NtStatus.to_str(info.status)
                    smb_status_codes[status_str] = smb_status_codes.get(status_str, 0) + 1
                    logger.info(f"SMB状态: {status_str}")
                
                # 提取方言信息
                if hasattr(info, 'dialect') and info.dialect:
                    smb_dialects.add(info.dialect)
                    logger.info(f"SMB方言: {info.dialect}")
                
                # 提取共享路径信息
                if hasattr(info, 'path') and info.path:
                    smb_shares.add(info.path)
                    logger.info(f"SMB共享: {info.path}")
                
                # 提取文件名信息
                if hasattr(info, 'filename') and info.filename:
                    smb_files.add(info.filename)
                    logger.info(f"SMB文件: {info.filename}")
                
                # 保存会话信息
                try:
                    logger.debug("保存SMB会话信息...")
                    smb.smb_save(session, info, True)
                    logger.debug("SMB会话信息保存成功")
                except Exception as e:
                    logger.debug(f"保存SMB会话信息失败: {e}")
                
            except Exception as e:
                logger.error(f"SMB解析器调用失败: {e}")
                logger.debug(traceback.format_exc())
                
        except Exception as e:
            logger.error(f"处理SMB数据包时出错: {e}")
            logger.debug(traceback.format_exc())
    


    return session

def process_dhcp_packet(packet):
    """处理捕获的DHCP数据包"""
    pass

def packet_callback(packet):
    try:
        # 获取时间戳
        timestamp = datetime.fromtimestamp(packet.time)
        
        # 获取数据包摘要
        summary = packet.summary()
        
        # 创建会话对象
        session = None
        
        # 根据数据包类型处理
        if packet.haslayer(TCP):
            # 获取源端口和目标端口
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # 处理TLS流量
            if packet.haslayer(TLS):
                session = process_tls_packet(packet)
            # 处理SSH流量
            elif src_port == 22 or dst_port == 22:
                session = process_ssh_packet(packet)
            # 处理HTTP流量
            elif src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080:
                session = process_http_packet(packet)
            # 处理SMB流量
            elif src_port == 445 or dst_port == 445:
                session = process_smb_packet(packet)
            # 处理SOCKS流量
            elif src_port == 1080 or dst_port == 1080:
                session = process_socks_packet(packet)
            # 处理可能的TLS流量（基于端口443）
            elif src_port == 443 or dst_port == 443:
                session = process_tls_packet(packet)
                
        elif packet.haslayer(UDP):
            # 获取源端口和目标端口
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # 处理DNS流量
            if src_port == 53 or dst_port == 53:
                session = process_dns_packet(packet)
            # 处理DHCP流量
            elif src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68:
                session = process_dhcp_packet(packet)
                
        elif packet.haslayer(ICMP):
            session = process_icmp_packet(packet)
            
        # 如果成功处理了数据包，保存结果
        if session:
            # 获取完整的会话信息
            session_data = session.get_readable_fields()
            
            # 创建结果对象
            result = {
                "timestamp": timestamp.isoformat(),
                "summary": summary,
                "protocols": [
                    {
                        "type": session.protocols[0].upper() if session.protocols else "UNKNOWN",
                        "data": session_data
                    }
                ]
            }
            
            # 保存结果
            json_storage.append_packet_data(result)
            
    except Exception as e:
        logger.error(f"处理数据包时出错: {str(e)}")
        logger.error(traceback.format_exc())

def capture_live(interface, dns_port=53, dhcp_ports=None, http_ports=None, smb_ports=None, socks_ports=None, ssh_ports=None, tls_ports=None):
    """从网络接口实时捕获DNS, DHCP, ICMP, HTTP, SMB, SOCKS, SSH和TLS流量"""
    if not dhcp_ports:
        dhcp_ports = [67, 68]  # 默认DHCP端口
        
    if not http_ports:
        http_ports = [80, 8080, 443]  # 默认HTTP端口
        
    if not smb_ports:
        smb_ports = [445, 139]  # 默认SMB端口
        
    if not socks_ports:
        socks_ports = [1080]  # 默认SOCKS端口
        
    if not ssh_ports:
        ssh_ports = [22]  # 默认SSH端口
        
    if not tls_ports:
        tls_ports = [443, 8443]  # 默认TLS端口
        
    logger.info(f"开始在接口 {interface} 上捕获流量...")
    
    # 初始化解析器
    logger.info("初始化DNS解析器...")
    dns.parser_init()
    
    logger.info("初始化DHCP解析器...")
    dhcp.parser_init()
    
    logger.info("初始化ICMP解析器...")
    icmp.parser_init()
    
    logger.info("初始化HTTP解析器...")
    http.parser_init()
    
    logger.info("初始化SMB解析器...")
    smb.parser_init()
    
    logger.info("初始化SOCKS解析器...")
    socks.parser_init()
    
    logger.info("初始化SSH解析器...")
    ssh.parser_init()
    
    logger.info("初始化TLS解析器...")
    tls.parser_init()
    
    try:
        # 定义BPF过滤器，捕获DNS、DHCP、ICMP、HTTP、SMB、SOCKS、SSH和TLS流量
        dhcp_filter = " or ".join([f"port {port}" for port in dhcp_ports])
        http_filter = " or ".join([f"port {port}" for port in http_ports])
        smb_filter = " or ".join([f"port {port}" for port in smb_ports])
        socks_filter = " or ".join([f"port {port}" for port in socks_ports])
        ssh_filter = " or ".join([f"port {port}" for port in ssh_ports])
        tls_filter = " or ".join([f"port {port}" for port in tls_ports])
        
        bpf_filter = f"udp port {dns_port} or ({dhcp_filter}) or icmp or ({http_filter}) or ({smb_filter}) or ({socks_filter}) or ({ssh_filter}) or ({tls_filter})"
        logger.info(f"设置BPF过滤器: {bpf_filter}")
        
        # 开始捕获
        logger.info(f"开始在接口 {interface} 上捕获...")
        sniff(iface=interface, filter=bpf_filter, prn=packet_callback, store=0)
        
    except KeyboardInterrupt:
        logger.info("捕获被用户中断")
        show_stats()
    except Exception as e:
        logger.error(f"捕获过程中出错: {e}")
        logger.error(traceback.format_exc())

def analyze_pcap(pcap_file):
    """分析pcap文件中的DNS、DHCP、ICMP、HTTP、SMB、SOCKS、SSH和TLS流量"""
    logger.info(f"分析PCAP文件: {pcap_file}")
    
    # 初始化解析器
    logger.info("初始化DNS解析器...")
    dns.parser_init()
    
    logger.info("初始化DHCP解析器...")
    dhcp.parser_init()
    
    logger.info("初始化ICMP解析器...")
    icmp.parser_init()
    
    logger.info("初始化HTTP解析器...")
    http.parser_init()
    
    logger.info("初始化SMB解析器...")
    smb.parser_init()
    
    logger.info("初始化SOCKS解析器...")
    socks.parser_init()
    
    logger.info("初始化SSH解析器...")
    ssh.parser_init()
    
    logger.info("初始化TLS解析器...")
    tls.parser_init()
    
    try:
        # 读取pcap文件
        logger.info(f"读取PCAP文件: {pcap_file}")
        packets = rdpcap(pcap_file)
        logger.info(f"读取到 {len(packets)} 个数据包")
        
        # 处理每个数据包
        for packet in packets:
            packet_callback(packet)
        
        # 显示统计信息
        show_stats()
        
    except Exception as e:
        logger.error(f"分析PCAP文件时出错: {e}")
        logger.error(traceback.format_exc())

def call_all_http_functions():
    """调用http.py中的所有函数"""
    logger.info("开始调用HTTP模块中的所有函数...")
    
    try:
        # 初始化HTTP解析器
        logger.info("\n========== 调用 http.parser_init() ==========")
        http.parser_init()
        
        # 创建测试会话对象
        session = Session()
        
        # 测试HTTP各类回调函数
        logger.info("\n========== 测试HTTP回调函数 ==========")
        
        # 创建一些示例HTTP请求和响应
        logger.info("\n========== 创建测试HTTP数据 ==========")
        
        # 创建HTTP GET请求测试数据
        http_get_request = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: www.example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Accept: text/html\r\n"
            b"\r\n"
        )
        
        # 创建HTTP响应测试数据
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Date: Mon, 23 May 2023 22:38:34 GMT\r\n"
            b"Server: Apache/2.4.38\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"Content-Length: 138\r\n"
            b"\r\n"
            b"<!DOCTYPE html>\r\n"
            b"<html>\r\n"
            b"<head>\r\n"
            b"    <title>Example Web Page</title>\r\n"
            b"</head>\r\n"
            b"<body>\r\n"
            b"    <h1>Example</h1>\r\n"
            b"</body>\r\n"
            b"</html>"
        )
        
        # 测试HTTP请求解析
        logger.info("\n----- 测试HTTP请求解析 -----")
        metadata = {'src_ip': '192.168.1.100', 'dst_ip': '93.184.216.34', 'src_port': 54321, 'dst_port': 80}
        
        # 创建HTTP信息对象
        http_info = http.HttpInfo()
        http_info.session = session
        
        # 调用HTTP解析器处理请求，which=0表示请求
        http.http_parse(session, http_info, bytearray(http_get_request), len(http_get_request), 0)
        logger.info("处理HTTP请求成功")
        
        # 检查会话中的数据
        methods = http_getcb_methods(session)
        if methods:
            logger.info(f"HTTP方法: {methods}")
        
        host_set = http_getcb_hosts(session)
        if host_set:
            logger.info(f"HTTP主机: {host_set}")
        
        user_agent_set = http_getcb_user_agents(session)
        if user_agent_set:
            logger.info(f"HTTP用户代理: {user_agent_set}")
        
        # 测试HTTP响应解析
        logger.info("\n----- 测试HTTP响应解析 -----")
        session2 = Session()
        metadata2 = {'src_ip': '93.184.216.34', 'dst_ip': '192.168.1.100', 'src_port': 80, 'dst_port': 54321}
        
        # 创建HTTP信息对象
        http_info2 = http.HttpInfo()
        http_info2.session = session2
        
        # 调用HTTP解析器处理响应，which=1表示响应
        http.http_parse(session2, http_info2, bytearray(http_response), len(http_response), 1)
        logger.info("处理HTTP响应成功")
        
        # 检查会话中的数据
        status_set = http_getcb_status(session2)
        if status_set:
            logger.info(f"HTTP状态: {status_set}")
        
        content_type_set = http_getcb_content_types(session2)
        if content_type_set:
            logger.info(f"HTTP内容类型: {content_type_set}")
        
        # 测试HTTP保存函数
        logger.info("\n----- 调用 http_save() -----")
        try:
            # 注意: http_save可能需要更完整的会话数据才能成功运行
            # 如果失败，请确保HttpInfo对象包含所有必要的信息
            from analyzers import BSB
            bsb = BSB.BSB(bytearray(500), 500)
            logger.info("尝试保存HTTP请求数据...")
            http.http_save(bsb, http_info, False)
            logger.info(f"保存HTTP请求数据成功, 大小: {bsb.ptr}字节")
        except Exception as e:
            logger.error(f"保存HTTP请求数据失败: {e}")
            
        try:    
            bsb2 = BSB.BSB(bytearray(500), 500)
            logger.info("尝试保存HTTP响应数据...")
            http.http_save(bsb2, http_info2, False)
            logger.info(f"保存HTTP响应数据成功, 大小: {bsb2.ptr}字节")
        except Exception as e:
            logger.error(f"保存HTTP响应数据失败: {e}")
        
        logger.info("\n========== HTTP模块所有函数调用完成 ==========")
        
    except ImportError as e:
        logger.error(f"导入失败: {e}")
    except Exception as e:
        logger.error(f"发生错误: {e}")
        logger.error(traceback.format_exc())

def http_test():
    """运行HTTP解析器测试"""
    logger.info("开始运行HTTP测试...")
    
    # 初始化HTTP解析器
    logger.info("初始化HTTP解析器...")
    http.parser_init()
    
    # 创建测试会话对象
    session = Session()
    
    # 创建HTTP测试数据
    # 创建HTTP GET请求测试数据
    http_get_request = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept: text/html\r\n"
        b"\r\n"
    )
    
    # 创建HTTP响应测试数据
    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Mon, 23 May 2023 22:38:34 GMT\r\n"
        b"Server: Apache/2.4.38\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Content-Length: 138\r\n"
        b"\r\n"
        b"<!DOCTYPE html>\r\n"
        b"<html>\r\n"
        b"<head>\r\n"
        b"    <title>Example Web Page</title>\r\n"
        b"</head>\r\n"
        b"<body>\r\n"
        b"    <h1>Example</h1>\r\n"
        b"</body>\r\n"
        b"</html>"
    )
    
    # 测试HTTP请求分析
    logger.info("\n----- 测试HTTP请求分析 -----")
    
    # 创建HTTP请求对象
    req_http_obj = Http()
    req_http_obj.is_request = True
    req_http_obj.src_ip = "192.168.1.100"
    req_http_obj.dst_ip = "93.184.216.34"
    req_http_obj.src_port = 54321
    req_http_obj.dst_port = 80
    req_http_obj.payload = http_get_request
    
    # 保存到会话
    session.http_obj = req_http_obj
    
    # 创建HTTP信息对象
    http_info = http.HttpInfo()
    http_info.session = session
    
    # 解析HTTP请求
    try:
        http.http_parse(session, http_info, bytearray(http_get_request), len(http_get_request), 0)
        logger.info("HTTP请求解析成功")
        
        # 获取分析结果
        http_methods = http_getcb_methods(session)
        if http_methods:
            logger.info(f"HTTP方法: {http_methods}")
        
        http_hosts = http_getcb_hosts(session)
        if http_hosts:
            logger.info(f"HTTP主机: {http_hosts}")
        
        # 打印完整会话信息
        logger.info("HTTP请求会话信息:")
        if hasattr(session, 'http_obj'):
            for attr_name, attr_value in vars(session.http_obj).items():
                if attr_value and not attr_name.startswith('_') and not callable(attr_value):
                    logger.info(f"  {attr_name}: {attr_value}")
    except Exception as e:
        logger.error(f"HTTP请求解析失败: {e}")
    
    # 测试HTTP响应分析
    logger.info("\n----- 测试HTTP响应分析 -----")
    
    # 创建新会话
    session2 = Session()
    
    # 创建HTTP响应对象
    resp_http_obj = Http()
    resp_http_obj.is_request = False
    resp_http_obj.src_ip = "93.184.216.34"
    resp_http_obj.dst_ip = "192.168.1.100"
    resp_http_obj.src_port = 80
    resp_http_obj.dst_port = 54321
    resp_http_obj.payload = http_response
    
    # 保存到会话
    session2.http_obj = resp_http_obj
    
    # 创建HTTP信息对象
    http_info2 = http.HttpInfo()
    http_info2.session = session2
    
    # 解析HTTP响应
    try:
        http.http_parse(session2, http_info2, bytearray(http_response), len(http_response), 1)
        logger.info("HTTP响应解析成功")
        
        # 获取分析结果
        http_status = http_getcb_status(session2)
        if http_status:
            logger.info(f"HTTP状态码: {http_status}")
        
        http_content_types = http_getcb_content_types(session2)
        if http_content_types:
            logger.info(f"HTTP内容类型: {http_content_types}")
        
        # 打印完整会话信息
        logger.info("HTTP响应会话信息:")
        if hasattr(session2, 'http_obj'):
            for attr_name, attr_value in vars(session2.http_obj).items():
                if attr_value and not attr_name.startswith('_') and not callable(attr_value):
                    logger.info(f"  {attr_name}: {attr_value}")
    except Exception as e:
        logger.error(f"HTTP响应解析失败: {e}")
    
    logger.info("\n----- HTTP测试完成 -----")

def call_all_dns_functions():
    """测试DNS解析器的所有功能"""
    logger.info("开始调用DNS模块的所有函数...")
    
    # 初始化DNS解析器
    dns.parser_init()
    logger.info("DNS解析器初始化成功")
    
    # 创建会话对象
    session = Session()
    
    # 创建DNS测试数据
    dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    dns_response = b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\x5d\xb8\xd8\x22"
    
    # 调用解析器解析查询
    metadata = {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'src_port': 12345, 'dst_port': 53}
    logger.info("解析DNS查询...")
    dns.dns_parser(session, 0, bytearray(dns_query), len(dns_query), metadata)
    
    # 调用解析器解析响应
    metadata = {'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.100', 'src_port': 53, 'dst_port': 12345}
    logger.info("解析DNS响应...")
    dns.dns_parser(session, 1, bytearray(dns_response), len(dns_response), metadata)
    
    # 使用各种回调函数来提取信息
    logger.info("使用DNS回调函数提取信息...")
    
    host_set = dns.dns_getcb_host(session)
    if host_set:
        logger.info(f"主机集合: {host_set}")
    
    query_host_set = dns.dns_getcb_query_host(session)
    if query_host_set:
        logger.info(f"查询主机集合: {query_host_set}")
    
    status_set = dns.dns_getcb_status(session)
    if status_set:
        logger.info(f"状态码集合: {status_set}")
    
    query_type_set = dns.dns_getcb_query_type(session)
    if query_type_set:
        logger.info(f"查询类型集合: {query_type_set}")
    
    query_class_set = dns.dns_getcb_query_class(session)
    if query_class_set:
        logger.info(f"查询类集合: {query_class_set}")
    
    nameserver_set = dns.dns_getcb_host_nameserver(session)
    if nameserver_set:
        logger.info(f"名称服务器集合: {nameserver_set}")
    
    mailserver_set = dns.dns_getcb_host_mailserver(session)
    if mailserver_set:
        logger.info(f"邮件服务器集合: {mailserver_set}")
    
    # 测试DNS保存功能
    try:
        from analyzers import BSB
        from analyzers.types import FieldObject
        bsb = BSB.BSB(bytearray(500), 500)
        
        # 获取或创建DNS字段对象
        dns_data = session.fields.get('dnsField')
        if dns_data:
            # 创建一个FieldObject对象
            dns_obj = dns.Dns(rcode_id=0, headerFlags=0)
            dns_obj.query = dns.DnsQuery()
            dns_obj.query.hostname = "example.com"
            dns_obj.query.type_id = 1  # A记录
            dns_obj.query.class_id = 1  # IN类
            
            # 添加一些测试数据
            dns_obj.hosts = {"example.com": {"str": "example.com", "len": 11, "utf8": True}}
            dns_obj.ips = {"93.184.216.34": {"ip": (0x5d << 24) | (0xb8 << 16) | (0xd8 << 8) | 0x22}}
            
            # 创建一个答案记录
            dns_obj.answers = dns.DnsAnswerHead()
            answer = dns.DnsAnswer()
            answer.ipA = (0x5d << 24) | (0xb8 << 16) | (0xd8 << 8) | 0x22  # 93.184.216.34
            answer.type_id = 1  # A记录
            answer.class_ = "IN"
            answer.ttl = 1200
            answer.name = "example.com"
            dns_obj.answers.push_tail(answer)
            
            # 创建FieldObject
            field_obj = FieldObject()
            field_obj.object = dns_obj
            field_obj.objcet = dns_obj  # 兼容性写法
            field_obj.objects = {}  # 初始化objects字典
            
            # 尝试调用dns_save函数
            try:
                dns.Dns.dns = dns_obj  # 设置全局DNS对象
                dns.dns_save(bsb, field_obj, session)
                if not bsb.error:
                    logger.info(f"DNS对象保存结果大小: {bsb.ptr}字节")
                else:
                    logger.error("保存DNS对象时发生错误")
            except AttributeError as e:
                logger.error(f"保存DNS对象时缺少必要属性: {e}")
            except Exception as e:
                logger.error(f"保存DNS对象失败: {e}")
    except Exception as e:
        logger.error(f"保存DNS对象失败: {e}")
    
    logger.info("DNS模块所有函数调用完成")

def main():
    """主程序入口"""
    parser = argparse.ArgumentParser(description='DNS, DHCP, ICMP, HTTP, SMB, SOCKS, SSH和TLS流量分析工具')
    
    # 添加参数
    parser.add_argument('-i', '--interface',default='ens33', help='要监听的网络接口')
    parser.add_argument('-f', '--file', help='要分析的pcap文件')
    parser.add_argument('-p', '--port', type=int, default=53, help='DNS端口号 (默认: 53)')
    parser.add_argument('-t', '--test', action='store_true', help='运行测试')
    
    # 解析参数
    args = parser.parse_args()
    
    try:
        # 处理测试参数
        if args.test:
            logger.info("运行测试模式...")
            dns_test()
            icmp_test()
            http_test()
            smb_test()
            socks_test()
            ssh_test()
            dhcp_test()
            tls_test()
            return
        
        # 处理实时捕获
        if args.interface:
            logger.info(f"从接口 {args.interface} 实时捕获流量...")
            capture_live(args.interface, args.port)
            return
        
        # 处理PCAP文件分析
        if args.file:
            logger.info(f"分析PCAP文件: {args.file}")
            analyze_pcap(args.file)
            return
        
        # 如果没有提供操作参数，显示帮助
        parser.print_help()
        
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
    except Exception as e:
        logger.error(f"程序执行出错: {e}")
        logger.error(traceback.format_exc())

def dns_test():
    """运行DNS解析器测试"""
    logger.info("开始运行DNS测试...")
    
    # 初始化DNS解析器
    logger.info("初始化DNS解析器...")
    dns.parser_init()
    
    # 创建DNS测试数据包
    logger.info("创建DNS测试数据...")
    dns_query = (
        b"\x00\x01"  # 事务ID
        b"\x01\x00"  # 标志 (标准查询)
        b"\x00\x01"  # 查询数量
        b"\x00\x00"  # 应答RR数量
        b"\x00\x00"  # 授权RR数量
        b"\x00\x00"  # 附加RR数量
        b"\x07example\x03com\x00"  # 查询名称
        b"\x00\x01"  # 查询类型 (A)
        b"\x00\x01"  # 查询类 (IN)
    )
    
    dns_response = (
        b"\x00\x01"  # 事务ID
        b"\x81\x80"  # 标志 (标准响应, 递归可用)
        b"\x00\x01"  # 查询数量
        b"\x00\x01"  # 应答RR数量
        b"\x00\x00"  # 授权RR数量
        b"\x00\x00"  # 附加RR数量
        b"\x07example\x03com\x00"  # 查询名称
        b"\x00\x01"  # 查询类型 (A)
        b"\x00\x01"  # 查询类 (IN)
        b"\xc0\x0c"  # 指针到名称 (压缩)
        b"\x00\x01"  # 类型 (A)
        b"\x00\x01"  # 类 (IN)
        b"\x00\x00\x04\xb0"  # TTL (1200秒)
        b"\x00\x04"  # 数据长度 (4字节)
        b"\x5d\xb8\xd8\x22"  # IP地址 (93.184.216.34)
    )
    
    # 创建会话对象
    session = Session()
    
    # 解析DNS查询
    logger.info("解析DNS查询...")
    metadata = {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'src_port': 12345, 'dst_port': 53}
    dns.dns_parser(session, 0, bytearray(dns_query), len(dns_query), metadata)
    
    # 提取查询信息
    dns_data = session.fields.get('dnsField')
    if dns_data:
        logger.info(f"DNS查询域名: {dns_data.get('qname', 'unknown')}")
        logger.info(f"DNS查询类型: {dns_data.get('qtype', 'unknown')}")
        logger.info(f"DNS查询类: {dns_data.get('qclass', 'unknown')}")
    
    # 解析DNS响应
    logger.info("解析DNS响应...")
    metadata = {'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.100', 'src_port': 53, 'dst_port': 12345}
    dns.dns_parser(session, 1, bytearray(dns_response), len(dns_response), metadata)
    
    # 提取查询主机集合
    host_set = dns.dns_getcb_host(session)
    if host_set:
        logger.info(f"解析的主机集合: {host_set}")
    
    query_host_set = dns.dns_getcb_query_host(session)
    if query_host_set:
        logger.info(f"查询主机集合: {query_host_set}")
    
    logger.info("DNS测试运行完成")

def call_all_smb_functions():
    """调用smb.py中的所有函数"""
    logger.info("开始调用SMB模块中的所有函数...")
    
    try:
        # 导入SMB模块
        from analyzers import smb
        
        # 初始化SMB解析器
        logger.info("\n========== 调用 smb.parser_init() ==========")
        smb.parser_init()
        
        # 创建测试会话对象
        session = Session()
        session.add_protocol("smb")
        session.fields = {}
        session.fields['smbField'] = {}
        
        # 创建SMB信息对象
        logger.info("\n========== 创建SMB信息对象 ==========")
        info = smb.SmbInfo()
        info.session = session
        
        # 测试SMB1和SMB2协议解析
        logger.info("\n========== 测试SMB协议解析 ==========")
        
        # 创建SMB1测试数据
        smb1_data = bytearray(b'\xffSMB' + b'\x72\x00\x00\x00\x00\x18\x43\xc8\x00\x00\x00\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        
        logger.info("解析SMB1数据...")
        smb.smb_parser(session, info, smb1_data, len(smb1_data), 0)
        
        # 创建SMB2测试数据
        smb2_data = bytearray(b'\xfeSMB' + b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        
        logger.info("解析SMB2数据...")
        smb.smb_parser(session, info, smb2_data, len(smb2_data), 0)
        
        # 测试SMB命令处理
        logger.info("\n========== 测试SMB命令处理 ==========")
        
        # SMB1命令测试
        info.command = smb.SmbCommand.NEGOTIATE
        info.is_smb2 = False
        cmd_str = smb.SmbCommand.to_str(info.command, False)
        logger.info(f"SMB1命令测试: {cmd_str}")
        
        # SMB2命令测试
        info.command = smb.SmbCommand.SMB2_NEGOTIATE
        info.is_smb2 = True
        cmd_str = smb.SmbCommand.to_str(info.command, True)
        logger.info(f"SMB2命令测试: {cmd_str}")
        
        # 测试SMB状态码处理
        logger.info("\n========== 测试SMB状态码处理 ==========")
        info.status = smb.NtStatus.STATUS_SUCCESS
        status_str = smb.NtStatus.to_str(info.status)
        logger.info(f"SMB状态码测试: {status_str}")
        
        # 测试SMB方言处理
        logger.info("\n========== 测试SMB方言处理 ==========")
        dialect = smb.SmbDialect.from_dialect_revision(0x0202)
        logger.info(f"SMB方言测试: {dialect}")
        
        # 测试文件名和路径处理
        logger.info("\n========== 测试SMB字段添加 ==========")
        info.filename = "test.txt"
        info.path = "\\\\server\\share"
        
        # 尝试保存会话信息
        logger.info("\n========== 测试SMB会话保存 ==========")
        try:
            smb.smb_save(session, info, True)
            logger.info("SMB会话保存成功")
        except Exception as e:
            logger.error(f"SMB会话保存失败: {e}")
        
        logger.info("\n========== SMB模块所有函数调用完成 ==========")
        
    except ImportError as e:
        logger.error(f"导入失败: {e}")
    except Exception as e:
        logger.error(f"发生错误: {e}")
        logger.error(traceback.format_exc())

def smb_test():
    """运行SMB解析器测试"""
    logger.info("开始运行SMB测试...")
    
    # 导入SMB模块
    from analyzers import smb
    
    # 初始化SMB解析器
    logger.info("初始化SMB解析器...")
    smb.parser_init()
    
    # 创建会话对象
    session = Session()
    session.add_protocol("smb")
    session.fields = {}
    session.fields['smbField'] = {}
    
    # 创建SMB信息对象
    logger.info("创建SMB信息对象...")
    info = smb.SmbInfo()
    info.session = session
    
    # 创建测试数据包
    logger.info("创建SMB1测试数据包...")
    smb1_data = bytearray(b'\xffSMB' + b'\x72\x00\x00\x00\x00\x18\x43\xc8\x00\x00\x00\x00\x00\x00\x00\x00' + 
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    
    # 解析SMB1数据包
    logger.info("解析SMB1数据包...")
    smb.smb_parser(session, info, smb1_data, len(smb1_data), 0)
    
    # 显示解析结果
    logger.info(f"SMB1解析结果: {session.fields.get('smbField', {})}")
    
    # 创建SMB2测试数据包
    logger.info("创建SMB2测试数据包...")
    smb2_data = bytearray(b'\xfeSMB' + b'\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00' + 
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    
    # 清空会话并重新创建SMB信息对象
    session = Session()
    session.add_protocol("smb")
    session.fields = {}
    session.fields['smbField'] = {}
    info = smb.SmbInfo()
    info.session = session
    
    # 解析SMB2数据包
    logger.info("解析SMB2数据包...")
    smb.smb_parser(session, info, smb2_data, len(smb2_data), 0)
    
    # 显示解析结果
    logger.info(f"SMB2解析结果: {session.fields.get('smbField', {})}")
    
    logger.info("SMB测试完成")

def process_socks_packet(packet):
    """处理捕获的SOCKS数据包"""
    global socks_packets_count, socks4_packets_count, socks5_packets_count
    global socks_hosts, socks_users, socks_ips, socks_ports, socks_auth_count, socks_version_counts
    
    # 增加包计数
    socks_packets_count += 1
    
    # 创建会话对象
    session = Session()
    logger.debug("创建会话对象用于SOCKS分析")
    
    # 提取IP信息
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        logger.debug(f"IP层信息: 源={src_ip}, 目标={dst_ip}")
    
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        logger.debug(f"TCP层信息: 源端口={src_port}, 目标端口={dst_port}")
    
    # 检查是否有Raw层
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        logger.debug(f"捕获SOCKS数据包, 负载大小={len(payload)}字节, 前8字节: {payload[:8].hex()}")
        
        try:
            # 判断是SOCKS4还是SOCKS5
            is_socks4 = len(payload) >= 1 and payload[0] == 0x04
            is_socks5 = len(payload) >= 1 and payload[0] == 0x05
            
            if is_socks4:
                socks4_packets_count += 1
                socks_version_counts["SOCKS4"] = socks_version_counts.get("SOCKS4", 0) + 1
                logger.info(f"检测到SOCKS4数据包: 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}")
                
                # 分析SOCKS4请求
                if len(payload) >= 9:  # SOCKS4请求至少需要9字节
                    cmd = payload[1]
                    if cmd == 1:
                        logger.info("SOCKS4 CONNECT请求")
                    elif cmd == 2:
                        logger.info("SOCKS4 BIND请求")
                    
                    # 提取端口
                    port = (payload[2] << 8) | payload[3]
                    socks_ports.add(port)
                    logger.info(f"目标端口: {port}")
                    
                    # 提取IP地址
                    ip = f"{payload[4]}.{payload[5]}.{payload[6]}.{payload[7]}"
                    socks_ips.add(ip)
                    logger.info(f"目标IP: {ip}")
                    
                    # 尝试提取用户ID
                    user_end = payload.find(b'\x00', 8)
                    if user_end > 8:
                        user = payload[8:user_end].decode('latin1', errors='ignore')
                        if user:
                            socks_users.add(user)
                            logger.info(f"用户ID: {user}")
                            socks_auth_count += 1
                    
                    # 尝试提取SOCKS4a域名
                    if payload[4] == 0 and payload[5] == 0 and payload[6] == 0 and payload[7] != 0:
                        if user_end + 1 < len(payload):
                            host_start = user_end + 1
                            host_end = payload.find(b'\x00', host_start)
                            if host_end > host_start:
                                host = payload[host_start:host_end].decode('latin1', errors='ignore')
                                socks_hosts.add(host)
                                logger.info(f"目标主机: {host}")
                
                # 使用socks4_classify函数进行分析
                try:
                    which = 0  # 假设是请求方向
                    socks.socks4_classify(session, payload, len(payload), which, None)
                    logger.debug("SOCKS4分类器调用成功")
                except Exception as e:
                    logger.error(f"SOCKS4分类器调用失败: {e}")
                
            elif is_socks5:
                socks5_packets_count += 1
                socks_version_counts["SOCKS5"] = socks_version_counts.get("SOCKS5", 0) + 1
                logger.info(f"检测到SOCKS5数据包: 源={src_ip}:{src_port}, 目标={dst_ip}:{dst_port}")
                
                # 分析SOCKS5协商阶段
                if len(payload) >= 3 and payload[0] == 0x05:
                    methods_count = payload[1]
                    logger.info(f"支持的认证方法数量: {methods_count}")
                    
                    # 检查认证方法
                    auth_methods = []
                    for i in range(2, min(2 + methods_count, len(payload))):
                        method = payload[i]
                        if method == 0x00:
                            auth_methods.append("无认证")
                        elif method == 0x01:
                            auth_methods.append("GSSAPI")
                        elif method == 0x02:
                            auth_methods.append("用户名/密码")
                            socks_auth_count += 1
                        else:
                            auth_methods.append(f"未知方法(0x{method:02x})")
                    
                    if auth_methods:
                        logger.info(f"认证方法: {', '.join(auth_methods)}")
                
                # 分析SOCKS5请求
                elif len(payload) >= 10 and payload[0] == 0x05 and payload[1] == 0x01:  # CONNECT请求
                    logger.info("SOCKS5 CONNECT请求")
                    
                    # 提取地址类型
                    atyp = payload[3]
                    if atyp == 0x01:  # IPv4
                        ip = f"{payload[4]}.{payload[5]}.{payload[6]}.{payload[7]}"
                        socks_ips.add(ip)
                        logger.info(f"目标IPv4: {ip}")
                        
                        port = (payload[8] << 8) | payload[9]
                        socks_ports.add(port)
                        logger.info(f"目标端口: {port}")
                        
                    elif atyp == 0x03:  # 域名
                        length = payload[4]
                        if 5 + length <= len(payload):
                            host = payload[5:5+length].decode('latin1', errors='ignore')
                            socks_hosts.add(host)
                            logger.info(f"目标主机: {host}")
                            
                            port_pos = 5 + length
                            if port_pos + 1 < len(payload):
                                port = (payload[port_pos] << 8) | payload[port_pos + 1]
                                socks_ports.add(port)
                                logger.info(f"目标端口: {port}")
                                
                    elif atyp == 0x04:  # IPv6
                        if len(payload) >= 22:
                            ipv6_bytes = payload[4:20]
                            # 将IPv6地址格式化为标准形式
                            ipv6 = ':'.join([f"{ipv6_bytes[i*2]:02x}{ipv6_bytes[i*2+1]:02x}" for i in range(8)])
                            socks_ips.add(ipv6)
                            logger.info(f"目标IPv6: {ipv6}")
                            
                            port = (payload[20] << 8) | payload[21]
                            socks_ports.add(port)
                            logger.info(f"目标端口: {port}")
                
                # 使用socks5_classify函数进行分析
                try:
                    which = 0  # 假设是请求方向
                    socks.socks5_classify(session, payload, len(payload), which, None)
                    logger.debug("SOCKS5分类器调用成功")
                except Exception as e:
                    logger.error(f"SOCKS5分类器调用失败: {e}")
                
            else:
                # 可能是SOCKS协议的后续数据包，或者是误报
                logger.debug(f"无法确定SOCKS协议版本: 负载开始字节为0x{payload[0]:02x}")
                
            # 检查会话中的提取结果
            if session.has_protocol("socks"):
                logger.info("成功识别SOCKS协议")
                
                # 从session提取hostnames
                if hasattr(session, 'fields') and 'host.socks' in session.fields:
                    for host in session.fields['host.socks']:
                        socks_hosts.add(host)
                        logger.info(f"提取的目标主机: {host}")
                
                # 从session提取用户名
                if hasattr(session, 'fields') and 'socks.user' in session.fields:
                    for user in session.fields['socks.user']:
                        socks_users.add(user)
                        logger.info(f"提取的用户名: {user}")
                
        except Exception as e:
            logger.error(f"处理SOCKS数据包时出错: {e}")
            logger.debug(traceback.format_exc())
    

    return session

def call_all_socks_functions():
    """调用socks.py中的所有函数"""
    logger.info("开始调用SOCKS模块中的所有函数...")
    
    try:
        # 初始化SOCKS解析器
        logger.info("\n========== 调用 socks.parser_init() ==========")
        socks.parser_init()
        
        # 创建测试会话对象
        session = Session()
        session.add_protocol("socks")
        
        # 展示SOCKS协议状态常量
        logger.info("\n========== SOCKS协议状态常量 ==========")
        logger.info(f"SOCKS4_STATE_REPLY = {socks.SOCKS4_STATE_REPLY}")
        logger.info(f"SOCKS4_STATE_DATA = {socks.SOCKS4_STATE_DATA}")
        logger.info(f"SOCKS5_STATE_VER_REQUEST = {socks.SOCKS5_STATE_VER_REQUEST}")
        logger.info(f"SOCKS5_STATE_VER_REPLY = {socks.SOCKS5_STATE_VER_REPLY}")
        logger.info(f"SOCKS5_STATE_USER_REQUEST = {socks.SOCKS5_STATE_USER_REQUEST}")
        logger.info(f"SOCKS5_STATE_USER_REPLY = {socks.SOCKS5_STATE_USER_REPLY}")
        logger.info(f"SOCKS5_STATE_CONN_REQUEST = {socks.SOCKS5_STATE_CONN_REQUEST}")
        logger.info(f"SOCKS5_STATE_CONN_REPLY = {socks.SOCKS5_STATE_CONN_REPLY}")
        logger.info(f"SOCKS5_STATE_CONN_DATA = {socks.SOCKS5_STATE_CONN_DATA}")
        
        # 创建和检查SocksInfo对象
        logger.info("\n========== SOCKS信息对象 ==========")
        socks_info = socks.SocksInfo()
        logger.info("创建SOCKS信息对象成功")
        
        # 展示SOCKS信息对象的属性
        logger.info("SOCKS信息对象属性:")
        logger.info(f"user = {socks_info.user}")
        logger.info(f"host = {socks_info.host}")
        logger.info(f"ip = {socks_info.ip}")
        logger.info(f"port = {socks_info.port}")
        logger.info(f"user_len = {socks_info.user_len}")
        logger.info(f"host_len = {socks_info.host_len}")
        logger.info(f"which = {socks_info.which}")
        logger.info(f"state4 = {socks_info.state4}")
        logger.info(f"state5 = {socks_info.state5}")
        
        # 设置SOCKS信息对象的属性
        logger.info("\n设置SOCKS信息对象属性:")
        socks_info.user = "testuser"
        socks_info.host = "example.com"
        socks_info.ip = 0xC0A80101  # 192.168.1.1
        socks_info.port = 80
        socks_info.user_len = len(socks_info.user)
        socks_info.host_len = len(socks_info.host)
        socks_info.which = 0
        socks_info.state4 = socks.SOCKS4_STATE_REPLY
        
        # 初始化state5列表
        socks_info.state5 = [0, 0]
        socks_info.state5[0] = socks.SOCKS5_STATE_VER_REQUEST
        socks_info.state5[1] = socks.SOCKS5_STATE_VER_REPLY
        
        logger.info(f"设置后user = {socks_info.user}")
        logger.info(f"设置后host = {socks_info.host}")
        logger.info(f"设置后ip = {socks_info.ip} ({ipaddress.IPv4Address(socks_info.ip)})")
        logger.info(f"设置后port = {socks_info.port}")
        logger.info(f"设置后state4 = {socks_info.state4}")
        logger.info(f"设置后state5 = {socks_info.state5}")
        
        # 展示SOCKS协议数据包格式
        logger.info("\n========== SOCKS协议数据包格式 ==========")
        
        # SOCKS4 CONNECT请求格式
        logger.info("SOCKS4 CONNECT请求格式:")
        logger.info("字节0: 版本(0x04)")
        logger.info("字节1: 命令(0x01=CONNECT, 0x02=BIND)")
        logger.info("字节2-3: 目标端口(大端序)")
        logger.info("字节4-7: 目标IP地址(大端序)")
        logger.info("字节8+: 用户ID(以NULL结尾)")
        logger.info("SOCKS4a扩展: 如果IP为0.0.0.x (x!=0), 则用户ID后跟域名(以NULL结尾)")
        
        # SOCKS4 REPLY响应格式
        logger.info("\nSOCKS4 REPLY响应格式:")
        logger.info("字节0: 空字节(0x00)")
        logger.info("字节1: 状态码(0x5A=成功, 0x5B=失败, 0x5C=无法连接目标, 0x5D=认证失败)")
        logger.info("字节2-3: 目标端口(大端序)")
        logger.info("字节4-7: 目标IP地址")
        
        # SOCKS5 VER握手请求格式
        logger.info("\nSOCKS5 VER握手请求格式:")
        logger.info("字节0: 版本(0x05)")
        logger.info("字节1: 认证方法数量(N)")
        logger.info("字节2+: N个认证方法(0x00=无认证, 0x01=GSSAPI, 0x02=用户名/密码, 0x03-0x7F=IANA分配, 0x80-0xFE=私有)")
        
        # SOCKS5 VER握手响应格式
        logger.info("\nSOCKS5 VER握手响应格式:")
        logger.info("字节0: 版本(0x05)")
        logger.info("字节1: 选择的认证方法(0x00=无认证, 0x02=用户名/密码, 0xFF=没有可接受的方法)")
        
        # SOCKS5 CONNECT请求格式
        logger.info("\nSOCKS5 CONNECT请求格式:")
        logger.info("字节0: 版本(0x05)")
        logger.info("字节1: 命令(0x01=CONNECT, 0x02=BIND, 0x03=UDP ASSOCIATE)")
        logger.info("字节2: 保留字节(0x00)")
        logger.info("字节3: 地址类型(0x01=IPv4, 0x03=域名, 0x04=IPv6)")
        logger.info("字节4+: 目标地址(IPv4=4字节, 域名=1字节长度+N字节内容, IPv6=16字节)")
        logger.info("最后2字节: 目标端口(大端序)")
        
        # SOCKS5 CONNECT响应格式
        logger.info("\nSOCKS5 CONNECT响应格式:")
        logger.info("字节0: 版本(0x05)")
        logger.info("字节1: 状态码(0x00=成功, 0x01=一般失败, 0x02=规则禁止, 0x03=网络不可达, ...)")
        logger.info("字节2: 保留字节(0x00)")
        logger.info("字节3: 地址类型(0x01=IPv4, 0x03=域名, 0x04=IPv6)")
        logger.info("字节4+: 绑定地址")
        logger.info("最后2字节: 绑定端口(大端序)")
        
        # 展示SOCKS协议字段定义
        logger.info("\n========== SOCKS协议字段定义 ==========")
        logger.info(f"ip_field = {socks.ip_field}")
        logger.info(f"port_field = {socks.port_field}")
        logger.info(f"user_field = {socks.user_field}")
        logger.info(f"host_field = {socks.host_field}")
        
        # 展示TCP解析器注册
        logger.info("\n========== SOCKS TCP解析器注册 ==========")
        logger.info("socks4_classify: 用于识别SOCKS4协议流量")
        logger.info("socks4_parser: 用于解析SOCKS4协议数据")
        logger.info("socks5_classify: 用于识别SOCKS5协议流量")
        logger.info("socks5_parser: 用于解析SOCKS5协议数据")
        
        logger.info("\n========== SOCKS模块所有函数调用完成 ==========")
        
    except ImportError as e:
        logger.error(f"导入失败: {e}")
    except Exception as e:
        logger.error(f"发生错误: {e}")
        logger.error(traceback.format_exc())

def socks_test():
    """运行SOCKS解析器测试"""
    logger.info("开始运行SOCKS测试...")
    
    # 初始化SOCKS解析器
    logger.info("初始化SOCKS解析器...")
    socks.parser_init()
    
    try:
        # 创建会话对象
        session = Session()
        session.add_protocol("socks")
        
        # 测试SOCKS4
        logger.info("\n----- 测试SOCKS4协议 -----")
        
        # 创建SOCKS4 CONNECT请求测试数据
        socks4_connect = bytearray([
            0x04,                   # SOCKS版本4
            0x01,                   # CONNECT命令
            0x00, 0x50,             # 端口80
            0xC0, 0xA8, 0x01, 0x01, # IP 192.168.1.1
            0x74, 0x65, 0x73, 0x74, 0x00  # 用户ID "test"
        ])
        
        # 分析SOCKS4 CONNECT请求
        logger.info("分析SOCKS4 CONNECT请求...")
        try:
            # 使用自定义方法分析SOCKS4请求
            socks_info = socks.SocksInfo()
            socks_info.which = 0
            socks_info.port = (socks4_connect[2] << 8) | socks4_connect[3]
            socks_info.ip = struct.unpack("!I", bytes(socks4_connect[4:8]))[0]
            socks_info.state4 = socks.SOCKS4_STATE_REPLY
            
            logger.info(f"SOCKS4请求: 端口={socks_info.port}, IP={ipaddress.IPv4Address(socks_info.ip)}")
            
            # 用户ID提取
            user_end = socks4_connect.find(b'\x00', 8)
            if user_end > 8:
                user = socks4_connect[8:user_end].decode('latin1', errors='ignore')
                logger.info(f"用户ID: {user}")
            
            logger.info("SOCKS4请求分析成功")
            
            # 保存会话信息
            session.fields['socks_ip'] = str(ipaddress.IPv4Address(socks_info.ip))
            session.fields['socks_port'] = socks_info.port
            logger.info("添加IP和端口信息到会话成功")
            
        except Exception as e:
            logger.error(f"SOCKS4分析失败: {e}")
            logger.debug(traceback.format_exc())
            
        # 测试SOCKS5
        logger.info("\n----- 测试SOCKS5协议 -----")
        
        # 创建新会话
        session2 = Session()
        session2.add_protocol("socks")
        
        # 创建SOCKS5握手请求测试数据
        socks5_handshake = bytearray([
            0x05,                   # SOCKS版本5
            0x02,                   # 支持2种认证方法
            0x00, 0x02              # 方法: 0=无认证, 2=用户名/密码
        ])
        
        # 分析SOCKS5握手请求
        logger.info("分析SOCKS5握手请求...")
        try:
            # 提取握手方法信息
            methods_count = socks5_handshake[1]
            methods = []
            for i in range(2, 2 + methods_count):
                if i < len(socks5_handshake):
                    method = socks5_handshake[i]
                    if method == 0x00:
                        methods.append("无认证")
                    elif method == 0x02:
                        methods.append("用户名/密码")
                    else:
                        methods.append(f"方法{method}")
            
            logger.info(f"支持的认证方法: {', '.join(methods)}")
            logger.info("SOCKS5握手请求分析成功")
            
            # 测试SOCKS5 CONNECT请求
            logger.info("测试SOCKS5 CONNECT请求")
            
            # 创建SOCKS5 CONNECT请求测试数据 (IPv4)
            socks5_connect_ipv4 = bytearray([
                0x05,                   # SOCKS版本5
                0x01,                   # CONNECT命令
                0x00,                   # 保留字节
                0x01,                   # 地址类型: IPv4
                0xC0, 0xA8, 0x01, 0x01, # IP 192.168.1.1
                0x00, 0x50              # 端口80
            ])
            
            # 提取IP和端口信息
            if socks5_connect_ipv4[3] == 0x01:  # IPv4
                ip_bytes = bytes(socks5_connect_ipv4[4:8])
                ip = ipaddress.IPv4Address(ip_bytes)
                port = (socks5_connect_ipv4[8] << 8) | socks5_connect_ipv4[9]
                logger.info(f"SOCKS5 CONNECT请求: 目标IP={ip}, 目标端口={port}")
                
                # 保存信息到会话
                session2.fields['socks_ipv4'] = str(ip)
                session2.fields['socks_port'] = port
                logger.info("添加IP和端口信息到会话成功")
            
            # 创建SOCKS5 CONNECT请求测试数据 (域名)
            domain = b"example.com"
            socks5_connect_domain = bytearray([
                0x05,                   # SOCKS版本5
                0x01,                   # CONNECT命令
                0x00,                   # 保留字节
                0x03,                   # 地址类型: 域名
                len(domain)             # 域名长度
            ]) + domain + bytearray([
                0x00, 0x50              # 端口80
            ])
            
            # 提取域名和端口信息
            if socks5_connect_domain[3] == 0x03:  # 域名
                domain_len = socks5_connect_domain[4]
                domain_name = socks5_connect_domain[5:5+domain_len].decode('latin1')
                port_pos = 5 + domain_len
                port = (socks5_connect_domain[port_pos] << 8) | socks5_connect_domain[port_pos + 1]
                logger.info(f"SOCKS5 CONNECT请求: 目标域名={domain_name}, 目标端口={port}")
                
                # 保存信息到会话
                session2.fields['socks_domain'] = domain_name
                session2.fields['socks_domain_port'] = port
                logger.info("添加域名和端口信息到会话成功")
            
        except Exception as e:
            logger.error(f"SOCKS5分析失败: {e}")
            logger.debug(traceback.format_exc())
        
        # 显示会话信息
        logger.info("\n----- 会话信息 -----")
        if session.has_protocol("socks"):
            logger.info("SOCKS4会话有效")
            if hasattr(session, 'fields'):
                for field_name, field_value in session.fields.items():
                    logger.info(f"字段: {field_name} = {field_value}")
        
        if session2.has_protocol("socks"):
            logger.info("SOCKS5会话有效")
            if hasattr(session2, 'fields'):
                for field_name, field_value in session2.fields.items():
                    logger.info(f"字段: {field_name} = {field_value}")
    
    except Exception as e:
        logger.error(f"SOCKS测试失败: {e}")
        logger.debug(traceback.format_exc())
        
    logger.info("\n----- SOCKS测试完成 -----")

def process_ssh_packet(packet):
    """处理捕获的SSH数据包"""
    global ssh_packets_count, ssh_client_versions, ssh_server_versions
    global ssh_kex_methods, ssh_auth_methods, ssh_cipher_client, ssh_cipher_server
    global ssh_mac_client, ssh_mac_server, ssh_hosts, ssh_usernames, ssh_kex_count, ssh_auth_count
    global ssh_connections
    
    # 增加包计数
    ssh_packets_count += 1
    
    # 创建会话对象
    session = Session()
    logger.debug("创建会话对象用于SSH分析")
    
    # 提取IP信息
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        logger.debug(f"IP层信息: 源={src_ip}, 目标={dst_ip}")
        
        # 添加SSH主机
        ssh_hosts.add(src_ip)
        ssh_hosts.add(dst_ip)
    
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        logger.debug(f"TCP层信息: 源端口={src_port}, 目标端口={dst_port}")
        
        # 分析TCP标志位
        flags = packet[TCP].flags
        flags_str = ""
        if flags & 0x01:  # FIN
            flags_str += "FIN "
        if flags & 0x02:  # SYN
            flags_str += "SYN "
        if flags & 0x04:  # RST
            flags_str += "RST "
        if flags & 0x08:  # PSH
            flags_str += "PSH "
        if flags & 0x10:  # ACK
            flags_str += "ACK "
        if flags & 0x20:  # URG
            flags_str += "URG "
        
        if flags_str:
            logger.info(f"TCP标志位: {flags_str.strip()}")
    
    # 添加数据包流向信息
    is_client_to_server = dst_port == 22
    flow_direction = "客户端->服务器" if is_client_to_server else "服务器->客户端"
    
    # 创建连接标识符
    if is_client_to_server:
        conn_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        client_ip = src_ip
        client_port = src_port
        server_ip = dst_ip
        server_port = dst_port
    else:
        conn_id = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
        client_ip = dst_ip
        client_port = dst_port
        server_ip = src_ip
        server_port = src_port
    
    # 获取或创建连接状态
    conn_state = ssh_connections.get(conn_id)
    if conn_state is None:
        conn_state = {
            'client': {'ip': client_ip, 'port': client_port},
            'server': {'ip': server_ip, 'port': server_port},
            'stage': SSH_STAGE_INIT,
            'packets': 0,
            'bytes': 0,
            'versions': [],
            'methods': set(),
            'last_update': datetime.now(),
            'errors': []
        }
        ssh_connections[conn_id] = conn_state
    
    # 更新连接状态
    conn_state['packets'] += 1
    conn_state['last_update'] = datetime.now()
    
    # 输出明显的SSH流量标记
    logger.info(f"========================= SSH流量 ({flow_direction}) ========================")
    logger.info(f"SSH连接: {src_ip}:{src_port} <-> {dst_ip}:{dst_port} [连接ID: {conn_id}]")
    logger.info(f"连接阶段: {SSH_STAGE_NAMES.get(conn_state['stage'], '未知')}")
    
    # 检查是否有Raw层
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        conn_state['bytes'] += len(payload)
        
        payload_hex = payload[:20].hex() if len(payload) >= 20 else payload.hex()
        payload_ascii = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in payload[:20])
        logger.info(f"SSH数据包: 大小={len(payload)}字节, 数据前缀={payload_hex}")
        logger.info(f"ASCII表示: {payload_ascii}")
        
        try:
            # 判断是否是SSH流量
            is_ssh = False
            
            # 检查是否是SSH握手数据包(SSH-开头)
            if len(payload) > 4 and payload[:4] == b'SSH-':
                is_ssh = True
                version_str = payload.decode('utf-8', 'ignore').strip()
                logger.info(f"💡 捕获SSH版本信息: {version_str}")
                
                # 更新连接状态 - 版本交换阶段
                conn_state['stage'] = SSH_STAGE_VERSION
                conn_state['versions'].append(version_str)
                
                # 保存客户端/服务器版本信息
                if dst_port == 22:  # 客户端->服务器
                    ssh_client_versions.add(version_str)
                    session.ssh_client_version = version_str
                    logger.info(f"客户端版本: {version_str}")
                else:  # 服务器->客户端
                    ssh_server_versions.add(version_str)
                    session.ssh_server_version = version_str
                    logger.info(f"服务器版本: {version_str}")
                
                # 保存版本信息到会话
                if 'ssh.ver' not in session.fields:
                    session.fields['ssh.ver'] = set()
                session.fields['ssh.ver'].add(version_str)
                
                # 尝试解析版本信息中的实现细节
                if "OpenSSH" in version_str:
                    logger.info(f"SSH实现: OpenSSH")
                    try:
                        version_parts = version_str.split('_')[1].split()[0]
                        logger.info(f"OpenSSH版本号: {version_parts}")
                    except:
                        pass
                elif "libssh" in version_str.lower():
                    logger.info(f"SSH实现: libssh")
                elif "putty" in version_str.lower():
                    logger.info(f"SSH实现: PuTTY")
                elif "dropbear" in version_str.lower():
                    logger.info(f"SSH实现: Dropbear")
            
            # 如果目标端口是22，也认为是SSH流量
            if src_port == 22 or dst_port == 22:
                is_ssh = True
            
            # 如果确认是SSH，设置协议标记
            if is_ssh:
                session.add_protocol("ssh")
                logger.info(f"✅ SSH流量识别成功")
                
                # 分析SSH数据包特征
                if len(payload) < 50:
                    logger.info(f"⚡ 小数据包 ({len(payload)}字节) - 可能是加密的命令或心跳包")
                    # 如果已经过了版本交换阶段，且是小数据包，可能进入了会话阶段
                    if conn_state['stage'] >= SSH_STAGE_VERSION and len(conn_state['versions']) >= 2:
                        if conn_state['stage'] < SSH_STAGE_SESSION:
                            conn_state['stage'] = SSH_STAGE_SESSION
                        
                        # 分析可能的命令类型
                        if len(payload) < 20:
                            logger.info("⚡ 可能是SSH心跳包或控制消息")
                        elif 20 <= len(payload) < 40:
                            logger.info("⚡ 可能是短命令，如cd/ls等")
                        elif 40 <= len(payload) < 100:
                            logger.info("⚡ 可能是中等长度命令")
                            
                elif len(payload) > 500:
                    logger.info(f"⚡ 大数据包 ({len(payload)}字节) - 可能是文件传输或批量数据")
                    if conn_state['stage'] >= SSH_STAGE_SESSION:
                        logger.info("⚡ 检测到可能的大文件传输 - SSH通道中的SCP/SFTP活动")
                
                # 基于TCP标志位提供更多上下文
                if "SYN" in flags_str and not "ACK" in flags_str:
                    logger.info("⚡ SSH连接建立阶段 - SYN包")
                    conn_state['stage'] = SSH_STAGE_INIT
                elif "SYN" in flags_str and "ACK" in flags_str:
                    logger.info("⚡ SSH连接建立阶段 - SYN+ACK包")
                    conn_state['stage'] = SSH_STAGE_INIT
                elif "PSH" in flags_str and "ACK" in flags_str:
                    if len(payload) > 100 and conn_state['stage'] <= SSH_STAGE_VERSION:
                        logger.info("⚡ SSH数据传输阶段 - 密钥交换或认证可能正在进行")
                        conn_state['stage'] = SSH_STAGE_KEX
                    elif len(payload) > 100 and conn_state['stage'] == SSH_STAGE_KEX:
                        logger.info("⚡ SSH数据传输阶段 - 认证可能正在进行")
                        conn_state['stage'] = SSH_STAGE_AUTH
                    elif conn_state['stage'] >= SSH_STAGE_AUTH:
                        logger.info("⚡ SSH数据传输阶段 - 交互命令可能正在传输")
                        if conn_state['stage'] < SSH_STAGE_SESSION:
                            conn_state['stage'] = SSH_STAGE_SESSION
                elif "FIN" in flags_str:
                    logger.info("⚡ SSH连接关闭阶段")
                    conn_state['stage'] = SSH_STAGE_CLOSING
                
                # 根据当前阶段提供上下文信息
                if conn_state['stage'] == SSH_STAGE_INIT:
                    logger.info("⚡ SSH连接初始阶段 - TCP握手")
                elif conn_state['stage'] == SSH_STAGE_VERSION:
                    logger.info("⚡ SSH版本交换阶段")
                elif conn_state['stage'] == SSH_STAGE_KEX:
                    logger.info("⚡ SSH密钥交换阶段 - 协商加密参数")
                elif conn_state['stage'] == SSH_STAGE_AUTH:
                    logger.info("⚡ SSH认证阶段 - 用户身份验证")
                elif conn_state['stage'] == SSH_STAGE_SESSION:
                    logger.info("⚡ SSH会话阶段 - 安全通道已建立")
                    # 分析交互模式vs批量传输
                    if len(payload) < 100:
                        logger.info("⚡ 可能是交互式命令")
                    else:
                        logger.info("⚡ 可能是批量数据传输")
                elif conn_state['stage'] == SSH_STAGE_DATA:
                    logger.info("⚡ SSH数据传输阶段")
                elif conn_state['stage'] == SSH_STAGE_CLOSING:
                    logger.info("⚡ SSH连接关闭阶段 - 释放资源")
            
            # 检查密钥交换消息 - 通常是长消息，且ssh已确认的包
            if is_ssh and len(payload) > 100:
                logger.info(f"💡 可能的SSH密钥交换消息: {len(payload)}字节")
                # 更新密钥交换计数
                ssh_kex_count += 1
                
                # 如果在版本交换后且数据包较大，认为进入密钥交换阶段
                if conn_state['stage'] == SSH_STAGE_VERSION:
                    conn_state['stage'] = SSH_STAGE_KEX
                
                # 检查常见的密钥交换算法
                algorithms = {
                    'diffie-hellman-group1-sha1': b'diffie-hellman-group1-sha1',
                    'diffie-hellman-group14-sha1': b'diffie-hellman-group14-sha1',
                    'diffie-hellman-group-exchange-sha1': b'diffie-hellman-group-exchange-sha1',
                    'diffie-hellman-group-exchange-sha256': b'diffie-hellman-group-exchange-sha256',
                    'ecdh-sha2-nistp256': b'ecdh-sha2-nistp256',
                    'ecdh-sha2-nistp384': b'ecdh-sha2-nistp384',
                    'ecdh-sha2-nistp521': b'ecdh-sha2-nistp521',
                    'curve25519-sha256': b'curve25519-sha256',
                    'curve25519-sha256@libssh.org': b'curve25519-sha256@libssh.org',
                }
                
                for alg_name, alg_bytes in algorithms.items():
                    if alg_bytes in payload:
                        ssh_kex_methods.add(alg_name)
                        conn_state['methods'].add(alg_name)
                        logger.info(f"✅ 检测到密钥交换算法: {alg_name}")
                
                # 检查加密算法
                cipher_algorithms = {
                    'aes128-ctr': b'aes128-ctr',
                    'aes192-ctr': b'aes192-ctr',
                    'aes256-ctr': b'aes256-ctr',
                    'aes128-gcm': b'aes128-gcm',
                    'aes256-gcm': b'aes256-gcm',
                    'chacha20-poly1305': b'chacha20-poly1305',
                }
                
                for cipher_name, cipher_bytes in cipher_algorithms.items():
                    if cipher_bytes in payload:
                        if dst_port == 22:
                            ssh_cipher_client.add(cipher_name)
                            conn_state['methods'].add(cipher_name)
                            logger.info(f"✅ 检测到客户端加密算法: {cipher_name}")
                        else:
                            ssh_cipher_server.add(cipher_name)
                            conn_state['methods'].add(cipher_name)
                            logger.info(f"✅ 检测到服务器加密算法: {cipher_name}")
            
            # 检查认证消息
            if is_ssh and len(payload) > 20:
                # 解析认证信息
                auth_algorithms = {
                    'password': b'password',
                    'publickey': b'publickey',
                    'keyboard-interactive': b'keyboard-interactive', 
                    'hostbased': b'hostbased',
                    'gssapi': b'gssapi',
                }
                
                auth_detected = False
                for auth_name, auth_bytes in auth_algorithms.items():
                    if auth_bytes in payload:
                        ssh_auth_methods.add(auth_name)
                        conn_state['methods'].add(auth_name)
                        ssh_auth_count += 1
                        auth_detected = True
                        logger.info(f"✅ 检测到认证方法: {auth_name}")
                
                # 如果检测到认证信息，更新阶段为认证阶段
                if auth_detected and conn_state['stage'] < SSH_STAGE_AUTH:
                    conn_state['stage'] = SSH_STAGE_AUTH
                
                # 查找常见的用户名
                common_usernames = ['root', 'admin', 'user', 'ubuntu', 'ec2-user', 
                                  'centos', 'fedora', 'debian', 'pi', 'guest']
                
                for username in common_usernames:
                    username_bytes = username.encode('utf-8')
                    if username_bytes in payload:
                        ssh_usernames.add(username)
                        logger.info(f"✅ 检测到SSH用户名: {username}")
            
            # 每个SSH数据包都显示一次当前统计信息（此连接的状态）
            logger.info(f"SSH会话统计 ({conn_id}):")
            logger.info(f"  连接阶段: {SSH_STAGE_NAMES.get(conn_state['stage'], '未知')}")
            logger.info(f"  总包数: {conn_state['packets']} (总计 {ssh_packets_count})")
            logger.info(f"  传输字节数: {conn_state['bytes']} 字节")
            if conn_state['versions']:
                logger.info(f"  版本信息: {', '.join(conn_state['versions'])}")
            if conn_state['methods']:
                logger.info(f"  检测到的算法/方法: {', '.join(conn_state['methods'])}")
            
            # 全局SSH流量统计
            if ssh_packets_count % 5 == 0:  # 每5个包输出一次全局统计
                logger.info(f"SSH全局统计:")
                logger.info(f"  活动连接: {len(ssh_connections)}")
                logger.info(f"  总数据包: {ssh_packets_count}")
                logger.info(f"  密钥交换数量: {ssh_kex_count}")
                if ssh_auth_count > 0:
                    logger.info(f"  认证尝试: {ssh_auth_count}")
                if ssh_client_versions:
                    logger.info(f"  客户端版本: {', '.join(ssh_client_versions)[:60]}...")
                if ssh_server_versions:
                    logger.info(f"  服务器版本: {', '.join(ssh_server_versions)[:60]}...")
                if ssh_kex_methods:
                    logger.info(f"  密钥交换算法: {', '.join(ssh_kex_methods)[:60]}...")
                if ssh_auth_methods:
                    logger.info(f"  认证方法: {', '.join(ssh_auth_methods)}")
                if ssh_usernames:
                    logger.info(f"  用户名: {', '.join(ssh_usernames)}")
            
        except Exception as e:
            logger.error(f"处理SSH数据包时出错: {e}")
            logger.debug(traceback.format_exc())
            # 记录错误到连接状态
            if 'errors' in conn_state:
                conn_state['errors'].append(str(e))
    
    logger.info(f"========================= SSH流量结束 ======================")


    return session

def call_all_ssh_functions():
    """调用ssh.py中的所有函数"""
    logger.info("开始调用SSH模块中的所有函数...")
    
    # 添加全局变量引用
    global ssh_packets_count, ssh_kex_count, ssh_auth_count
    global ssh_client_versions, ssh_server_versions
    global ssh_kex_methods, ssh_auth_methods
    global ssh_cipher_client, ssh_cipher_server
    global ssh_mac_client, ssh_mac_server
    global ssh_hosts, ssh_usernames
    
    try:
        # 初始化SSH解析器
        logger.info("\n========== 调用 ssh.parser_init() ==========")
        ssh.parser_init()
        
        # 创建测试会话对象
        session = Session()
        session.add_protocol("ssh")
        
        # 展示SSH协议常量和字段
        logger.info("\n========== SSH协议字段 ==========")
        try:
            # 使用dir()获取ssh模块的所有属性
            module_attrs = [attr for attr in dir(ssh) if not attr.startswith('__')]
            logger.info(f"SSH模块属性: {module_attrs}")
            
            # 查找字段
            field_attrs = [attr for attr in module_attrs if 'field' in attr.lower()]
            logger.info(f"SSH字段: {field_attrs}")
            
            # 查找状态常量
            state_attrs = [attr for attr in module_attrs if 'state' in attr.lower()]
            logger.info(f"SSH状态常量: {state_attrs}")
            
            # 查找函数
            func_attrs = [attr for attr in module_attrs if callable(getattr(ssh, attr))]
            logger.info(f"SSH函数: {func_attrs}")
        except Exception as e:
            logger.error(f"获取SSH模块属性失败: {e}")
        
        # 创建和检查SshInfo对象
        logger.info("\n========== SSH测试 ==========")
        
        # 创建一个SSH版本测试字符串
        version_str = "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2"
        
        # 将信息添加到会话
        if 'ssh.ver' not in session.fields:
            session.fields['ssh.ver'] = set()
        session.fields['ssh.ver'].add(version_str)
        session.ssh_version = version_str
        
        logger.info(f"添加SSH版本信息: {version_str}")
        
        # 输出一些SSH测试信息用于统计
        ssh_client_versions.add(version_str)
        ssh_hosts.add("192.168.1.100")
        ssh_kex_methods.add("curve25519-sha256")
        ssh_auth_methods.add("publickey")
        ssh_cipher_client.add("aes256-ctr")
        ssh_usernames.add("testuser")
        
        # 更新统计计数器
        ssh_packets_count += 1
        ssh_kex_count += 1
        ssh_auth_count += 1
        
        logger.info(f"SSH测试账号: {ssh_usernames}")
        logger.info(f"SSH测试密钥交换: {ssh_kex_methods}")
        logger.info(f"SSH测试认证方法: {ssh_auth_methods}")
        
        logger.info("\n========== SSH模块测试完成 ==========")
        
    except ImportError as e:
        logger.error(f"导入失败: {e}")
    except Exception as e:
        logger.error(f"发生错误: {e}")
        logger.error(traceback.format_exc())

def ssh_test():
    """运行SSH解析器测试"""
    logger.info("开始运行SSH测试...")
    
    # 添加全局变量引用
    global ssh_packets_count, ssh_kex_count, ssh_auth_count
    global ssh_client_versions, ssh_server_versions
    global ssh_kex_methods, ssh_auth_methods
    global ssh_cipher_client, ssh_cipher_server
    global ssh_mac_client, ssh_mac_server
    global ssh_hosts, ssh_usernames
    global ssh_connections
    
    # 初始化SSH解析器
    logger.info("初始化SSH解析器...")
    ssh.parser_init()
    
    # 创建会话对象
    session = Session()
    session.add_protocol("ssh")
    
    # 设置字段
    if 'ssh.ver' not in session.fields:
        session.fields['ssh.ver'] = set()
    
    # 测试SSH版本检测
    logger.info("\n----- 测试SSH版本检测 -----")
    
    # 模拟SSH版本字符串
    version_str = "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2"
    session.fields['ssh.ver'].add(version_str)
    session.ssh_version = version_str
    
    # 更新统计信息
    ssh_client_versions.add(version_str)
    logger.info(f"SSH客户端版本: {version_str}")
    
    # 添加测试数据用于统计
    ssh_hosts.add("192.168.1.1")
    ssh_hosts.add("192.168.1.2")
    logger.info(f"测试SSH主机: {ssh_hosts}")
    
    # 测试SSH密钥交换检测
    logger.info("\n----- 测试SSH密钥交换检测 -----")
    
    # 添加测试数据用于统计
    ssh_kex_count += 1
    ssh_kex_methods.add("curve25519-sha256")
    ssh_kex_methods.add("ecdh-sha2-nistp256")
    logger.info(f"测试SSH密钥交换方法: {ssh_kex_methods}")
    
    # 添加加密算法信息
    ssh_cipher_client.add("aes256-ctr")
    ssh_cipher_client.add("chacha20-poly1305")
    ssh_cipher_server.add("aes256-ctr")
    logger.info(f"测试SSH客户端加密算法: {ssh_cipher_client}")
    logger.info(f"测试SSH服务器加密算法: {ssh_cipher_server}")
    
    # 测试SSH认证检测
    logger.info("\n----- 测试SSH认证检测 -----")
    
    # 添加测试数据用于统计
    ssh_auth_count += 1
    ssh_auth_methods.add("publickey")
    ssh_auth_methods.add("password")
    logger.info(f"测试SSH认证方法: {ssh_auth_methods}")
    
    # 添加用户信息
    ssh_usernames.add("root")
    ssh_usernames.add("admin")
    logger.info(f"测试SSH用户名: {ssh_usernames}")
    
    # 测试SSH连接跟踪功能
    logger.info("\n----- 测试SSH连接跟踪功能 -----")
    
    # 创建测试连接
    test_conn_id = "192.168.1.100:12345->192.168.1.200:22"
    test_conn = {
        'client': {'ip': '192.168.1.100', 'port': 12345},
        'server': {'ip': '192.168.1.200', 'port': 22},
        'stage': SSH_STAGE_VERSION,
        'packets': 5,
        'bytes': 1024,
        'versions': ["SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"],
        'methods': {"curve25519-sha256", "aes256-ctr", "publickey"},
        'last_update': datetime.now(),
        'errors': []
    }
    ssh_connections[test_conn_id] = test_conn
    
    # 模拟连接进入不同阶段
    for stage in [SSH_STAGE_KEX, SSH_STAGE_AUTH, SSH_STAGE_SESSION, SSH_STAGE_DATA]:
        test_conn['stage'] = stage
        logger.info(f"连接 {test_conn_id} 进入阶段: {SSH_STAGE_NAMES[stage]}")
        logger.info(f"  连接状态: 包数={test_conn['packets']}, 字节数={test_conn['bytes']}")
        logger.info(f"  检测到的方法: {', '.join(test_conn['methods'])}")
        # 模拟包计数增加
        test_conn['packets'] += 1
        test_conn['bytes'] += 256
    
    # 测试关闭阶段
    test_conn['stage'] = SSH_STAGE_CLOSING
    logger.info(f"连接 {test_conn_id} 进入阶段: {SSH_STAGE_NAMES[SSH_STAGE_CLOSING]}")
    
    # 显示所有活动连接
    logger.info(f"\n活动SSH连接: {len(ssh_connections)}")
    for conn_id, conn in ssh_connections.items():
        logger.info(f"连接 {conn_id}: {SSH_STAGE_NAMES[conn['stage']]}, {conn['packets']}包, {conn['bytes']}字节")
    
    logger.info("\n----- SSH统计信息 -----")
    logger.info(f"SSH数据包: {ssh_packets_count + 1}")  # +1表示这次测试
    logger.info(f"密钥交换次数: {ssh_kex_count}")
    logger.info(f"认证尝试次数: {ssh_auth_count}")
    logger.info(f"客户端版本: {ssh_client_versions}")
    logger.info(f"密钥交换方法: {ssh_kex_methods}")
    logger.info(f"认证方法: {ssh_auth_methods}")
    logger.info(f"用户名: {ssh_usernames}")
    
    logger.info("\n----- SSH测试完成 -----")

def icmp_test():
    """运行ICMP解析器测试"""
    logger.info("开始运行ICMP测试...")
    
    # 初始化ICMP解析器
    logger.info("初始化ICMP解析器...")
    icmp.parser_init()
    
    # 创建ICMP测试数据包
    logger.info("创建ICMP测试数据...")
    icmp_echo_request = (
        b"\x08\x00"  # 类型 (8=Echo Request), 代码 (0)
        b"\x00\x00"  # 校验和 (占位)
        b"\x12\x34"  # 标识符
        b"\x00\x01"  # 序列号
        b"abcdefgh"  # 数据
    )
    
    # 创建会话对象
    session = Session()
    
    # 解析ICMP请求
    logger.info("解析ICMP请求...")
    
    # 创建ICMP信息对象
    class IcmpPacket:
        def __init__(self, type_value, code_value):
            self.type = type_value
            self.code = code_value
            self.id = 0x1234
            self.seq = 0x0001
    
    # 创建ICMP数据包对象
    icmp_packet = IcmpPacket(8, 0)  # Echo请求类型=8, 代码=0
    
    # 调用ICMP解析器
    metadata = {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8'}
    try:
        icmp.icmp_parser(session, icmp_packet, bytearray(icmp_echo_request), len(icmp_echo_request), metadata)
        logger.info("ICMP Echo请求解析成功")
        
        # 显示一些ICMP信息
        if hasattr(session, 'icmp_type'):
            logger.info(f"ICMP类型: {session.icmp_type}")
        if hasattr(session, 'icmp_code'):
            logger.info(f"ICMP代码: {session.icmp_code}")
        if hasattr(session, 'icmp_id'):
            logger.info(f"ICMP ID: {session.icmp_id}")
        if hasattr(session, 'icmp_seq'):
            logger.info(f"ICMP序列号: {session.icmp_seq}")
    except Exception as e:
        logger.error(f"ICMP解析失败: {e}")
    
    logger.info("ICMP测试运行完成")

def dhcp_test():
    """运行DHCP解析器测试"""
    logger.info("开始运行DHCP测试...")
    
    # 初始化DHCP解析器
    logger.info("初始化DHCP解析器...")
    dhcp.parser_init()
    
    # 创建DHCP测试数据包 - DHCP Discover示例
    logger.info("创建DHCP测试数据...")
    dhcp_discover = bytearray([
        0x01,  # 操作码 (1=请求)
        0x01,  # 硬件类型 (1=以太网)
        0x06,  # 硬件地址长度 (6=MAC地址)
        0x00,  # 跳数
        0x12, 0x34, 0x56, 0x78,  # 事务ID
        0x00, 0x00,  # 秒数
        0x00, 0x00,  # 标志
        0x00, 0x00, 0x00, 0x00,  # 客户端IP
        0x00, 0x00, 0x00, 0x00,  # 分配的IP
        0x00, 0x00, 0x00, 0x00,  # 服务器IP
        0x00, 0x00, 0x00, 0x00,  # 网关IP
    ])
    # 添加客户端MAC (填充到16字节)
    dhcp_discover.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    # 添加服务器主机名 (64字节) 和引导文件名 (128字节)
    dhcp_discover.extend([0x00] * 192)
    # 添加Magic Cookie和DHCP选项
    dhcp_discover.extend([0x63, 0x82, 0x53, 0x63])  # Magic Cookie
    dhcp_discover.extend([0x35, 0x01, 0x01])  # Option 53 (DHCP Message Type), 长度=1, DHCP Discover
    dhcp_discover.extend([0xff])  # 结束选项
    
    # 创建会话对象
    session = Session()
    
    # 解析DHCP数据包
    logger.info("解析DHCP Discover...")
    metadata = {'src_ip': '0.0.0.0', 'dst_ip': '255.255.255.255', 'src_port': 68, 'dst_port': 67}
    try:
        # 使用正确的DHCP解析函数
        dhcp.dhcp_udp_parser(session, None, dhcp_discover, len(dhcp_discover), 0)
        logger.info("DHCP Discover解析成功")
        
        # 显示一些DHCP信息
        if hasattr(session, 'dhcp_msg_type'):
            logger.info(f"DHCP消息类型: {session.dhcp_msg_type}")
        if hasattr(session, 'dhcp_client_mac'):
            logger.info(f"客户端MAC: {session.dhcp_client_mac}")
        if hasattr(session, 'dhcp_transaction_id'):
            logger.info(f"事务ID: {session.dhcp_transaction_id:08x}")
        
    except Exception as e:
        logger.error(f"DHCP解析失败: {e}")
    
    logger.info("DHCP测试运行完成")

def call_all_dhcp_functions():
    """调用dhcp.py中的所有函数"""
    logger.info("开始调用DHCP模块中的所有函数...")
    
    try:
        # 初始化DHCP解析器
        logger.info("\n========== 调用 dhcp.parser_init() ==========")
        dhcp.parser_init()
        
        # 创建测试会话对象
        session = Session()
        
        # 创建DHCP测试数据
        logger.info("\n========== 创建DHCP测试数据 ==========")
        dhcp_discover = bytearray([
            0x01, 0x01, 0x06, 0x00,  # 操作码, 硬件类型, 硬件地址长度, 跳数
            0x12, 0x34, 0x56, 0x78,  # 事务ID
            0x00, 0x00, 0x00, 0x00,  # 秒数和标志
            0x00, 0x00, 0x00, 0x00,  # 客户端IP
            0x00, 0x00, 0x00, 0x00,  # 分配的IP
            0x00, 0x00, 0x00, 0x00,  # 服务器IP
            0x00, 0x00, 0x00, 0x00,  # 网关IP
        ])
        # 添加客户端MAC (填充到16字节)
        dhcp_discover.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        # 添加服务器主机名 (64字节) 和引导文件名 (128字节)
        dhcp_discover.extend([0x00] * 192)
        # 添加Magic Cookie和DHCP选项
        dhcp_discover.extend([0x63, 0x82, 0x53, 0x63])  # Magic Cookie
        dhcp_discover.extend([0x35, 0x01, 0x01])  # Option 53 (DHCP Message Type), 长度=1, DHCP Discover
        dhcp_discover.extend([0xff])  # 结束选项
        
        # 调用DHCP解析器
        logger.info("\n========== 调用 dhcp_parser() ==========")
        metadata = {'src_ip': '0.0.0.0', 'dst_ip': '255.255.255.255', 'src_port': 68, 'dst_port': 67}
        try:
            dhcp.dhcp_parser(session, dhcp_discover, len(dhcp_discover), metadata)
            logger.info("DHCP解析成功")
        except Exception as e:
            logger.error(f"DHCP解析器失败: {e}")
            
        logger.info("\n========== DHCP模块所有函数调用完成 ==========")
        
    except ImportError as e:
        logger.error(f"导入失败: {e}")
    except Exception as e:
        logger.error(f"发生错误: {e}")
        logger.error(traceback.format_exc())

# 添加SSH连接状态全局变量
ssh_connections = {}  # 存储所有活动SSH连接的状态信息

# 连接阶段枚举
SSH_STAGE_INIT = 0      # 初始阶段
SSH_STAGE_VERSION = 1   # 版本交换
SSH_STAGE_KEX = 2       # 密钥交换
SSH_STAGE_AUTH = 3      # 认证
SSH_STAGE_SESSION = 4   # 会话建立
SSH_STAGE_DATA = 5      # 数据传输
SSH_STAGE_CLOSING = 6   # 连接关闭

# SSH阶段名称
SSH_STAGE_NAMES = {
    SSH_STAGE_INIT: "初始化",
    SSH_STAGE_VERSION: "版本交换",
    SSH_STAGE_KEX: "密钥交换",
    SSH_STAGE_AUTH: "认证阶段",
    SSH_STAGE_SESSION: "会话建立",
    SSH_STAGE_DATA: "数据传输",
    SSH_STAGE_CLOSING: "连接关闭"
}

def process_tls_packet(packet):
    """处理捕获的TLS数据包"""
    global tls_packets_count, tls_client_hello_count, tls_server_hello_count
    global tls_certificate_count, tls_handshake_count, tls_alert_count, tls_application_data_count
    global tls_versions, tls_cipher_suites, tls_extensions, tls_hosts
    global tls_ja3_fingerprints, tls_ja3s_fingerprints, tls_ja4_fingerprints
    global tls_client_count, tls_server_count, tls_connections
    
    # 增加包计数
    tls_packets_count += 1
    
    # 创建会话对象
    session = Session()
    logger.debug("创建会话对象用于TLS分析")
    
    # 提取IP信息
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        logger.debug(f"IP层信息: 源={src_ip}, 目标={dst_ip}")
        
        # 设置会话基本信息
        session.addr1 = ipaddress.IPv4Address(src_ip) if packet.haslayer(IP) else ipaddress.IPv6Address(src_ip)
        session.addr2 = ipaddress.IPv4Address(dst_ip) if packet.haslayer(IP) else ipaddress.IPv6Address(dst_ip)
        session.port1 = src_port
        session.port2 = dst_port
        session.ip_protocol = 6  # TCP协议号
        session.is_session_v6 = packet.haslayer(IPv6)
        session.session_id = 0
        session.databytes = len(packet)
        
        # 设置会话字段
        session.fields['src_ip'] = str(session.addr1)
        session.fields['dst_ip'] = str(session.addr2)
        session.fields['src_port'] = session.port1
        session.fields['dst_port'] = session.port2
        session.fields['ip_protocol'] = session.ip_protocol
        session.fields['is_ipv6'] = session.is_session_v6
        session.fields['session_id'] = session.session_id
        session.fields['databytes'] = session.databytes
        
        # 添加TLS主机
        tls_hosts.add(src_ip)
        tls_hosts.add(dst_ip)
    
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        logger.debug(f"TCP层信息: 源端口={src_port}, 目标端口={dst_port}")
    
    # 检查是否有Raw层
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        
        # 创建连接标识符
        is_client_to_server = dst_port in (443, 8443) or (dst_port > 1024 and src_port < 1024)
        if is_client_to_server:
            conn_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            client_ip = src_ip
            client_port = src_port
            server_ip = dst_ip
            server_port = dst_port
        else:
            conn_id = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
            client_ip = dst_ip
            client_port = dst_port
            server_ip = src_ip
            server_port = src_port
        
        # 获取或创建连接状态
        conn_state = tls_connections.get(conn_id)
        if conn_state is None:
            conn_state = {
                'client': {'ip': client_ip, 'port': client_port},
                'server': {'ip': server_ip, 'port': server_port},
                'stage': TLS_STAGE_INIT,
                'packets': 0,
                'bytes': 0,
                'versions': set(),
                'ciphers': set(),
                'last_update': datetime.now(),
                'errors': []
            }
            tls_connections[conn_id] = conn_state
        
        # 更新连接状态
        conn_state['packets'] += 1
        conn_state['bytes'] += len(payload)
        conn_state['last_update'] = datetime.now()
        
        # 确定数据流方向
        flow_direction = "客户端->服务器" if is_client_to_server else "服务器->客户端"
        
        try:
            # 简单检查TLS记录层头部 (Content Type, Version, Length)
            if len(payload) >= 5:
                record_type = payload[0]
                record_version = (payload[1] << 8) | payload[2]
                record_length = (payload[3] << 8) | payload[4]
                
                # 检查是否是有效的TLS记录类型
                is_tls = (0 < record_type <= 23) and (0x0300 <= record_version <= 0x0304 or 0x7f00 <= record_version <= 0x7fff)
                
                # 合理的TLS记录长度检查
                is_length_valid = record_length <= 16384 and record_length <= len(payload) - 5
                
                if is_tls and is_length_valid:
                    logger.info(f"========================= TLS流量 ({flow_direction}) ========================")
                    logger.info(f"TLS连接: {src_ip}:{src_port} <-> {dst_ip}:{dst_port} [连接ID: {conn_id}]")
                    
                    # 添加基本信息到会话对象
                    if 'tls.ver' not in session.fields:
                        session.fields['tls.ver'] = set()
                    
                    # 将记录层版本添加到会话
                    tls_session_version = ""
                    if record_version == 0x0300:
                        tls_session_version = "SSLv3"
                    elif record_version == 0x0301:
                        tls_session_version = "TLSv1.0"
                    elif record_version == 0x0302:
                        tls_session_version = "TLSv1.1"
                    elif record_version == 0x0303:
                        tls_session_version = "TLSv1.2"
                    elif record_version == 0x0304:
                        tls_session_version = "TLSv1.3"
                    elif 0x7f00 <= record_version <= 0x7fff:
                        tls_session_version = f"TLSv1.3-draft-{record_version & 0xff:02d}"
                    else:
                        tls_session_version = f"0x{record_version:04x}"
                    
                    session.fields['tls.ver'].add(tls_session_version)
                    tls_versions.add(tls_session_version)
                    
                    # 分析TLS记录类型
                    if record_type == 20:  # Change Cipher Spec
                        logger.info(f"TLS记录类型: Change Cipher Spec")
                        conn_state['stage'] = TLS_STAGE_CHANGE_CIPHER
                    elif record_type == 21:  # Alert
                        logger.info(f"TLS记录类型: Alert")
                        tls_alert_count += 1
                        conn_state['stage'] = TLS_STAGE_ALERT
                        
                        # 尝试解析警告级别和描述
                        if len(payload) >= 7:
                            alert_level = payload[5]
                            alert_description = payload[6]
                            level_str = "致命" if alert_level == 2 else "警告"
                            logger.info(f"TLS警告: 级别={level_str}({alert_level}), 描述={alert_description}")
                    elif record_type == 22:  # Handshake
                        logger.info(f"TLS记录类型: Handshake")
                        tls_handshake_count += 1
                        
                        # 解析握手消息类型
                        if len(payload) >= 6:
                            handshake_type = payload[5]
                            
                            # 根据握手类型进行处理
                            if handshake_type == 1:  # Client Hello
                                logger.info(f"TLS握手类型: Client Hello")
                                tls_client_hello_count += 1
                                conn_state['stage'] = TLS_STAGE_CLIENT_HELLO
                                tls_client_count += 1
                                
                                # 将原始数据传递给TLS模块进行深度分析
                                tls_info = tls.TLSInfo(buf=payload, length=len(payload), which=0)
                                tls.tls_process_client_hello_data(session, payload, len(payload), 0)
                                
                                # 从会话中提取JA3/JA4指纹
                                if 'tls.ja3' in session.fields:
                                    ja3 = list(session.fields['tls.ja3'])[0] if len(session.fields['tls.ja3']) > 0 else ""
                                    if ja3:
                                        logger.info(f"JA3指纹: {ja3}")
                                        tls_ja3_fingerprints.add(ja3)
                                
                                if 'tls.ja4' in session.fields:
                                    ja4 = list(session.fields['tls.ja4'])[0] if len(session.fields['tls.ja4']) > 0 else ""
                                    if ja4:
                                        logger.info(f"JA4指纹: {ja4}")
                                        tls_ja4_fingerprints.add(ja4)
                            
                            elif handshake_type == 2:  # Server Hello
                                logger.info(f"TLS握手类型: Server Hello")
                                tls_server_hello_count += 1
                                conn_state['stage'] = TLS_STAGE_SERVER_HELLO
                                tls_server_count += 1
                                
                                # 将原始数据传递给TLS模块进行深度分析
                                tls_info = tls.TLSInfo(buf=payload, length=len(payload), which=1)
                                tls.tls_process_server_hello(session, payload, len(payload), 0)
                                
                                # 从会话中提取JA3S指纹和密码套件
                                if 'tls.ja3s' in session.fields:
                                    ja3s = list(session.fields['tls.ja3s'])[0] if len(session.fields['tls.ja3s']) > 0 else ""
                                    if ja3s:
                                        logger.info(f"JA3S指纹: {ja3s}")
                                        tls_ja3s_fingerprints.add(ja3s)
                                
                                if 'tls.cipher' in session.fields:
                                    cipher = list(session.fields['tls.cipher'])[0] if len(session.fields['tls.cipher']) > 0 else ""
                                    if cipher:
                                        logger.info(f"选择的密码套件: {cipher}")
                                        tls_cipher_suites.add(cipher)
                                        conn_state['ciphers'].add(cipher)
                            
                            elif handshake_type == 11:  # Certificate
                                logger.info(f"TLS握手类型: Certificate")
                                tls_certificate_count += 1
                                conn_state['stage'] = TLS_STAGE_CERTIFICATE
                            
                            elif handshake_type == 14:  # Server Hello Done
                                logger.info(f"TLS握手类型: Server Hello Done")
                                conn_state['stage'] = TLS_STAGE_SERVER_DONE
                            
                            elif handshake_type == 16:  # Client Key Exchange
                                logger.info(f"TLS握手类型: Client Key Exchange")
                                conn_state['stage'] = TLS_STAGE_CLIENT_KEY_EXCHANGE
                            
                            else:
                                logger.info(f"TLS握手类型: 未知({handshake_type})")
                    
                    elif record_type == 23:  # Application Data
                        logger.info(f"TLS记录类型: Application Data")
                        tls_application_data_count += 1
                        conn_state['stage'] = TLS_STAGE_APPLICATION
                    
                    else:
                        logger.info(f"TLS记录类型: 未知({record_type})")
                    
                    # 输出连接阶段信息
                    logger.info(f"连接阶段: {TLS_STAGE_NAMES.get(conn_state['stage'], '未知')}")
                    
                    # 输出连接统计信息
                    if conn_state['packets'] > 1:
                        logger.info(f"连接统计: {conn_state['packets']}个包, {conn_state['bytes']}字节")
                    
                    # 给会话添加TLS协议标记
                    session.add_protocol("tls")
                    
                    session_data = session.get_readable_fields()
                    session.fields.update(session_data)
                    
            # 处理特定端口上的非标准TLS流量
            elif (src_port == 443 or dst_port == 443) and len(payload) > 0:
                logger.info(f"端口443上的可能TLS流量: {len(payload)}字节, 但无法识别TLS记录头")
        
        except Exception as e:
            logger.error(f"处理TLS数据包时出错: {e}")
            if conn_state:
                conn_state['errors'].append(str(e))
    
    return session

# 添加TLS回调函数
def tls_getcb_versions(session):
    """获取TLS版本"""
    if 'tls.ver' in session.fields:
        return list(session.fields['tls.ver'])
    return []

def tls_getcb_ciphers(session):
    """获取TLS密码套件"""
    if 'tls.cipher' in session.fields:
        return list(session.fields['tls.cipher'])
    return []

def tls_getcb_ja3(session):
    """获取TLS JA3指纹"""
    if 'tls.ja3' in session.fields:
        return list(session.fields['tls.ja3'])
    return []

def tls_getcb_ja3s(session):
    """获取TLS JA3S指纹"""
    if 'tls.ja3s' in session.fields:
        return list(session.fields['tls.ja3s'])
    return []

def tls_getcb_ja4(session):
    """获取TLS JA4指纹"""
    if 'tls.ja4' in session.fields:
        return list(session.fields['tls.ja4'])
    return []

def tls_getcb_hosts(session):
    """获取TLS主机"""
    hosts = []
    if 'ip.src' in session.fields and session.has_protocol("tls"):
        hosts.extend(list(session.fields['ip.src']))
    if 'ip.dst' in session.fields and session.has_protocol("tls"):
        hosts.extend(list(session.fields['ip.dst']))
    return hosts

def call_all_tls_functions():
    """调用tls.py中的所有函数"""
    logger.info("开始调用TLS模块中的所有函数...")
    
    try:
        # 初始化TLS解析器
        logger.info("\n========== 调用 tls.parser_init() ==========")
        tls.parser_init()
        
        # 创建测试会话对象
        session = Session()
        
        # 测试TLS各类回调函数
        logger.info("\n========== 测试TLS回调函数 ==========")
        
        # 创建Client Hello测试数据 (TLS 1.2)
        tls_client_hello = bytes.fromhex(
            "16030100c1010000bd03033d852b477bfb08f8c2e51128dc2956a393a66a03"
            "5734a946b79c5942182f5b31001c0a0a130113021303c02bc02fc02cc030cc"
            "a9cca8c009c013c00ac014009c009d002f003500ff010001780000001a0018"
            "00000f6578616d706c652e626c6f672e636f6d000b000403000102000a000c"
            "000a001d0017001e00190018001000130011001200300016001500170018000b"
            "00020100002300000010000e000c02683208687474702f312e310005000501"
            "00000000000d001a001804030804040105030805050108060601020603020802"
            "0801002b0009080304030303020301002d00020101001c00024001"
        )
        
        # 创建Server Hello测试数据 (TLS 1.2)
        tls_server_hello = bytes.fromhex(
            "1603030046020000420303f0e71a9144caf7903ba23a7ff6683e3740e78ac"
            "36e9cb564a1cab3e372255b83d65f301a8c9c59da7a94d23b8b4db6cca96e"
            "b0c751a68a27430a13010000"
        )
        
        # 测试处理Client Hello
        logger.info("\n========== 调用 tls.tls_process_client_hello_data() ==========")
        tls.tls_process_client_hello_data(session, tls_client_hello, len(tls_client_hello), 0)
        
        # 测试处理Server Hello
        logger.info("\n========== 调用 tls.tls_process_server_hello() ==========")
        tls.tls_process_server_hello(session, tls_server_hello, len(tls_server_hello), 0)
        
        # 测试TLS回调函数
        logger.info("\n========== 测试 tls_getcb_versions() ==========")
        versions = tls_getcb_versions(session)
        logger.info(f"TLS版本: {versions}")
        
        logger.info("\n========== 测试 tls_getcb_ciphers() ==========")
        ciphers = tls_getcb_ciphers(session)
        logger.info(f"TLS密码套件: {ciphers}")
        
        logger.info("\n========== 测试 tls_getcb_ja3() ==========")
        ja3 = tls_getcb_ja3(session)
        logger.info(f"JA3指纹: {ja3}")
        
        logger.info("\n========== 测试 tls_getcb_ja3s() ==========")
        ja3s = tls_getcb_ja3s(session)
        logger.info(f"JA3S指纹: {ja3s}")
        
        logger.info("\n========== 测试 tls_getcb_ja4() ==========")
        ja4 = tls_getcb_ja4(session)
        logger.info(f"JA4指纹: {ja4}")
        
    except Exception as e:
        logger.error(f"调用TLS模块函数时出错: {e}")
        logger.error(traceback.format_exc())

def tls_test():
    """测试TLS模块功能"""
    logger.info("\n----- 开始TLS测试 -----")
    
    try:
        # 调用所有TLS函数
        call_all_tls_functions()
        
        # 测试TLS数据包处理
        logger.info("\n----- 测试TLS数据包处理 -----")
        
        # 创建模拟TLS会话
        # 创建模拟IP数据包
        class IPPacket:
            def __init__(self, src, dst):
                self.src = src
                self.dst = dst
        
        # 创建模拟TCP数据包
        class TCPPacket:
            def __init__(self, sport, dport):
                self.sport = sport
                self.dport = dport
        
        # 创建模拟Raw数据包
        class RawPacket:
            def __init__(self, load):
                self.load = load
        
        # 创建模拟数据包
        class PacketMock:
            def __init__(self):
                self.layers = {}
            
            def haslayer(self, layer):
                return layer in self.layers
            
            def __getitem__(self, layer):
                if layer in self.layers:
                    return self.layers[layer]
                raise KeyError(f"Layer {layer} not found")
            
            def summary(self):
                return "TLS测试数据包"
        
        # 创建TLS Client Hello数据包
        client_hello_packet = PacketMock()
        client_hello_packet.layers[IP] = IPPacket("192.168.1.10", "192.168.1.1")
        client_hello_packet.layers[TCP] = TCPPacket(49152, 443)
        client_hello_packet.layers[Raw] = RawPacket(bytes.fromhex(
            "16030100c1010000bd03033d852b477bfb08f8c2e51128dc2956a393a66a03"
            "5734a946b79c5942182f5b31001c0a0a130113021303c02bc02fc02cc030cc"
            "a9cca8c009c013c00ac014009c009d002f003500ff010001780000001a0018"
            "00000f6578616d706c652e626c6f672e636f6d000b000403000102000a000c"
            "000a001d0017001e00190018001000130011001200300016001500170018000b"
            "00020100002300000010000e000c02683208687474702f312e310005000501"
            "00000000000d001a001804030804040105030805050108060601020603020802"
            "0801002b0009080304030303020301002d00020101001c00024001"
        ))
        
        # 清空统计计数器
        global tls_packets_count, tls_client_hello_count, tls_server_hello_count
        global tls_versions, tls_cipher_suites, tls_ja3_fingerprints
        tls_packets_count = 0
        tls_client_hello_count = 0
        tls_server_hello_count = 0
        tls_versions = set()
        tls_cipher_suites = set()
        tls_ja3_fingerprints = set()
        
        # 处理Client Hello数据包
        logger.info("\n----- 测试处理TLS Client Hello数据包 -----")
        process_tls_packet(client_hello_packet)
        
        # 创建TLS Server Hello数据包
        server_hello_packet = PacketMock()
        server_hello_packet.layers[IP] = IPPacket("192.168.1.1", "192.168.1.10")
        server_hello_packet.layers[TCP] = TCPPacket(443, 49152)
        server_hello_packet.layers[Raw] = RawPacket(bytes.fromhex(
            "1603030046020000420303f0e71a9144caf7903ba23a7ff6683e3740e78ac"
            "36e9cb564a1cab3e372255b83d65f301a8c9c59da7a94d23b8b4db6cca96e"
            "b0c751a68a27430a13010000"
        ))
        
        # 处理Server Hello数据包
        logger.info("\n----- 测试处理TLS Server Hello数据包 -----")
        process_tls_packet(server_hello_packet)
        
        # 显示统计信息
        logger.info("\n----- TLS测试统计 -----")
        logger.info(f"TLS数据包: {tls_packets_count}")
        logger.info(f"TLS Client Hello: {tls_client_hello_count}")
        logger.info(f"TLS Server Hello: {tls_server_hello_count}")
        logger.info(f"TLS协议版本: {tls_versions}")
        logger.info(f"TLS密码套件: {tls_cipher_suites}")
        logger.info(f"TLS JA3指纹: {tls_ja3_fingerprints}")
        
    except Exception as e:
        logger.error(f"TLS测试出错: {e}")
        logger.error(traceback.format_exc())
    
    logger.info("\n----- TLS测试完成 -----")

class JsonStorageManager:
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
        self.current_file = os.path.join(self.output_dir, f"packet_analysis_{timestamp}.json")
        with open(self.current_file, 'w') as f:
            json.dump([], f)
            
    def append_packet_data(self, packet_data):
        """添加数据包分析结果到JSON文件"""
        if not self.current_file:
            self.create_new_file()
            
        try:
            with open(self.current_file, 'r+') as f:
                data = json.load(f)
                data.append(packet_data)
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()
        except Exception as e:
            logger.error(f"写入JSON文件时出错: {str(e)}")
            
    def get_current_file(self):
        """获取当前JSON文件路径"""
        return self.current_file

# 创建全局JSON存储管理器实例
json_storage = JsonStorageManager()

if __name__ == "__main__":
    try:
        packet_rule_info = PacketParser.Packet()
        main()
    except KeyboardInterrupt:
        logger.info("用户中断程序执行")
        sys.exit(0)
    except Exception as e:
        logger.error(f"主程序出错: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
