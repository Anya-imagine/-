import configparser
import sys
import os
import logging
import socket
import functools
import time
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Tuple
from enum import Enum, IntEnum

try:
    from .imports import (
        FieldType,
        Session
    )
except ImportError:
    from analyzers.imports import (
        FieldType,
        Session
    )

from _socket import IPPROTO_ICMP, IPPROTO_ICMPV6

from analyzers import packet
from analyzers.field import field_manager
from analyzers.packet import PacketBatch, Packet, PacketReturnCode, packet_set_ip_callback
from analyzers.protocol import magic_protocol_register
from analyzers.session import Session,SessionTypes
from .field import FieldManager, FieldType
from .singleton import field_manager
from .constants import FIELD_FLAG_CNT, FIELD_FLAG_IPPRE

config = configparser.ConfigParser()

icmp_magic_protocol = 0
icmpv6_magic_protocol = 0
icmp_type_field = 0
icmp_code_field = 0

# 配置日志
logging.basicConfig(level=logging.INFO)
icmp_logger = logging.getLogger("ICMP_MODULE")

# ICMP类型和代码常量定义
class IcmpType(IntEnum):
    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    SOURCE_QUENCH = 4
    REDIRECT = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14
    INFO_REQUEST = 15
    INFO_REPLY = 16
    ADDRESS_MASK_REQUEST = 17
    ADDRESS_MASK_REPLY = 18

    @classmethod
    def to_str(cls, type_value: int) -> str:
        """将ICMP类型值转换为可读字符串"""
        try:
            return cls(type_value).name
        except ValueError:
            return f"UNKNOWN({type_value})"

# ICMP不可达代码
class DestUnreachableCode(IntEnum):
    NET_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    DESTINATION_NETWORK_UNKNOWN = 6
    DESTINATION_HOST_UNKNOWN = 7
    SOURCE_HOST_ISOLATED = 8
    DESTINATION_NETWORK_ADMINISTRATIVELY_PROHIBITED = 9
    DESTINATION_HOST_ADMINISTRATIVELY_PROHIBITED = 10
    NETWORK_UNREACHABLE_FOR_TOS = 11
    HOST_UNREACHABLE_FOR_TOS = 12
    COMMUNICATION_ADMINISTRATIVELY_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF_IN_EFFECT = 15

    @classmethod
    def to_str(cls, code_value: int) -> str:
        """将ICMP不可达代码值转换为可读字符串"""
        try:
            return cls(code_value).name
        except ValueError:
            return f"UNKNOWN({code_value})"

# 时间超时代码
class TimeExceededCode(IntEnum):
    TTL_EXCEEDED = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1

    @classmethod
    def to_str(cls, code_value: int) -> str:
        """将时间超时代码值转换为可读字符串"""
        try:
            return cls(code_value).name
        except ValueError:
            return f"UNKNOWN({code_value})"

# ICMP信息类，存储解析过程中的数据
class IcmpInfo:
    def __init__(self):
        self.session = None
        self.type = 0
        self.code = 0
        self.checksum = 0
        self.identifier = 0
        self.sequence = 0
        self.original_timestamp = 0
        self.receive_timestamp = 0
        self.transmit_timestamp = 0
        self.gateway_address = None
        self.original_datagram = None
        self.redirect_type = 0

# 全局字段ID
type_field = 0
code_field = 0
identifier_field = 0
sequence_field = 0
unreachable_field = 0
redirect_field = 0
ttl_field = 0

# 函数调用跟踪装饰器
def track_icmp_calls(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # 打印详细的函数调用信息
        arg_str = ""
        if len(args) > 0:
            # 限制参数打印长度，避免输出过长
            arg_str = ", ".join([str(type(a)) + (f"={str(a)[:50]}" if len(str(a)) < 50 else "=<...>") for a in args])
        
        icmp_logger.info(f"⚡ 调用ICMP函数: {func.__name__}({arg_str})")
        
        # 如果有Session参数，打印其信息
        for arg in args:
            if hasattr(arg, 'protocols') and isinstance(arg.protocols, list):
                icmp_logger.info(f"  - 会话协议: {arg.protocols}")
            elif hasattr(arg, 'fields') and isinstance(arg.fields, dict):
                field_names = list(arg.fields.keys())
                icmp_logger.info(f"  - 会话字段: {field_names}")
        
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        # 记录函数执行时间
        icmp_logger.info(f"  - 耗时: {(end_time - start_time)*1000:.2f}ms")
        
        # 根据返回值类型提供不同的输出
        if result is not None:
            result_type = type(result).__name__
            if isinstance(result, (int, float, bool, str)):
                icmp_logger.info(f"  - 返回值 ({result_type}): {result}")
            elif hasattr(result, '__len__'):
                icmp_logger.info(f"  - 返回值 ({result_type}): 长度={len(result)}")
            else:
                icmp_logger.info(f"  - 返回值类型: {result_type}")
        
        return result
    return wrapper

# ICMP解析器初始化函数
@track_icmp_calls
def parser_init():
    """初始化ICMP解析器并注册字段"""
    global type_field, code_field, identifier_field, sequence_field
    global unreachable_field, redirect_field, ttl_field
    
    # 不使用field_manager，改为直接返回
    icmp_logger.info("初始化ICMP解析器")
    
    # 将字段ID设置为占位符值
    type_field = 1
    code_field = 2
    identifier_field = 3
    sequence_field = 4
    unreachable_field = 5
    redirect_field = 6
    ttl_field = 7
    
    return 0

# ICMP协议分类函数
@track_icmp_calls
def icmp_classify(session: Session, data: bytearray, length: int, metadata: dict) -> int:
    """对ICMP数据包进行分类"""
    if length < 8:  # ICMP头至少8字节
        return 0
    
    # 已经标记为ICMP，无需重复处理
    if hasattr(session, 'protocols') and session.has_protocol('icmp'):
        return 0
    
    # 标记为ICMP协议
    if hasattr(session, 'protocols'):
        session.add_protocol('icmp')
    else:
        session.protocols = ['icmp']  # 如果protocols属性不存在，则创建它
    
    # 创建ICMP信息对象
    info = IcmpInfo()
    info.session = session
    
    # 解析ICMP头
    icmp_type = data[0]
    icmp_code = data[1]
    
    # 存储到会话
    if not hasattr(session, 'fields'):
        session.fields = {}
    
    if 'icmpField' not in session.fields:
        session.fields['icmpField'] = {}
    
    session.fields['icmpField']['type'] = icmp_type
    session.fields['icmpField']['code'] = icmp_code
    
    # 注册解析器
    from .parsers import parsers_register
    parsers_register(session, icmp_parser, info, icmp_save)
    
    return 1

# ICMP解析函数
@track_icmp_calls
def icmp_parser(session: Session, uw: IcmpInfo, data: bytearray, length: int, which: int) -> int:
    """解析ICMP数据包内容"""
    if length < 8:  # ICMP头至少8字节
        return 0
    
    info = uw  # 用户数据就是IcmpInfo对象
    
    # 解析ICMP头部
    icmp_type = data[0]
    icmp_code = data[1]
    checksum = (data[2] << 8) | data[3]
    
    # 保存到信息对象
    info.type = icmp_type
    info.code = icmp_code
    info.checksum = checksum
    
    # 保存到会话字段
    # 直接使用session.fields存储而不是field_manager
    if 'icmpField' not in session.fields:
        session.fields['icmpField'] = {}
    
    session.fields['icmpField']['type_str'] = IcmpType.to_str(icmp_type)
    session.fields['icmpField']['code'] = icmp_code
    
    # 根据ICMP类型处理不同数据
    if icmp_type == IcmpType.ECHO_REQUEST or icmp_type == IcmpType.ECHO_REPLY:
        # Echo请求/响应处理
        if length >= 8:
            identifier = (data[4] << 8) | data[5]
            sequence = (data[6] << 8) | data[7]
            
            info.identifier = identifier
            info.sequence = sequence
            
            session.fields['icmpField']['identifier'] = identifier
            session.fields['icmpField']['sequence'] = sequence
            
            icmp_logger.info(f"ICMP {IcmpType.to_str(icmp_type)}: id={identifier}, seq={sequence}")
    
    elif icmp_type == IcmpType.DEST_UNREACHABLE:
        # 目的不可达处理
        if length >= 8:
            unreachable_reason = DestUnreachableCode.to_str(icmp_code)
            session.fields['icmpField']['unreachable_reason'] = unreachable_reason
            icmp_logger.info(f"ICMP不可达: {unreachable_reason}")
    
    elif icmp_type == IcmpType.TIME_EXCEEDED:
        # 超时处理
        if length >= 8:
            time_exceeded_type = TimeExceededCode.to_str(icmp_code)
            session.fields['icmpField']['time_exceeded_type'] = time_exceeded_type
            icmp_logger.info(f"ICMP超时: {time_exceeded_type}")
    
    elif icmp_type == IcmpType.REDIRECT:
        # 重定向处理
        if length >= 12:
            # 提取网关地址 (4字节IPv4地址)
            gateway = f"{data[8]}.{data[9]}.{data[10]}.{data[11]}"
            info.gateway_address = gateway
            
            # 添加重定向类型
            redirect_types = ["网络重定向", "主机重定向", "服务类型及网络重定向", "服务类型及主机重定向"]
            if 0 <= icmp_code < len(redirect_types):
                redirect_type = redirect_types[icmp_code]
                session.fields['icmpField']['redirect_type'] = redirect_type
                icmp_logger.info(f"ICMP重定向: {redirect_type}, 网关: {gateway}")
    
    return 0

# ICMP会话保存函数
@track_icmp_calls
def icmp_save(session: Session, uw: IcmpInfo, final: bool) -> None:
    """保存ICMP会话信息"""
    if not final:
        return
    
    info = uw
    
    # 更新类型统计信息
    if 'icmpStats' not in session.fields:
        session.fields['icmpStats'] = {'types': {}, 'counts': 0}
    
    type_str = IcmpType.to_str(info.type)
    if type_str in session.fields['icmpStats']['types']:
        session.fields['icmpStats']['types'][type_str] += 1
    else:
        session.fields['icmpStats']['types'][type_str] = 1
    
    session.fields['icmpStats']['counts'] += 1
    
    icmp_logger.info(f"ICMP会话统计: 类型={type_str}, 代码={info.code}, 总计={session.fields['icmpStats']['counts']}")

# ICMP类型获取函数
@track_icmp_calls
def icmp_getcb_type(session: Session) -> set:
    """获取会话中的ICMP类型"""
    result = set()
    
    if 'icmpField' in session.fields and 'type' in session.fields['icmpField']:
        icmp_type = session.fields['icmpField']['type']
        result.add(IcmpType.to_str(icmp_type))
    
    return result

# ICMP代码获取函数 
@track_icmp_calls
def icmp_getcb_code(session: Session) -> set:
    """获取会话中的ICMP代码"""
    result = set()
    
    if 'icmpField' in session.fields and 'code' in session.fields['icmpField']:
        icmp_code = session.fields['icmpField']['code']
        result.add(str(icmp_code))
    
    return result


def icmp_packet_enqueue(batch: PacketBatch, packet: Packet, data, length) -> PacketReturnCode:
    """处理ICMP数据包入队"""
    try:
        # 创建会话ID
        session_id = bytearray(16)  # 创建足够大的缓冲区
        
        # 安全检查
        if not hasattr(packet, 'ip_offset') or packet.ip_offset < 0:
            return PacketReturnCode.PACKET_CORRUPT
            
        # 检查数据是否为None或长度不足
        if data is None or len(data) < packet.ip_offset + 20:
            return PacketReturnCode.PACKET_CORRUPT
            
        # 根据是否是IPv6处理不同的会话创建
        if hasattr(packet, 'v6') and packet.v6:
            # IPv6处理
            if len(data) < packet.ip_offset + 40:  # IPv6头至少40字节
                return PacketReturnCode.PACKET_CORRUPT
                
            # 提取源地址和目标地址
            src_addr = data[packet.ip_offset+8:packet.ip_offset+24]
            dst_addr = data[packet.ip_offset+24:packet.ip_offset+40]
            
            # 使用session_id6创建会话ID
            if hasattr(Session, 'session_id6'):
                # 注意: 这里简化调用，实际上可能需要根据Session类的具体实现调整
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id6(session_id, src_addr, 0, dst_addr, 0, vlan, vni)
        else:
            # IPv4处理
            if len(data) < packet.ip_offset + 20:  # IPv4头至少20字节
                return PacketReturnCode.PACKET_CORRUPT
                
            # 提取源地址和目标地址
            src_addr = data[packet.ip_offset+12:packet.ip_offset+16]
            dst_addr = data[packet.ip_offset+16:packet.ip_offset+20]
            
            # 使用session_id4创建会话ID
            if hasattr(Session, 'session_id4'):
                # 注意: 这里简化调用，实际上可能需要根据Session类的具体实现调整
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id4(session_id, src_addr, 0, dst_addr, 0, vlan, vni)
        
        # 设置数据包的协议类型和哈希值
        if hasattr(packet, 'magic_protocol'):
            packet.magic_protocol = icmp_magic_protocol
        
        if hasattr(packet, 'hash') and hasattr(Session, 'session_hash'):
            packet.hash = Session.session_hash(session_id)
            
        return PacketReturnCode.PACKET_DO_PROCESS
    except Exception as e:
        # 出现异常时安全返回
        print(f"ICMP入队处理异常: {e}")
        return PacketReturnCode.PACKET_CORRUPT


def icmpv6_packet_enqueue(batch: PacketBatch, packet: Packet, data, length) -> PacketReturnCode:
    """处理ICMPv6数据包入队"""
    try:
        # 创建会话ID
        session_id = bytearray(16)  # 创建足够大的缓冲区
        
        # 安全检查
        if not hasattr(packet, 'ip_offset') or packet.ip_offset < 0:
            return PacketReturnCode.PACKET_CORRUPT
            
        # 检查数据是否为None或长度不足，IPv6头至少40字节
        if data is None or len(data) < packet.ip_offset + 40:
            return PacketReturnCode.PACKET_CORRUPT
            
        # 验证这是一个IPv6包
        if hasattr(packet, 'v6') and not packet.v6:
            return PacketReturnCode.PACKET_CORRUPT
            
        # 提取源地址和目标地址
        src_addr = data[packet.ip_offset+8:packet.ip_offset+24]
        dst_addr = data[packet.ip_offset+24:packet.ip_offset+40]
        
        # 使用session_id6创建会话ID
        if hasattr(Session, 'session_id6'):
            # 注意: 这里简化调用，实际上可能需要根据Session类的具体实现调整
            vlan = packet.vlan if hasattr(packet, 'vlan') else 0
            vni = packet.vni if hasattr(packet, 'vni') else 0
            Session.session_id6(session_id, src_addr, 0, dst_addr, 0, vlan, vni)
        
        # 设置数据包的协议类型和哈希值
        if hasattr(packet, 'magic_protocol'):
            packet.magic_protocol = icmpv6_magic_protocol
        
        if hasattr(packet, 'hash') and hasattr(Session, 'session_hash'):
            packet.hash = Session.session_hash(session_id)
            
        return PacketReturnCode.PACKET_DO_PROCESS
    except Exception as e:
        # 出现异常时安全返回
        print(f"ICMPv6入队处理异常: {e}")
        return PacketReturnCode.PACKET_CORRUPT


def icmp_create_session_id(session_id, packet):
    """创建ICMP会话ID"""
    try:
        # 安全检查
        if packet is None or not hasattr(packet, 'ip_offset'):
            return
            
        # 获取数据包内容
        data = None
        if hasattr(packet, 'pkt'):
            data = packet.pkt
        elif hasattr(packet, 'packet'):
            data = packet.packet
        
        if data is None or packet.ip_offset >= len(data):
            return
            
        # 从IP头开始解析
        data = data[packet.ip_offset:]
        if len(data) < 1:
            return
            
        # 解析IP版本
        ip_version = (data[0] >> 4) & 0x0f
        
        # IPv4处理
        if ip_version == 4:
            if len(data) < 20:  # IPv4头至少20字节
                return
                
            # 提取源地址和目标地址
            src_addr = data[12:16]
            dst_addr = data[16:20]
            
            # 使用IPv4会话ID创建函数
            if hasattr(Session, 'session_id4'):
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id4(session_id, src_addr, 0, dst_addr, 0, vlan, vni)
                
        # IPv6处理
        elif ip_version == 6:
            if len(data) < 40:  # IPv6头至少40字节
                return
                
            # 提取源地址和目标地址
            src_addr = data[8:24]
            dst_addr = data[24:40]
            
            # 使用IPv6会话ID创建函数
            if hasattr(Session, 'session_id6'):
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id6(session_id, src_addr, 0, dst_addr, 0, vlan, vni)
    except Exception as e:
        print(f"创建ICMP会话ID异常: {e}")


def icmp_pre_process(session, packet, is_new_session=True):
    """ICMP数据包预处理"""
    try:
        # 安全检查
        if session is None or packet is None:
            return -1
            
        # 获取数据包内容
        data = None
        if hasattr(packet, 'packet'):
            data = packet.packet
        elif hasattr(packet, 'pkt'):
            data = packet.pkt
            
        if data is None or not hasattr(packet, 'ip_offset') or packet.ip_offset >= len(data):
            return -1
        
        # 从IP头开始解析
        ip_data = data[packet.ip_offset:]
        if len(ip_data) < 1:
            return -1
            
        # 解析IP版本
        ip_version = (ip_data[0] >> 4) & 0x0f
        
        # 根据IP版本处理
        if ip_version == 4:
            if len(ip_data) < 20:  # IPv4头至少20字节
                return -1
                
            # 提取源地址和目标地址
            ipv4_src = ip_data[12:16]
            ipv4_dst = ip_data[16:20]
            
            # 对于新会话，添加协议标签
            if is_new_session:
                if hasattr(session, 'add_protocol'):
                    session.add_protocol("icmp")
            
            # 确定数据包方向
            dir = False
            if hasattr(session, 'addr1') and hasattr(session, 'addr2'):
                # 假设可能使用IPv6地址存储格式
                if len(session.addr1) >= 16 and len(session.addr2) >= 16:
                    # 比较地址的最后4个字节（IPv4地址）
                    dir = (session.addr1[-4:] == ipv4_src and session.addr2[-4:] == ipv4_dst)
            
            # 设置数据包方向
            if hasattr(packet, 'direction'):
                packet.direction = 0 if dir else 1
                
            # 更新会话数据字节计数
            if hasattr(session, 'databytes') and hasattr(packet, 'packet_len') and hasattr(packet, 'payload_offset'):
                session.databytes[packet.direction] += packet.packet_len - packet.payload_offset
                
        elif ip_version == 6:
            if len(ip_data) < 40:  # IPv6头至少40字节
                return -1
                
            # 提取源地址和目标地址
            ipv6_src = ip_data[8:24]
            ipv6_dst = ip_data[24:40]
            
            # 对于新会话，添加协议标签
            if is_new_session:
                if hasattr(session, 'add_protocol'):
                    session.add_protocol("icmp")
            
            # 确定数据包方向
            dir = False
            if hasattr(session, 'addr1') and hasattr(session, 'addr2'):
                if len(session.addr1) >= 16 and len(session.addr2) >= 16:
                    dir = (session.addr1 == ipv6_src and session.addr2 == ipv6_dst)
            
            # 设置数据包方向
            if hasattr(packet, 'direction'):
                packet.direction = 0 if dir else 1
                
            # 更新会话数据字节计数
            if hasattr(session, 'databytes') and hasattr(packet, 'packet_len') and hasattr(packet, 'payload_offset'):
                session.databytes[packet.direction] += packet.packet_len - packet.payload_offset
        
        return 0
    except Exception as e:
        print(f"ICMP预处理异常: {e}")
        return -1


def icmp_process(session, packet):
    """处理ICMP数据包"""
    try:
        # 安全检查
        if session is None or packet is None:
            return 0
            
        # 获取数据包内容
        data = None
        if hasattr(packet, 'packet'):
            data = packet.packet
        elif hasattr(packet, 'pkt'):
            data = packet.pkt
            
        if data is None or not hasattr(packet, 'ip_offset'):
            return 0
            
        # 获取ICMP头部位置
        if hasattr(packet, 'payload_offset') and packet.payload_offset > 0:
            icmp_offset = packet.payload_offset
        else:
            # 对于IPv4，ICMP头部紧跟在IP头之后
            if (data[packet.ip_offset] >> 4) & 0x0f == 4:
                ip_header_len = (data[packet.ip_offset] & 0x0f) * 4
                icmp_offset = packet.ip_offset + ip_header_len
            # 对于IPv6，ICMP头部在IPv6头(40字节)之后
            else:
                icmp_offset = packet.ip_offset + 40
        
        # 确保有足够数据读取ICMP类型和代码
        if icmp_offset + 2 > len(data):
            return 0
            
        # 提取ICMP类型和代码
        icmp_type = data[icmp_offset]
        icmp_code = data[icmp_offset + 1]
        
        # 更新会话的ICMP信息
        if hasattr(session, 'icmp_info'):
            if len(session.icmp_info) >= 2 and session.icmp_info[0] == 0 and session.icmp_info[1] == 0:
                session.icmp_info[0] = icmp_type
                session.icmp_info[1] = icmp_code
        
        # 将ICMP类型和代码添加到字段中
        field_manager.field_int_add(icmp_type_field, session, icmp_type)
        field_manager.field_int_add(icmp_code_field, session, icmp_code)
        
        return 1
    except Exception as e:
        print(f"ICMP处理异常: {e}")
        return 0


def icmpv6_create_session_id(session_id, packet):
    """创建ICMPv6会话ID"""
    try:
        # 安全检查
        if packet is None or not hasattr(packet, 'ip_offset'):
            return
            
        # 获取数据包内容
        data = None
        if hasattr(packet, 'packet'):
            data = packet.packet
        elif hasattr(packet, 'pkt'):
            data = packet.pkt
        
        if data is None or packet.ip_offset + 40 > len(data):
            return
            
        # 提取源地址和目标地址
        ipv6_src = data[packet.ip_offset+8:packet.ip_offset+24]
        ipv6_dst = data[packet.ip_offset+24:packet.ip_offset+40]
        
        # 使用session_id6创建会话ID
        if hasattr(Session, 'session_id6'):
            vlan = packet.vlan if hasattr(packet, 'vlan') else 0
            vni = packet.vni if hasattr(packet, 'vni') else 0
            Session.session_id6(session_id, ipv6_src, 0, ipv6_dst, 0, vlan, vni)
    except Exception as e:
        print(f"创建ICMPv6会话ID异常: {e}")


def icmpv6_pre_process(session, packet, is_new_session=True):
    """ICMPv6数据包预处理"""
    try:
        # 安全检查
        if session is None or packet is None:
            return -1
            
        # 获取数据包内容
        data = None
        if hasattr(packet, 'packet'):
            data = packet.packet
        elif hasattr(packet, 'pkt'):
            data = packet.pkt
            
        if data is None or not hasattr(packet, 'ip_offset') or packet.ip_offset + 40 > len(data):
            return -1
        
        # 提取源地址和目标地址
        ipv6_src = data[packet.ip_offset+8:packet.ip_offset+24]
        ipv6_dst = data[packet.ip_offset+24:packet.ip_offset+40]
        
        # 对于新会话，添加协议标签
        if is_new_session:
            if hasattr(session, 'add_protocol'):
                session.add_protocol("icmp")
        
        # 确定数据包方向
        dir = False
        if hasattr(session, 'addr1') and hasattr(session, 'addr2'):
            dir = (session.addr1 == ipv6_src and session.addr2 == ipv6_dst)
        
        # 设置数据包方向
        if hasattr(packet, 'direction'):
            packet.direction = 0 if dir else 1
            
        # 更新会话数据字节计数
        if hasattr(session, 'databytes') and hasattr(packet, 'packet_len') and hasattr(packet, 'payload_offset'):
            direction = 0 if dir else 1
            session.databytes[direction] += packet.packet_len - packet.payload_offset
        
        return 0
    except Exception as e:
        print(f"ICMPv6预处理异常: {e}")
        return -1

