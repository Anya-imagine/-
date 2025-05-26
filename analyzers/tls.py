import configparser
import sys
import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

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

from analyzers.BSB import BSB
from analyzers.field import FIELD_FLAG_CNT, FIELD_FLAG_FAKE, field_manager

# Remove these imports to avoid circular dependencies
# try:
#     from .parsers import (
#         parsers_add_named_func,
#         parsers_get_named_func,
#         parsers_classifier_register_tcp
#     )
# except ImportError:
#     from analyzers.parsers import (
#         parsers_add_named_func,
#         parsers_get_named_func,
#         parsers_classifier_register_tcp
#     )

config = configparser.ConfigParser()

host_field = 0
ver_field = 0
cipher_field = 0
ja3_field = 0
ja3s_field = 0
src_id_field = 0
dst_id_field = 0
ja3_str_field = 0
ja3s_str_field = 0
ja4_field = 0
ja4_raw_field = 0

ja4_raw = False


class TLSInfo:
    def __init__(self, buf=None, length=0, which=0):
        self.buf = bytearray(8192) if buf is None else buf  # 默认分配8KB缓冲区
        self.length = length
        self.which = which
        self.data = None
        self.server_version = 0
        self.client_version = 0
        self.type = 0


char_to_hex_str = []

check_sums_256 = []

tls_process_client_hello_func = 0
tls_process_server_hello_func = 0
tls_process_server_certificate_func = 0

def is_alnum(c: int) -> bool:
    return chr(c).isalnum() if 0 <= c <= 0x7F else False

# 检测TLS协议中GREASE值
def tls_is_grease_value(value):
    """
    检测TLS握手报文中的GREASE值
    GREASE (Generate Random Extensions And Sustain Extensibility) 是客户端随机生成的值，
    用于测试服务器对未知扩展的兼容性，这些值不应该被计入协议指纹中
    """
    # 确保输入是整数类型
    if not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return 0

    # 检测低4位是否为0xA
    if ((value & 0x0f) != 0x0a):
        return 0

    # 验证是否为对称字节模式（如0x1A1A）
    if ((value & 0xff) != ((value >> 8) & 0xff)):
        return 0

    return 1


# 将二进制 TLS 版本号转换为人类可读的协议版本字符串
def tls_session_version(session, ver):
    """将TLS版本号转换为可读字符串并更新会话字段"""
    
    # 确保版本号是整数
    if not isinstance(ver, int):
        try:
            if isinstance(ver, bytes):
                # 尝试从字节中提取版本号
                if len(ver) >= 2:
                    ver = (ver[0] << 8) | ver[1]
                else:
                    return  # 无效数据
            else:
                # 尝试将其他类型转换为整数
                ver = int(ver)
        except (TypeError, ValueError):
            return  # 转换失败

    # 版本号映射
    match ver:
        case 0x0002:  # SSLv2
            field_manager.field_str_add(ver_field, session, "SSLv2", 5, True)
        case 0x0003:  # SSLv3
            field_manager.field_str_add(ver_field, session, "SSLv3", 5, True)
        case 0x0301:  # TLSv1.0
            field_manager.field_str_add(ver_field, session, "TLSv1.0", 5, True)
        case 0x0302:  # TLSv1.1
            field_manager.field_str_add(ver_field, session, "TLSv1.1", 7, True)
        case 0x0303:  # TLSv1.2
            field_manager.field_str_add(ver_field, session, "TLSv1.2", 7, True)
        case 0x0304:  # TLSv1.3
            field_manager.field_str_add(ver_field, session, "TLSv1.3", 7, True)
        case x if 0x7f00 <= x <= 0x7fff:  # TLSv1.3 draft版本
            str_val = f"TLSv1.3-draft-{ver & 0xff:02d}"
            field_manager.field_str_add(ver_field, session, str_val, -1, True)
        case _:  # 未知版本
            str_val = f"0x{ver:04x}"
            field_manager.field_str_add(ver_field, session, str_val, 6, True)


# 将TLS协议版本号转换为JA4指纹所需的两位简写形式
def tls_ja4_version(ver, v_str):
    match ver:
        case 0x0002:  # SSLv2
            v_str = bytearray(3)
            v_str[0:3] = b's2\x00'
        case 0x0300:  # SSLv3
            v_str = bytearray(3)
            v_str[0:3] = b's3\x00'
        case 0x0301:  # TLSv1.0
            v_str = bytearray(3)
            v_str[0:3] = b'11\x00'
        case 0x0302:
            v_str = bytearray(3)
            v_str[0:3] = b'12\x00'
        case 0x0303:
            v_str = bytearray(3)
            v_str[0:3] = b'13\x00'
        case _:
            v_str = bytearray(3)
            v_str[0:3] = b'00\x00'


# 解析Server Hello消息的各个部分
def tls_process_server_hello(session: Session, data, length, uw):
    # 安全性检查
    if not isinstance(data, (bytes, bytearray)) or length < 2:
        return -1
        
    try:
        bsb = BSB(data, length)  # 将输入数据包装为可解析的位流

        # 读取TLS协议版本号
        ver = bsb.import_u16()  # 从数据流提取版本号
        if ver is None:  # 添加None检查
            return -1

        # 跳过32字节的随机数
        bsb.skip(32)  

        if bsb.error:
            return -1

        add_12_later = False  # 特殊版本处理标志（用于 TLS 1.3 草案版本的特殊处理）

        # 版本号 0x0303 对应 TLS 1.2，但当出现此版本时：
        # 1. 实际可能使用 TLS 1.3 草案版本
        # 2. 真实版本在扩展字段中指定
        if ver != 0x0303:
            tls_session_version(session, ver)  # 直接记录已知版本
        else:
            add_12_later = True  # 延迟到扩展解析阶段处理真实版本

        # 仅处理 SSLv3 到 TLS 1.2 的协议版本
        if ver >= 0x0300 and ver <= 0x0303:
            # 读取会话ID长度（1字节）
            skip_len = bsb.import_u8()  # Session Id Length
            if skip_len is None:  # 添加None检查
                return -1

            # 当存在有效会话ID时
            if skip_len > 0 and bsb.remaining() > skip_len:
                ptr = bsb.work_ptr()  # 获取会话ID起始指针
                if ptr is None:  # 添加None检查
                    return -1
                    
                session_id = []
                # 将每个字节转换为双字符十六进制表示
                for i in range(skip_len):
                    if i*2+1 < len(session_id):
                        session_id[i * 2] = char_to_hex_str[ptr[i]][0]  # 高位十六进制字符
                        session_id[i * 2 + 1] = char_to_hex_str[ptr[i]][1]  # 低位十六进制字符

                session_id[skip_len * 2] = 0  # 添加字符串终止符
                # 将会话ID存入字段（最大支持256字节原始数据 → 512字符十六进制）
                field_manager.field_str_add(dst_id_field, session, session_id, skip_len * 2, True)

            # 跳过会话ID字段（即使长度为0也要执行）
            bsb.skip(skip_len)

        # 从数据流读取 2 字节的密码套件标识符
        cipher = bsb.import_u16()

        # 解析密码套件
        # 使用二维数组查表（高字节为类型，低字节为算法）
        if cipher is not None:
            cipher_str = f"0x{cipher:04x}"  # 格式化为十六进制
            field_manager.field_str_add(cipher_field, session, cipher_str, len(cipher_str), True)

        # 跳过压缩方法字段（TLS 1.3 草案22之前无压缩）
        if ver is not None and (ver < 0x0700 or ver >= 0x7f16):  # 过滤条件
            bsb.skip(1)  # 跳过 1 字节的压缩方法长度字段

        # 处理扩展字段
        if bsb.remaining() > 2:
            # 读取扩展字段总长度
            etot_len = bsb.import_u16()
            if etot_len is not None:  # 添加None检查
                etot_len = min(etot_len, bsb.remaining())  # 安全截断

                # 处理延迟版本处理（TLS 1.3草案伪装成TLS 1.2的情况）
                if add_12_later:
                    tls_session_version(session, 0x303)  # 标记为TLS 1.2
                
        return 0
    except Exception as e:
        print(f"处理TLS Server Hello错误: {e}")
        return -1


def tls_process_server_handshake_record(session: Session, data, length):
    """处理服务器端TLS握手记录"""
    # 基础数据检查
    if data is None or length < 4:
        return 0
        
    # 使用合适的方式访问字节数据
    if isinstance(data, (bytes, bytearray)):
        # 读取握手消息类型（通常，type=2表示ServerHello）
        msg_type = data[0]
        
        # 计算握手消息的长度（3字节，大端序）
        msg_len = (data[1] << 16) | (data[2] << 8) | data[3]
        
        # 验证长度信息
        if 4 + msg_len > length:
            return 0  # 数据段不完整
            
        # 根据握手消息类型进行处理
        if msg_type == 2:  # ServerHello
            # 调用ServerHello处理函数
            if tls_process_server_hello_func:
                local_call_named_func(tls_process_server_hello_func, session, data[4:], msg_len, None)
            else:
                # 直接使用内置函数
                tls_process_server_hello(session, data[4:], msg_len, None)
            return 0
        elif msg_type == 11:  # Certificate
            # 调用证书处理函数（如果注册了）
            if tls_process_server_certificate_func:
                local_call_named_func(tls_process_server_certificate_func, session, data[4:], msg_len, None)
            return 0
            
    return 0

# 将TLS 指纹生成的核心排序函数
def compare_uint16_t(a,b):
    # 安全检查 - 确保a和b都是可比较类型
    if a is None:
        return -1 if b is not None else 0
    if b is None:
        return 1
    
    # 整数比较
    if isinstance(a, int) and isinstance(b, int):
        return -1 if a < b else (1 if a > b else 0)
    
    # 将对象转换为整数（如果可能）
    try:
        va = int(a) if a is not None else 0
        vb = int(b) if b is not None else 0
        return -1 if va < vb else (1 if va > vb else 0)
    except (TypeError, ValueError):
        # 如果无法比较，将None视为小于非None
        if a is None:
            return -1
        if b is None:
            return 1
        # 如果都不是None但无法比较，使用默认字符串比较
        return -1 if str(a) < str(b) else (1 if str(a) > str(b) else 0)

# 将ALPN字符串的首尾字符转换为小写或十六进制简写
def tls_alpn_to_ja4_alpn(alpn, length, ja4_alpn):
    """将ALPN字段转换为JA4格式的ALPN表示"""
    
    # 安全校验输入
    if alpn is None or not isinstance(length, int) or length <= 0 or ja4_alpn is None:
        return 0
        
    try:
        # 处理alpn作为bytes或bytearray的情况
        if isinstance(alpn, (bytes, bytearray)):
            # 计算可用空间
            ja4_length = len(ja4_alpn) if hasattr(ja4_alpn, '__len__') else 2
            if ja4_length <= 0:
                return 0
                
            # 限制输出缓冲区使用
            used_length = 0
            
            # 处理每个ALPN协议
            pos = 0
            while pos < length:
                # 读取协议标识符长度（一字节）
                proto_len = alpn[pos] if pos < length else 0
                pos += 1
                
                # 提取协议标识符（如果可能）
                # 确保pos和proto_len都是整数，并且长度检查正确
                if isinstance(proto_len, int) and isinstance(pos, int) and pos + proto_len <= int(length):
                    # 简化处理，只取首尾字符
                    if proto_len > 0 and isinstance(ja4_alpn, list) and len(ja4_alpn) >= 2:
                        # 取首字符
                        ja4_alpn[0] = chr(alpn[pos])
                        # 取尾字符(如果存在)
                        if proto_len > 1:
                            ja4_alpn[1] = chr(alpn[pos+proto_len-1])
                        else:
                            ja4_alpn[1] = ja4_alpn[0]
                        return 1
                pos += proto_len  # 移动到下一个协议
            
            return 0
    except Exception as e:
        print(f"ALPN转换错误: {e}")
        return 0

# 解析客户端Hello消息，提取关键信息，生成JA3和JA4指纹
def tls_process_client_hello_data(session:Session, data, length, uw):
    """解析客户端Hello消息并提取TLS指纹特征"""
    # 基本安全检查
    if not isinstance(data, (bytes, bytearray)) or length < 7:
        return -1
        
    try:
        # 简化处理，专注于提取关键TLS特征
        pbsb = BSB(data, length)  # 创建数据解析器
        
        # 跳过基本头部(4字节记录层头部 + 2字节版本)
        pbsb.skip(4)
        ver = pbsb.import_u16()
        
        if pbsb.error:
            return -1
            
        # 记录TLS版本
        tls_session_version(session, ver)
        
        # 记录客户端支持的TLS版本
        field_manager.field_str_add(ver_field, session, f"0x{ver:04x}", 6, True)
        
        # 成功解析客户端Hello
        return 0
    except Exception as e:
        print(f"解析TLS客户端Hello错误: {e}")
        return -1

# Helper function to call named functions directly
def local_call_named_func(func_id, session, data, length, uw):
    """调用命名函数的安全包装器"""
    if func_id is None:
        return 0
        
    # 如果func_id已经是函数对象，直接调用
    if callable(func_id):
        try:
            return func_id(session, data, length, uw)
        except Exception as e:
            print(f"调用函数失败: {e}")
            return 0
            
    # 否则尝试从函数字典中获取
    try:
        from analyzers.parsers import named_funcs_hash
        if hasattr(named_funcs_hash, 'get'):
            func = named_funcs_hash.get(func_id)
            if callable(func):
                return func(session, data, length, uw)
    except (ImportError, AttributeError, TypeError) as e:
        print(f"查找命名函数失败: {e}")
    
    return 0

# Helper function to unregister parsers
def local_parsers_unregister(session, uw):
    """安全注销当前解析器"""
    if hasattr(session, 'parser_active'):
        session.parser_active = False

# 验证和处理TLS客户端握手记录，提取有效载荷，并将客户端的Hello消息分发给相应的处理函数
def tls_process_client(session:Session,data,length):
    # 确保数据是bytes对象
    if not isinstance(data, (bytes, bytearray)):
        print("tls_process_client: 期望bytes类型数据")
        return
        
    # 使用BSB对象前进行安全检查
    if length < 5:
        return
        
    # 创建一个内存视图用于高效处理
    ssl_data = data
    
    # 确保至少有完整的TLS记录层头部（5字节）
    if length > 5:  # 包含：1B类型 + 2B版本 + 2B长度
        # 计算有效载荷长度（安全处理不完整数据包）
        ssl_len = min(length - 5, (ssl_data[3] << 8) | ssl_data[4])
        
        # 使用切片处理数据，避免指针算术操作
        payload_data = ssl_data[5:5+ssl_len]
        
        # 调用客户端Hello消息处理器
        if tls_process_client_hello_func and callable(tls_process_client_hello_func):
            local_call_named_func(tls_process_client_hello_func, session, payload_data, ssl_len, None)
        elif hasattr(session, 'tls_process_client_hello'):
            session.tls_process_client_hello(payload_data, ssl_len)

# 确保服务器握手记录被完整捕获和处理
def tls_parser(session:Session,uw,data,remaining,which):
    if not session.parser_active:
        return 0
        
    if uw is None:
        return 0
    
    tls = uw
    
    # 确保TLS对象有必要的属性
    if not hasattr(tls, 'buf') or not hasattr(tls, 'length'):
        return 0
    
    # 安全地复制数据到TLS缓冲区
    if data is None or remaining <= 0:
        return 0
        
    # 处理字节数组或字节对象
    if isinstance(data, (bytes, bytearray)):
        copy_length = min(remaining, len(tls.buf) - tls.length)
        if copy_length <= 0:
            return 0
            
        # 安全地复制数据
        tls.buf[tls.length:tls.length + copy_length] = data[:copy_length]
        tls.length += copy_length

        # 基础协议头验证（至少需要5字节头）
        if tls.length < 5:
            return 0

        # 协议类型过滤（0x16=握手协议）
        if tls.buf[0] != 0x16:
            tls.length = 0 # 重置缓冲区
            local_parsers_unregister(session,uw) # 注销当前解析器
            return 0

        # 计算完整记录长度（头部的长度字段 + 5字节头）
        record_length = (tls.buf[3] << 8 | tls.buf[4]) + 5
        if record_length > tls.length:
            return 0

        # 服务器握手记录处理（跳过5字节头）
        if tls_process_server_handshake_record(session, tls.buf[5:5+record_length-5], record_length - 5):
            tls.length = 0 # 重置缓冲区
            local_parsers_unregister(session,uw) # 注销当前解析器
            return 0

        # 缓冲区滑动处理
        tls.length -= record_length
        if tls.length > 0:
            # 使用切片正确移动剩余数据
            tls.buf[:tls.length] = tls.buf[record_length:record_length + tls.length]

    return 0

# 会话持久化处理函数
def tls_save(session:Session,uw,final):
    # 确保uw不为None
    if uw is None:
        return
    
    tls = uw # 获取TLS解析上下文
    
    # 确保TLS对象有必要的属性
    if not hasattr(tls, 'buf') or not hasattr(tls, 'length'):
        return

    # 处理条件：缓冲区有未处理的完整记录（>5字节）且协议类型为握手协议（0x16）
    if tls.length > 5 and len(tls.buf) > 0 and tls.buf[0] == 0x16:
        # 调用服务器握手记录处理器（跳过5字节的协议头）
        tls_process_server_handshake_record(session, tls.buf[5:5+tls.length-5], tls.length - 5)
        # 重置缓冲区长度（确保后续处理从干净状态开始）
        tls.length = 0

# 流量分类函数
def tls_classify(session:Session,data,length,which,uw):
    # 基础协议过滤（至少需要6字节且版本号 <= 0x03）
    if length < 6 or data[2] > 0x03:
        return

    # 避免重复处理已识别的 TLS 会话
    if session.has_protocol("tls"):
        return

    # 协议特征验证：
    # *[0] = 0x16(握手协议类型)
    # *[1 - 2] = 版本号(例如0x0303 表示 TLS1.2)
    # *[5] = 消息类型(1 = ClientHello, 2 = ServerHello)

    if data[2] <= 0x03 and (data[5] == 1 or data[5] == 2):
        # 记录会话协议为TLS
        session.add_protocol("tls")

        # 初始化 TLS 解析上下文
        tls = TLSInfo()
        tls.length = 0 # 初始化缓冲区长度

        # 注册后续解析器（tls_parser）到会话系统
        from analyzers.parsers import parsers_register
        parsers_register(session, tls_parser, tls, tls_save)

        # 处理客户端/服务端 Hello 消息
        if data[5] == 1: # Client hello
            tls_process_client(session,data,length) # 解析客户端特征
            tls.which = (which + 1) % 2 # 切换流量方向
        else: # Server hello
            tls.which = which # 保持流量方向不变

def parser_init():
    global host_field, ver_field, cipher_field, ja3_field, ja3s_field
    global dst_id_field, src_id_field, ja3_str_field, ja4_field, ja4_raw_field
    global tls_process_client_hello_func, tls_process_server_hello_func, tls_process_server_certificate_func
    
    # Import parsers module directly
    import analyzers.parsers as parsers_module
    API_VERSION = parsers_module.API_VERSION

    # Define TLS host field directly instead of referencing HTTP one
    host_field = field_manager.field_define("tls", "lotermfield",
                                          "host.tls", "Hostname", "tls.host",
                                          "TLS Server Name Indication (SNI)",
                                          FieldType.FIELD_TYPE_STR_HASH,
                                          FIELD_FLAG_CNT,
                                          None)

    # Define TLS version field (e.g., TLS 1.2)
    ver_field = field_manager.field_define("tls", "termfield",
                                    "tls.version", "Version", "tls.version",
                                    "SSL/TLS version field",
                                    FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                    None)

    # Define cipher suite field (e.g., AES128-GCM-SHA256)
    cipher_field = field_manager.field_define("tls", "uptermfield",
                                       "tls.cipher", "Cipher", "tls.cipher",
                                       "SSL/TLS cipher field",
                                       FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                       None)

    # JA3 client fingerprint field
    ja3_field = field_manager.field_define("tls", "lotermfield",
                                    "tls.ja3", "JA3", "tls.ja3",
                                    "SSL/TLS JA3 field",
                                    FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                    None)

    # JA4 new version fingerprint field
    ja4_field = field_manager.field_define("tls", "lotermfield",
                                    "tls.ja4", "JA4", "tls.ja4",
                                    "SSL/TLS JA4 field",
                                    FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                    None)

    # JA4 raw data field
    ja4_raw_field = field_manager.field_define("tls", "lotermfield",
                                       "tls.ja4_r", "JA4_r", "tls.ja4_r",
                                       "SSL/TLS JA4_r field",
                                       FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                       None)

    # JA3S server fingerprint field
    ja3s_field = field_manager.field_define("tls", "lotermfield",
                                     "tls.ja3s", "JA3S", "tls.ja3s",
                                     "SSL/TLS JA3S field",
                                     FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                     None)

    # Destination session ID field (server)
    dst_id_field = field_manager.field_define("tls", "lotermfield",
                                      "tls.sessionid.dst", "Dst Session Id", "tls.dstSessionId",
                                      "SSL/TLS Dst Session Id",
                                      FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                      None)

    # Source session ID field (client)
    src_id_field = field_manager.field_define("tls", "lotermfield",
                                      "tls.sessionid.src", "Src Session Id", "tls.srcSessionId",
                                      "SSL/TLS Src Session Id",
                                      FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                      None)

    # Virtual field: merge source/destination session ID queries
    field_manager.field_define("general", "lotermfield",
                         "tls.sessionid", "Src or Dst Session Id", "tlsidall",
                         "Shorthand for tls.sessionid.src or tls.sessionid.dst",
                         0, FIELD_FLAG_FAKE,
                         None)

    # Check if JA3 strings should be saved
    ja3_str = config.getboolean("tls", "ja3Strings", fallback=False)
    if ja3_str:
        ja3_str_field = field_manager.field_define("tls", "lotermfield",
                                            "tls.ja3sstring", "JA3SSTR", "tls.ja3sstring",
                                            "SSL/TLS JA3S String field",
                                            FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT, None)

        ja3_str_field = field_manager.field_define("tls", "lotermfield",
                                           "tls.ja3string", "JA3STR", "tls.ja3string",
                                           "SSL/TLS JA3 String field",
                                           FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                           None)
    
    # Register TLS classifier
    parsers_module.parsers_classifier_register_tcp("tls", None, 0, "\\x16\\x03", 2, tls_classify, 0, API_VERSION)

    # Fix: Get packet_threads as an integer (not an iterable)
    packet_threads_count = int(config.get("tls", "packetThreads", fallback="0"))
    
    # Fix: Create the proper number of items in check_sums_256
    import hashlib
    for i in range(packet_threads_count):
        check_sums_256.append(hashlib.sha256())  # Create a SHA256 object for each thread

    # Define our own simplified version of these functions to avoid circular imports
    def local_add_named_func(name, func):
        # Just store the mapping between name and function
        if not hasattr(parsers_module, 'named_funcs_hash'):
            parsers_module.named_funcs_hash = {}
        if name not in parsers_module.named_funcs_hash:
            parsers_module.named_funcs_hash[name] = func
        return 1  # Return a dummy ID

    def local_get_named_func(name):
        # Just retrieve the function from the mapping
        if not hasattr(parsers_module, 'named_funcs_hash'):
            parsers_module.named_funcs_hash = {}
        return parsers_module.named_funcs_hash.get(name, None)

    # Use our local functions
    tls_process_client_hello_func = local_add_named_func("tls_process_client_hello", tls_process_client_hello_data)
    tls_process_server_hello_func = local_add_named_func("tls_process_server_hello", tls_process_server_hello)
    tls_process_server_certificate_func = local_get_named_func("tls_process_server_certificate")