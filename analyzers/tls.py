import configparser
import sys
import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
import binascii

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
def tls_session_version(session, version):
    """设置 TLS 版本号"""
    try:
        # 确保版本号是整数
        if isinstance(version, (bytes, bytearray)):
            version = int.from_bytes(version, byteorder='big')
        elif isinstance(version, str):
            version = int(version, 16)
        elif not isinstance(version, int):
            version = int(version)
            
        print(f"DEBUG: Setting TLS version: {version:04x}")
        
        # 映射版本号到可读字符串
        version_str = None
        if version == 0x0300:
            version_str = "SSLv3"
        elif version == 0x0301:
            version_str = "TLSv1.0"
        elif version == 0x0302:
            version_str = "TLSv1.1"
        elif version == 0x0303:
            version_str = "TLSv1.2"
        elif version == 0x0304:
            version_str = "TLSv1.3"
            
        if version_str:
            print(f"DEBUG: Mapped version {version:04x} to {version_str}")
            field_manager.field_str_add("tls.version", version_str, session)
            print(f"DEBUG: Session fields after setting version: {session.fields}")
        else:
            print(f"DEBUG: Unknown TLS version: {version:04x}")
            
    except Exception as e:
        print(f"Error in tls_session_version: {e}")
        return


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
    """处理 Server Hello 消息"""
    print(f"DEBUG: Processing Server Hello, data length={length}")  # 调试日志
    
    # 基本安全检查
    if not isinstance(data, (bytes, bytearray)) or length < 2:
        print("DEBUG: Invalid data in tls_process_server_hello")  # 调试日志
        return -1
        
    try:
        # 读取版本号
        version = (data[0] << 8) | data[1]
        print(f"DEBUG: Server Hello version: {version:04x}")  # 调试日志
        
        # 设置 TLS 版本
        tls_session_version(session, version)
        
        # 跳过随机数（32 字节）
        if length < 34:  # 2 字节版本号 + 32 字节随机数
            print("DEBUG: Data too short for random bytes")  # 调试日志
            return -1
        data = data[34:]
        length -= 34
        
        # 读取会话 ID 长度
        if length < 1:
            print("DEBUG: Data too short for session ID length")  # 调试日志
            return -1
        session_id_length = data[0]
        data = data[1:]
        length -= 1
        
        # 跳过会话 ID
        if length < session_id_length:
            print("DEBUG: Data too short for session ID")  # 调试日志
            return -1
        data = data[session_id_length:]
        length -= session_id_length
        
        # 读取密码套件
        if length < 2:
            print("DEBUG: Data too short for cipher suite")  # 调试日志
            return -1
        cipher_suite = (data[0] << 8) | data[1]
        print(f"DEBUG: Server Hello cipher suite: {cipher_suite:04x}")  # 调试日志
        
        # 设置密码套件
        tls_session_cipher(session, cipher_suite)
        
        return 0
    except Exception as e:
        print(f"Error in tls_process_server_hello: {e}")  # 调试日志
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
        print(f"DEBUG: Server handshake message type={msg_type:02x}")  # 调试日志
        
        # 计算握手消息的长度（3字节，大端序）
        msg_len = (data[1] << 16) | (data[2] << 8) | data[3]
        print(f"DEBUG: Server handshake message length={msg_len}")  # 调试日志
        
        # 验证长度信息
        if 4 + msg_len > length:
            return 0
            
        # 根据握手消息类型进行处理
        if msg_type == 2:  # ServerHello
            print("DEBUG: Processing Server Hello")  # 调试日志
            # 调用ServerHello处理函数
            if tls_process_server_hello_func:
                local_call_named_func(tls_process_server_hello_func, session, data[4:], msg_len, None)
            else:
                # 直接使用内置函数
                tls_process_server_hello(session, data[4:], msg_len, None)
            return 0
        elif msg_type == 11:  # Certificate
            print("DEBUG: Processing Certificate")  # 调试日志
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
    print(f"DEBUG: Processing Client Hello, data length={length}")  # 调试日志
    
    # 基本安全检查
    if not isinstance(data, (bytes, bytearray)) or length < 2:
        print("DEBUG: Invalid data in tls_process_client_hello_data")  # 调试日志
        return -1
        
    try:
        # 读取TLS版本号
        version = (data[0] << 8) | data[1]
        print(f"DEBUG: Client Hello version: {version:04x}")  # 调试日志
        
        # 设置TLS版本
        tls_session_version(session, version)
        
        # 跳过随机数（32字节）
        if length < 34:  # 2字节版本号 + 32字节随机数
            print("DEBUG: Data too short for random bytes")  # 调试日志
            return -1
        data = data[34:]
        length -= 34
        
        # 读取会话ID长度
        if length < 1:
            print("DEBUG: Data too short for session ID length")  # 调试日志
            return -1
        session_id_length = data[0]
        data = data[1:]
        length -= 1
        
        # 跳过会话ID
        if length < session_id_length:
            print("DEBUG: Data too short for session ID")  # 调试日志
            return -1
        data = data[session_id_length:]
        length -= session_id_length
        
        # 读取密码套件长度
        if length < 2:
            print("DEBUG: Data too short for cipher suites length")  # 调试日志
            return -1
        cipher_suites_length = (data[0] << 8) | data[1]
        data = data[2:]
        length -= 2
        
        # 读取第一个密码套件
        if length < 2:
            print("DEBUG: Data too short for first cipher suite")  # 调试日志
            return -1
        cipher_suite = (data[0] << 8) | data[1]
        print(f"DEBUG: Client Hello first cipher suite: {cipher_suite:04x}")  # 调试日志
        
        # 设置密码套件
        tls_session_cipher(session, cipher_suite)
        
        return 0
    except Exception as e:
        print(f"Error in tls_process_client_hello_data: {e}")  # 调试日志
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
def tls_parser(session, offset, data, length, options):
    """
    Parse TLS handshake message and extract relevant information including cipher suites and fingerprints
    """
    try:
        # Check if data is long enough to contain TLS header
        if not data or len(data) < 5:
            return None
            
        # TLS Record Layer
        content_type = data[0]
        version = data[1:3]
        record_length = int.from_bytes(data[3:5], byteorder='big')
        
        # Check if it's a handshake message
        if content_type != 0x16:  # 0x16 is handshake
            return None
            
        # Get TLS version
        tls_version = "Unknown"
        if version == b'\x03\x01':
            tls_version = "TLS 1.0"
        elif version == b'\x03\x02':
            tls_version = "TLS 1.1"
        elif version == b'\x03\x03':
            tls_version = "TLS 1.2"
        elif version == b'\x03\x04':
            tls_version = "TLS 1.3"
            
        # Get handshake message
        if len(data) < 6:
            return None
            
        handshake_type = data[5]
        handshake_type_str = "Unknown"
        
        if handshake_type == 1:
            handshake_type_str = "Client Hello"
        elif handshake_type == 2:
            handshake_type_str = "Server Hello"
        elif handshake_type == 11:
            handshake_type_str = "Certificate"
        elif handshake_type == 16:
            handshake_type_str = "Client Key Exchange"
        elif handshake_type == 14:
            handshake_type_str = "Server Key Exchange"
        elif handshake_type == 15:
            handshake_type_str = "Certificate Request"
        elif handshake_type == 20:
            handshake_type_str = "Finished"
            
        # Extract cipher suites and fingerprints
        cipher_suites = []
        extensions = {}
        if handshake_type in [1, 2] and len(data) > 40:
            # Skip handshake header and random bytes
            offset = 6 + 4 + 32  # handshake header + length + random
            if len(data) < offset:
                return None
            # Skip session ID
            if len(data) < offset + 1:
                return None
            session_id_length = data[offset]
            offset += 1
            if len(data) < offset + session_id_length:
                return None
            offset += session_id_length
            
            if handshake_type == 1:  # Client Hello
                # Get cipher suites length
                if len(data) < offset + 2:
                    return None
                cipher_suites_length = int.from_bytes(data[offset:offset+2], byteorder='big')
                offset += 2
                if len(data) < offset + cipher_suites_length:
                    return None
                # Extract all cipher suites
                for i in range(0, cipher_suites_length, 2):
                    if offset + i + 2 <= len(data):
                        cipher_suite = int.from_bytes(data[offset+i:offset+i+2], byteorder='big')
                        cipher_suites.append(f"0x{cipher_suite:04x}")
                offset += cipher_suites_length
                # Skip compression methods
                if len(data) < offset + 1:
                    return None
                compression_methods_length = data[offset]
                offset += 1
                if len(data) < offset + compression_methods_length:
                    return None
                offset += compression_methods_length
                # Parse extensions
                if len(data) < offset + 2:
                    return {
                        'version': tls_version,
                        'handshake_type': handshake_type_str,
                        'cipher_suites': cipher_suites,
                        'extensions': extensions
                    }
                extensions_length = int.from_bytes(data[offset:offset+2], byteorder='big')
                offset += 2
                if len(data) < offset + extensions_length:
                    return {
                        'version': tls_version,
                        'handshake_type': handshake_type_str,
                        'cipher_suites': cipher_suites,
                        'extensions': extensions
                    }
                ext_offset = offset
                while ext_offset + 4 <= offset + extensions_length and ext_offset + 4 <= len(data):
                    ext_type = int.from_bytes(data[ext_offset:ext_offset+2], byteorder='big')
                    ext_length = int.from_bytes(data[ext_offset+2:ext_offset+4], byteorder='big')
                    if ext_offset + 4 + ext_length > len(data):
                        break
                    if ext_type == 0:  # Server Name Indication
                        if ext_length > 0 and ext_offset + 5 + ext_length - 1 <= len(data):
                            try:
                                server_name = data[ext_offset+5:ext_offset+5+ext_length-1].decode('utf-8', errors='ignore')
                                extensions['SNI'] = server_name
                            except Exception:
                                pass
                    elif ext_type == 10:  # Supported Groups
                        if ext_length > 0:
                            groups = []
                            for i in range(0, ext_length, 2):
                                if ext_offset+4+i+2 <= len(data):
                                    group = int.from_bytes(data[ext_offset+4+i:ext_offset+4+i+2], byteorder='big')
                                    groups.append(f"0x{group:04x}")
                            extensions['Supported Groups'] = groups
                    elif ext_type == 11:  # EC Point Formats
                        if ext_length > 0:
                            formats = []
                            for i in range(ext_length):
                                if ext_offset+4+i < len(data):
                                    formats.append(f"0x{data[ext_offset+4+i]:02x}")
                            extensions['EC Point Formats'] = formats
                    ext_offset += 4 + ext_length
            elif handshake_type == 2:  # Server Hello
                # Get selected cipher suite
                if len(data) < offset + 2:
                    return None
                cipher_suite = int.from_bytes(data[offset:offset+2], byteorder='big')
                cipher_suites.append(f"0x{cipher_suite:04x}")
        # Update session fields
        if session is not None:
            session.fields["tls.version"] = tls_version
            session.fields["tls.cipher_suites"] = ", ".join(cipher_suites)
            session.fields["tls.handshake_type"] = handshake_type_str
            if extensions:
                session.fields["tls.extensions"] = str(extensions)
        return {
            'version': tls_version,
            'handshake_type': handshake_type_str,
            'cipher_suites': cipher_suites,
            'extensions': extensions
        }
    except Exception as e:
        print(f"Error parsing TLS message: {str(e)}")
        return None

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
    """TLS 流量分类函数"""
    print(f"DEBUG: tls_classify called with length={length}")  # 调试日志
    
    # 基础协议过滤（至少需要6字节）
    if length < 6:
        print("DEBUG: Data too short for TLS classification")  # 调试日志
        return

    # 避免重复处理已识别的 TLS 会话
    if session.has_protocol("tls"):
        return

    # 验证 TLS 记录类型
    record_type = data[0]
    print(f"DEBUG: TLS record type: {record_type:02x}")  # 调试日志
    
    # 只处理握手消息
    if record_type != 0x16:  # 0x16 = Handshake
        print(f"DEBUG: Skipping non-handshake message type: {record_type:02x}")  # 调试日志
        return

    # 验证 TLS 版本号
    version = (data[1] << 8) | data[2]
    print(f"DEBUG: TLS version: {version:04x}")  # 调试日志
    
    if version not in [0x0300, 0x0301, 0x0302, 0x0303, 0x0304]:  # SSLv3 到 TLS 1.3
        print(f"DEBUG: Invalid TLS version: {version:04x}")  # 调试日志
        return

    # 验证握手消息类型
    if length < 6:
        print("DEBUG: Data too short for handshake type")  # 调试日志
        return
        
    handshake_type = data[5]
    print(f"DEBUG: TLS handshake type: {handshake_type:02x}")  # 调试日志
    
    # 只处理 Client Hello 和 Server Hello
    if handshake_type not in [1, 2]:  # 1 = Client Hello, 2 = Server Hello
        print(f"DEBUG: Skipping non-Hello handshake message type: {handshake_type:02x}")  # 调试日志
        return

    print(f"DEBUG: Found valid TLS handshake message: type={handshake_type:02x}, version={version:04x}")  # 调试日志
    
    # 记录会话协议为TLS
    session.add_protocol("tls")

    # 初始化 TLS 解析上下文
    tls = TLSInfo()
    tls.length = length
    tls.buf = bytearray(data)
    tls.which = which

    # 注册后续解析器（tls_parser）到会话系统
    from analyzers.parsers import parsers_register
    parsers_register(session, tls_parser, tls, tls_save)

    # 处理客户端/服务端 Hello 消息
    if handshake_type == 1:  # Client Hello
        print("DEBUG: Processing Client Hello")  # 调试日志
        tls_process_client_hello_data(session, data[5:], length-5, None)
    elif handshake_type == 2:  # Server Hello
        print("DEBUG: Processing Server Hello")  # 调试日志
        tls_process_server_hello(session, data[5:], length-5, None)

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
    print(f"DEBUG: Defined ver_field with ID: {ver_field}")  # 调试日志

    # Define cipher suite field (e.g., AES128-GCM-SHA256)
    cipher_field = field_manager.field_define("tls", "uptermfield",
                                       "tls.cipher", "Cipher", "tls.cipher",
                                       "SSL/TLS cipher field",
                                       FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                       None)
    print(f"DEBUG: Defined cipher_field with ID: {cipher_field}")  # 调试日志

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

def tls_session_cipher(session, cipher):
    """设置 TLS 密码套件"""
    try:
        # 确保密码套件是整数
        if isinstance(cipher, (bytes, bytearray)):
            cipher = int.from_bytes(cipher, byteorder='big')
        elif isinstance(cipher, str):
            cipher = int(cipher, 16)
        elif not isinstance(cipher, int):
            cipher = int(cipher)
            
        print(f"DEBUG: Setting TLS cipher suite: {cipher:04x}")
        
        # 映射密码套件到可读字符串
        cipher_str = None
        if cipher == 0x0001:
            cipher_str = "TLS_NULL_WITH_NULL_NULL"
        elif cipher == 0x0002:
            cipher_str = "TLS_RSA_WITH_NULL_MD5"
        elif cipher == 0x0003:
            cipher_str = "TLS_RSA_WITH_NULL_SHA"
        elif cipher == 0x0004:
            cipher_str = "TLS_RSA_WITH_RC4_128_MD5"
        elif cipher == 0x0005:
            cipher_str = "TLS_RSA_WITH_RC4_128_SHA"
        elif cipher == 0x0006:
            cipher_str = "TLS_RSA_WITH_DES_CBC_SHA"
        elif cipher == 0x0007:
            cipher_str = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        elif cipher == 0x0008:
            cipher_str = "TLS_RSA_WITH_AES_128_CBC_SHA"
        elif cipher == 0x0009:
            cipher_str = "TLS_RSA_WITH_AES_256_CBC_SHA"
        elif cipher == 0x000A:
            cipher_str = "TLS_RSA_WITH_AES_128_CBC_SHA256"
        elif cipher == 0x000B:
            cipher_str = "TLS_RSA_WITH_AES_256_CBC_SHA256"
        elif cipher == 0x000C:
            cipher_str = "TLS_RSA_WITH_AES_128_GCM_SHA256"
        elif cipher == 0x000D:
            cipher_str = "TLS_RSA_WITH_AES_256_GCM_SHA384"
        elif cipher == 0x000E:
            cipher_str = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        elif cipher == 0x000F:
            cipher_str = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        elif cipher == 0x0010:
            cipher_str = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
        elif cipher == 0x0011:
            cipher_str = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        elif cipher == 0x0012:
            cipher_str = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        elif cipher == 0x0013:
            cipher_str = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
        elif cipher == 0x0014:
            cipher_str = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
        elif cipher == 0x0015:
            cipher_str = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
        elif cipher == 0x0016:
            cipher_str = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
        elif cipher == 0x0017:
            cipher_str = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
        elif cipher == 0x0018:
            cipher_str = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        elif cipher == 0x0019:
            cipher_str = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            
        if cipher_str:
            print(f"DEBUG: Mapped cipher {cipher:04x} to {cipher_str}")
            field_manager.field_str_add("tls.cipher", cipher_str, session)
            print(f"DEBUG: Session fields after setting cipher: {session.fields}")
        else:
            print(f"DEBUG: Unknown TLS cipher suite: {cipher:04x}")
            
    except Exception as e:
        print(f"Error in tls_session_cipher: {e}")
        return

def format_tls_handshake_message(data, length):
    """格式化输出TLS握手消息的各个部分"""
    if not isinstance(data, (bytes, bytearray)) or length < 5:
        return "Invalid TLS handshake message"
        
    try:
        # TLS Record Header
        content_type = data[0]
        version = (data[1] << 8) | data[2]
        record_length = (data[3] << 8) | data[4]
        
        # Handshake Header
        handshake_type = data[5]
        handshake_length = (data[6] << 16) | (data[7] << 8) | data[8]
        
        # Server/Client Version
        tls_version = (data[9] << 8) | data[10]
        
        # Random (32 bytes)
        random = data[11:43]
        
        # Session ID
        session_id_length = data[43]
        session_id = data[44:44+session_id_length]
        
        # Cipher Suite
        cipher_suite = (data[44+session_id_length] << 8) | data[44+session_id_length+1]
        
        # Compression Method
        compression_method = data[44+session_id_length+2]
        
        # Extensions (if any)
        extensions_start = 44+session_id_length+3
        extensions = data[extensions_start:] if extensions_start < length else b''
        
        # Format output
        output = []
        output.append("TLS Record Header:")
        output.append(f"{content_type:02x} {version:04x} {record_length:04x}")
        output.append(f"- Content Type: {content_type:02x} ({'Handshake' if content_type == 0x16 else 'Unknown'})")
        output.append(f"- Version: {version:04x} ({'TLS 1.2' if version == 0x0303 else 'Unknown'})")
        output.append(f"- Length: {record_length:04x}")
        output.append("")
        
        output.append("Handshake Header:")
        output.append(f"{handshake_type:02x} {handshake_length:06x}")
        output.append(f"- Type: {handshake_type:02x} ({'Server Hello' if handshake_type == 0x02 else 'Client Hello' if handshake_type == 0x01 else 'Unknown'})")
        output.append(f"- Length: {handshake_length:06x}")
        output.append("")
        
        output.append("Server/Client Version:")
        output.append(f"{tls_version:04x} ({'TLS 1.2' if tls_version == 0x0303 else 'Unknown'})")
        output.append("")
        
        output.append("Random (32 bytes):")
        output.append(binascii.hexlify(random).decode())
        output.append("")
        
        output.append("Session ID:")
        output.append(f"Length: {session_id_length:02x}")
        output.append(binascii.hexlify(session_id).decode())
        output.append("")
        
        output.append("Cipher Suite:")
        output.append(f"{cipher_suite:04x}")
        output.append("")
        
        output.append("Compression Method:")
        output.append(f"{compression_method:02x}")
        output.append("")
        
        if extensions:
            output.append("Extensions:")
            output.append(binascii.hexlify(extensions).decode())
        
        return "\n".join(output)
        
    except Exception as e:
        return f"Error formatting TLS handshake message: {e}"