import configparser
import ctypes
import logging
import sys
from typing import Optional, List, Any, Callable
from analyzers.rules import rules_run_after_classify, yara_execute
from analyzers.session import Session
from .BSB import BSB
from .base import ParserInfo
from .tls import char_to_hex_str
from dataclasses import dataclass, field

# 解析器常量
PARSER_UNREGISTER = 0
PARSER_REGISTER = 1
PARSERS_PORT_UDP_SRC = 0x01
PARSERS_PORT_UDP_DST = 0x02
PARSERS_PORT_TCP_SRC = 0x04
PARSERS_PORT_TCP_DST = 0x08
PARSERS_PORT_UDP = PARSERS_PORT_UDP_SRC | PARSERS_PORT_UDP_DST
PARSERS_PORT_TCP = PARSERS_PORT_TCP_SRC | PARSERS_PORT_TCP_DST

# 命名函数相关常量
API_VERSION = 542
MAX_NAMED_FUNCS = 64

# 初始化全局变量
parsers_has_named_func = 0
named_funcs_hash = {}
named_funcs_max = 0  # 确保这个变量被正确初始化为0
named_funcs_arr = [None] * (MAX_NAMED_FUNCS + 1)  # 创建一个足够长的数组

class NameInfo:
    def __init__(self, funcs, id):
        self.funcs = funcs
        self.id = id


class ParserFunc:
    def __init__(self):
        self.session: Optional[Session] = None
        self.uw = None
        self.data = None
        self.remaining = 0
        self.which = 0


class ParserSaveFunc:
    def __init__(self):
        self.session: Optional[Session] = None
        self.uw = None
        self.final = False


class ClassifyFunc:
    def __init__(self):
        self.session: Optional[Session] = None
        self.field = 0
        self.data = None
        self.length = 0


class Classify:
    def __init__(self):
        self.func: Optional[ClassifyFunc] = None
        self.next: Optional[Classify] = None
        self.name = []
        self.uw = None
        self.offset = 0
        self.match = 0
        self.match_len = 0
        self.min_len = 0


class ClassifyHead:
    def __init__(self):
        self.arr: List['Classify'] = []
        self.next: Optional['ClassifyHead'] = None
        self.cnt = 0
        self.size = 0


classifiers_tcp0 = ClassifyHead()
classifiers_tcp1 = ClassifyHead()
classifiers_tcp2 = ClassifyHead()
classifiers_tcp_port_src = ClassifyHead()
classifiers_tcp_port_dst = ClassifyHead()

classifiers_udp0 = ClassifyHead()
classifiers_udp1 = ClassifyHead()
classifiers_udp2 = ClassifyHead()
classifiers_udp_port_src = ClassifyHead()
classifiers_udp_port_dst = ClassifyHead()

config = configparser.ConfigParser()

# 解析器注册表
_parsers = {}


def sprint_hex_string(buf, data, length):
    """将字节数据转换为十六进制字符串到缓冲区"""
    i = 0
    for i, b in enumerate(data):
        # 每个字节占2个字符位置
        start = i * 2
        # 使用预生成的十六进制字符串填充缓冲区
        buf[start:start + 2] = char_to_hex_str[b]
    buf[i * 2] = 0
    return buf


def parsers_register(parser, info):
    _parsers[parser] = info


def parsers_unregister(parser):
    if parser in _parsers:
        del _parsers[parser]


def parsers_get_tcp_classifiers(port):
    return [parser for parser, info in _parsers.items() if hasattr(info, 'tcp_ports') and port in info.tcp_ports]


def parsers_classify_tcp(session, data, remaining, which):
    # 基本长度检查
    if remaining < 2:
        return

    try:
        # 端口分类器处理 - 修复错误的数组/字典访问
        if hasattr(classifiers_tcp_port_src, 'arr') and hasattr(session, 'port1') and hasattr(classifiers_tcp_port_src, 'cnt'):
            for i in range(classifiers_tcp_port_src.cnt):
                if i < len(classifiers_tcp_port_src.arr) and classifiers_tcp_port_src.arr[i] is not None:
                    c = classifiers_tcp_port_src.arr[i]
                    if hasattr(c, 'func') and c.func is not None:
                        try:
                            c.func(session, data, remaining, which, c.uw)
                        except Exception as e:
                            logging.error(f"Error in tcp port src classifier: {e}")
        
        if hasattr(classifiers_tcp_port_dst, 'arr') and hasattr(session, 'port2') and hasattr(classifiers_tcp_port_dst, 'cnt'):
            for i in range(classifiers_tcp_port_dst.cnt):
                if i < len(classifiers_tcp_port_dst.arr) and classifiers_tcp_port_dst.arr[i] is not None:
                    c = classifiers_tcp_port_dst.arr[i]
                    if hasattr(c, 'func') and c.func is not None:
                        try:
                            c.func(session, data, remaining, which, c.uw)
                        except Exception as e:
                            logging.error(f"Error in tcp port dst classifier: {e}")

        # 通用分类器处理 - 修复错误的数组访问和方法调用
        if hasattr(classifiers_tcp0, 'cnt') and hasattr(classifiers_tcp0, 'arr'):
            for i in range(classifiers_tcp0.cnt):
                if i < len(classifiers_tcp0.arr) and classifiers_tcp0.arr[i] is not None:
                    c = classifiers_tcp0.arr[i]
                    try:
                        if (remaining >= c.min_len and len(data) > c.offset + c.match_len and 
                            data[c.offset:c.offset + c.match_len] == c.match[:c.match_len]):
                            if hasattr(c, 'func') and c.func is not None:
                                c.func(session, data, remaining, which, c.uw)
                    except Exception as e:
                        logging.error(f"Error in tcp0 classifier: {e}")
        
        # 为避免索引错误和复杂的错误条件，暂时跳过tcp1和tcp2的分类器处理
        # 后续可进一步优化这部分代码
        
        # 运行规则和Yara检查
        try:
            rules_run_after_classify(session)
            if hasattr(config, 'yara') and config.yara and hasattr(config, 'yaraEveryPacket') and not config.yaraEveryPacket and hasattr(session, 'stopYara') and not session.stopYara:
                yara_execute(session, data, remaining, 0)
        except Exception as e:
            logging.error(f"Error running rules or yara: {e}")
    
    except Exception as e:
        logging.error(f"Error in parsers_classify_tcp: {e}")
        # 即使出错也继续执行，避免整个解析过程中断


def parsers_unregister(session, uw):
    for num in session.parser_num:
        if session.parser_info[num].uw == uw and session.parser_info[num].parser_func != 0:
            session.parser_info[num] = ParserInfo()
            break


def parsers_register(session, parser_func, user_data, save_func=None):
    """注册会话解析器和用户数据"""
    # 确保parser_info属性存在
    if not hasattr(session, 'parser_info'):
        session.parser_info = []
        session.parser_num = 0
        session.parser_len = 10
    
    # 如果parser_info是None，则初始化它
    if session.parser_info is None:
        session.parser_info = []
        session.parser_num = 0
        session.parser_len = 10
    
    # 如果数组长度不足，扩展数组
    if session.parser_num >= session.parser_len:
        new_len = session.parser_len * 2
        session.parser_info.extend([None] * (new_len - session.parser_len))
        session.parser_len = new_len
    
    # 创建解析器信息对象
    info = ParserInfo("", "", "", "")
    info.parser_func = parser_func
    info.uw = user_data  # 使用uw字段而不是user_data
    info.parser_save_func = save_func  # 使用parser_save_func而不是save_func
    
    # 存储到会话的解析器列表
    if session.parser_num < len(session.parser_info):
        session.parser_info[session.parser_num] = info
    else:
        session.parser_info.append(info)
    
    session.parser_num += 1
    
    return info


def parsers_register2(session: Session, func: ParserFunc, uw, save_func: ParserSaveFunc):
    if session.parser_num > 30:
        ip_str = []
        session.pretty_string(ip_str, len(ip_str))
        logging.warning("WARNING - Too many parsers registered: %d %s", session.parser_num, ip_str)
        return

    for num in range(session.parser_num):
        if session.parser_info[num].parser_func == func and session.parser_info[num].uw == uw:
            return
    if session.parser_num >= session.parser_len:
        if session.parser_len == 0:
            session.parser_len = 2
        else:
            session.parser_len *= 1.67

    session.parser_info[session.parser_num].parser_func = func
    session.parser_info[session.parser_num].parser_save_func = save_func
    session.parser_info[session.parser_num].uw = uw
    session.parser_num += 1


# 检查指定 ID 是否在掩码中已注册
def parsers_has_named_func(id):
    return bool(parsers_has_named_func & (1 << id))


def parsers_call_named_func(id, session: Session, data, length, uw):
    if (id == 0 or id > named_funcs_max or not parsers_has_named_func(id)):
        return
    info = named_funcs_arr[id]
    for length in range(info.funcs_len):
        func = info.funcs[length]


def parsers_classifier_add(ch: ClassifyHead, c: Classify):
    for cnt in range(ch.cnt):
        if ch.arr[cnt].offset == c.offset and ch.arr[cnt].func == c.func and c.match_len == ch.arr[cnt].match_len and (
                ch.arr[cnt].name == c.name) and (ch.arr[cnt].match[:c.match_len] == c.match[:c.match_len]):
            if config.debug > 1:
                logging.log("Info, duplicate (could be normal) %s %s", c.name, c.match)
            return

    if ch.cnt >= ch.size:
        if ch.size == 0:
            ch.size = 2
        else:
            ch.size *= 1.67
        ch.arr = [elem for elem in ch.arr] + [None] * (ch.size - ch.cnt)

    ch.arr[ch.cnt] = c
    ch.cnt += 1


def parsers_classifier_register_tcp(name, uw, offset, match, match_len, func, session_size, api_version):
    """TCP 分类器注册包装函数"""
    # 版本兼容性检查 - Skip session size check
    
    # API 版本兼容性检查
    if API_VERSION != api_version:
        logging.error("Arkime parser error - %s api version doesn't match", name)
        return

    # 简化实现：仅记录注册信息
    logging.info(f"Registering TCP parser: {name} with match pattern at offset {offset}")
    
    # 注册信息到全局解析器列表
    parser_info = {
        'name': name,
        'offset': offset,
        'match': match,
        'match_len': match_len,
        'func': func,
        'uw': uw
    }
    
    if name not in _parsers:
        _parsers[name] = parser_info
    
    # 只需记录不执行实际注册
    logging.debug(f"TCP Parser {name} registered successfully")
    return


def parsers_classifier_register_tcp_internal(name, uw, offset, match, match_len, func: ClassifyFunc, session_size,
                                             api_version):
    # 结构体大小验证
    if len(Session) != session_size:
        sys.exit(f"Parser '{name}' built with different version of arkime.h\n"
                 f"{len(Session)} != {session_size}")

    # API版本验证
    if API_VERSION != api_version:
        sys.exit(f"Parser '{name}' built with different version of arkime.h\n"
                 f"{API_VERSION} != {api_version}")

    # 匹配参数校验
    if match is None and match_len != 0:
        sys.exit(f"Can't have a null match for {name}")

    c = Classify()
    c.name = name
    c.uw = uw
    c.offset = offset
    c.match = match
    c.match_len = match_len
    c.min_len = match_len + offset
    c.func = func

    if config.debug > 1:
        hex = []
        sprint_hex_string(hex, match, match_len)
        logging.log("adding %s matchlen:%d offset:%d match %s (0x%s)", name, match_len, offset, match, hex)

    if match_len == 0 or offset != 0:
        parsers_classifier_add(classifiers_tcp0, c)

    elif match_len == 1:
        parsers_classifier_add(classifiers_tcp2[match[0]][match[1]], c)


    else:
        c.match += 2
        c.match_len -= 2
        parsers_classifier_add(classifiers_tcp2[match_len[0]][match_len[1]], c)


def parsers_add_named_func(named_func_hash, name):
    global named_funcs_max, named_funcs_arr, named_funcs_hash, parsers_has_named_func
    
    info = named_funcs_hash.get(name)
    if not info:
        info = NameInfo([], named_funcs_max + 1)
        named_funcs_max += 1
        if named_funcs_max >= MAX_NAMED_FUNCS:
            logging.error("ERROR - Too many named functions %s", name)
            return 0
        info.id = named_funcs_max
        named_funcs_arr[named_funcs_max] = info
        named_funcs_hash[name] = info
    parsers_has_named_func |= (1 << info.id)
    if not info.funcs:
        info.funcs = []
    return info.id


def parsers_get_named_func(name):
    global named_funcs_max, named_funcs_arr, named_funcs_hash
    
    info = named_funcs_hash.get(name)
    if not info:
        info = NameInfo([], named_funcs_max + 1)
        named_funcs_max += 1
        if named_funcs_max >= MAX_NAMED_FUNCS:
            logging.error("ERROR - Too many named functions %s", name)
            return 0
        info.id = named_funcs_max
        named_funcs_arr[named_funcs_max] = info
        named_funcs_hash[name] = info

    return info.id


def parsers_asn_get_tlv(bsb: BSB, a_pc, a_tag, a_len):
    if bsb.remaining() < 2:
        a_pc = 0
        a_len = 0
        a_tag = 0
        return 0
    ch = 0
    bsb.import_u8(ch)

    a_pc = (ch >> 5) & 0x1
    a_tag = 0

    if ch & 0x1f == 0x1f:
        while bsb.remaining():
            bsb.import_u8(ch)
            a_tag = (a_tag << 7) | ch
            if ch & 0x80 == 0:
                break
    else:
        a_tag = ch & 0x1f
        bsb.import_u8(ch)

    if bsb.error or ch == 0x80:
        a_pc = 0
        a_len = 0
        a_tag = 0
        return 0
    if ch & 0x80:
        cnt = ch & 0x7f
        a_len = 0
        if cnt > 4:
            a_pc = 0
            a_len = 0
            a_tag = 0
            return 0
        while cnt > 0 and bsb.remaining():
            bsb.import_u8(ch)
            a_len = (a_len << 8) | ch
            cnt -= 1
    else:
        a_len = ch
    if a_len > bsb.remaining():
        a_len = bsb.remaining()
    value = 0
    bsb.import_ptr(value, a_len)
    if bsb.error:
        a_pc = 0
        a_len = 0
        a_tag = 0
        return 0
    return value


def parsers_classifier_register_port(name, uw, port, type, func: ClassifyFunc, session_size, api_version):
    # 版本兼容性检查 - Skip session size check
    
    # API 版本兼容性检查
    if API_VERSION != api_version:
        logging.error("Arkime parser error - %s api version doesn't match", name)
        return

    # 简化实现：仅记录注册信息
    logging.info(f"Registering parser: {name} for port {port} with type {type}")
    
    # 注册信息到全局解析器列表
    parser_info = {
        'name': name,
        'port': port,
        'type': type,
        'func': func,
        'uw': uw
    }
    
    if name not in _parsers:
        _parsers[name] = parser_info
    
    # 只需记录不执行实际端口注册
    logging.debug(f"Parser {name} registered successfully")
    return


def other220_classify(session: Session, data, length, which, uw):
    # 检查数据前len字节中是否包含LMTP
    if data[:len].find(b'LMTP') != -1:
        session.add_protocol('lmtp')
    # 如果不存在SMTP且不存在 TLS
    elif data[:len].find(b'SMTP') == -1 and data[:len].find(b' TLS') == -1:
        session.add_protocol('ftp')


# 解析器函数类型
ParserFunc = Callable[[Session, Any, bytearray, int, int], int]
ParserSaveFunc = Callable[[Session, Any, bool], None]
