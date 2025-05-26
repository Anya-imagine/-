import configparser
import sys
import os
import ipaddress
import json
import urllib.parse
import logging
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
import functools

from .field import FieldManager
from .session import Session
from analyzers.imports import (
    FieldType,
    FIELD_TYPE_IP_GHASH,
    FIELD_FLAG_CNT,
    FIELD_FLAG_IPPRE,
    FIELD_FLAG_FAKE,
    FIELD_TYPE_STR_HASH,
    FIELD_FLAG_FORCE_UTF8,
    FieldObject,
)
from analyzers import BSB
from scapy.all import sniff, DNS, IP

BSB = BSB.BSB
logger = logging.getLogger(__name__)

MAX_QTYPES = 512
MAX_QCLASSES = 256
MAX_IPS = 2000

DEFAULT_JSON_LEN = 200
HOST_IP_JSON_LEN = 250
ANSWER_JSON_LEN = 200

FNV_OFFSET = 0x811c9dc5 
FNV_PRIME = 0x01000193  

dnsField = 0
dnsHostField = 0
dnsHostMailserverField = 0
dnsHostNameserverField = 0
dnsPunyField = 0
dnsStatusField = 0
dnsOpcodeField = 0
dnsQueryTypeField = 0
dnsQueryClassField = 0
dnsQueryHostField = 0
dnsOutputAnswers = ""
parseDNSRecordAll = 0
root = "<root>"
field_registry = {}

qclasses = []
qtypes = bytearray(MAX_QTYPES)
rcodes = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMPL", "REFUSED", 
         "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI", 
         "12", "13", "14", "15", "BADSIG", "BADKEY", "BADTIME", "BADMODE",
         "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE"]
opcodes = ["QUERY", "IQUERY", "STATUS", "3", "NOTIFY", "UPDATE", "DSO", "7", 
          "8", "9", "10", "11", "12", "13", "14", "15"]
flagsStr = ["AA", "TC", "RD", "RA", "Z", "AD", "CD"]

# Setup logging
logging.basicConfig(level=logging.INFO)
dns_logger = logging.getLogger("DNS_MODULE")

# Create a decorator to track function calls
def track_dns_calls(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Print function call info
        session = args[0] if len(args) > 0 else None
        dns_logger.info(f"✅ 调用DNS函数: {func.__name__}")
        result = func(*args, **kwargs)
        if result is not None:
            dns_logger.info(f"  - 返回值: {result}")
        return result
    return wrapper

# Add the decorator to all DNS functions
# Find all functions that start with dns_ and apply the decorator
current_module = sys.modules[__name__]
for name in dir(current_module):
    if name.startswith("dns_"):
        func = getattr(current_module, name)
        if callable(func):
            setattr(current_module, name, track_dns_calls(func))

# Keep the original parser_init function
original_parser_init = None
if "parser_init" in dir(current_module):
    original_parser_init = current_module.parser_init

# Override parser_init to report when it's called
@track_dns_calls
def parser_init():
    dns_logger.info("🔄 初始化DNS解析器")
    if original_parser_init:
        return original_parser_init()
    return None

# Replace the original parser_init
if original_parser_init:
    current_module.parser_init = parser_init

class Classifier:
    @staticmethod
    def register_port(protocol: str, callback: callable, port: int, port_type: str):
        """
        :param protocol: 协议名称（dns/llmnr/mdns）
        :param callback: 分类回调函数
        :param port: 监听端口号
        :param port_type: 端口类型，支持：
            - 'tcp_src'   TCP源端口
            - 'tcp_dst'   TCP目标端口
            - 'udp'       UDP端口（双向）
        """

class DoublyLinkedList:
    def __init__(self):
        self.head = None
        self.tail = None
        self.count = 0  # 对应DLL_COUNT的计数器

    def get_count(self):
        """获取链表元素数量，对应DLL_COUNT宏"""
        return self.count




class DnsType(Enum):
    DNS_RR_A = 1,
    DNS_RR_NS = 2,
    DNS_RR_CNAME = 5,
    DNS_RR_MX = 15,
    DNS_RR_TXT = 16,
    DNS_RR_AAAA = 28,
    DNS_RR_HTTPS = 65,
    DNS_RR_CAA = 257


class DnsClass(Enum):
    CLASS_IN = 1,
    CLASS_CS = 2,
    CLASS_CH = 3,
    CLASS_HS = 4,
    CLASS_NONE = 254,
    CLASS_ANY = 255,
    CLASS_UNKNOWN = 65280


class DnsSvcbParamKey(Enum):
    SVCB_PARAM_KEY_ALPN = 1
    SVCB_PARAM_KEY_PORT = 3
    SVCB_PARAM_KEY_IPV4_HINT = 4
    SVCB_PARAM_KEY_IPV6_HINT = 6


class DnsResultRecordType(Enum):
    RESULT_RECORD_ANSWER = 1  # Answer or Prerequisites Record
    RESULT_RECORD_AUTHORITATIVE = 2  # Authoritative or Update Record
    RESULT_RECORD_ADDITIONAL = 3  # Additional Record
    RESULT_RECORD_UNKNOWN = 4  # Unknown Record


@dataclass
class DnsAnswerMxrdata:
    preference: int = field(metadata={"range": (0, 65535)})
    exchange: Optional[str] = None

    def preference_range(self):
        if self.preference > 65536 or self.preference < 0:
            raise ValueError("preference must be between 0 and 65535")


@dataclass
class DnsAnswerSvcbRDataFieldValue:
    key: 'DnsSvcbParamKey'
    t_next: Optional['DnsAnswerSvcbRDataFieldValue'] = None
    t_prev: Optional['DnsAnswerSvcbRDataFieldValue'] = None
    value: Any = None


class DnsAnswerSvcbRDataFieldHead:
    t_count: int = 0


@dataclass
class DnsAnswerSvcbRData:
    priority: int = field(metadata={"range": (0, 65535)})
    dname: Optional[str] = None
    fieldValues: Optional['DnsAnswerSvcbRDataFieldHead'] = None

    def priority_range(self):
        if self.priority > 65536 or self.priority < 0:
            raise ValueError("preference must be between 0 and 65535")


@dataclass
class DnsAnswerCaaData:
    flags: int = field(metadata={"range": (0, 255)})
    char: Optional[str] = None
    value: Optional[str] = None


@dataclass
class DnsAnswer:
    ipA: Optional[int] = None
    type_id: Optional[int] = None
    ttl: Optional[int] = None
    class_: Optional[str] = None
    type_: Optional[DnsType] = None
    name: Optional[str] = None
    cname: Optional[str] = None
    mx: Optional[DnsAnswerMxrdata] = None
    nsdname: Optional[str] = None
    ipAAAA: Optional[ipaddress.IPv6Address] = None
    txt: Optional[str] = None
    svcb: Optional[DnsAnswerSvcbRData] = None
    caa: Optional[DnsAnswerCaaData] = None
    t_next: Optional['DnsAnswer'] = None
    t_prev: Optional['DnsAnswer'] = None

    def __post_init__(self):
        # 修复：添加None值检查，避免与None进行比较
        if self.ipA is not None and not (0 <= self.ipA < 2**32):
            raise ValueError("ipA must be between 0 and 2^32-1")
        elif self.ttl is not None and not (0 <= self.ttl < 2**32):
            raise ValueError("ttl must be between 0 and 2^32-1")
        elif self.type_id is not None and not (0 <= self.type_id < 2**16):
            raise ValueError("type_id must be between 0 and 2^16-1")


class DnsAnswerHead:
    def __init__(self):
        self.t_count = 0
        self.t_head = None
        self.t_prev = None

    def push_tail(self, answer):
        if self.t_count == 0:
            self.t_head = answer
            self.t_prev = answer
        else:
            answer.t_prev = self.t_prev
            answer.t_next = None
            answer.t_prev.t_next = answer
            self.t_prev = answer
        self.t_count += 1
    
    def get_count(self):
        return self.t_count
        
    def __iter__(self):
        """使DnsAnswerHead可迭代，从t_head开始遍历链表"""
        current = self.t_head
        while current is not None:
            yield current
            current = getattr(current, 't_next', None)


@dataclass
class DnsQuery:
    class_: Optional[str] = None
    type_: Optional[DnsType] = None
    type_id: Optional[int] = field(metadata={"range": (0, 2**16 - 1)}, default=0)
    class_id: Optional[int] = field(metadata={"range": (0, 2**16 - 1)}, default=0)
    packet_id: Optional[int] = field(metadata={"range": (0, 2**16 - 1)}, default=0)
    opcode_id: Optional[int] = field(metadata={"range": (0, 2**8 - 1)}, default=0)
    opcode: Optional[str] = None
    hostname: Optional[str] = None
    packet_uid: Optional[str] = None

    def __post_init__(self):
        # 修复：添加None值检查，避免与None进行比较
        if self.type_id is not None and not (0 <= self.type_id < 2**16 - 1):
            raise ValueError("type_id must be between 0 and 2^16-1")
        elif self.class_id is not None and not (0 <= self.class_id < 2**16 - 1):
            raise ValueError("class_id must be between 0 and 2^16-1")
        elif self.packet_id is not None and not (0 <= self.packet_id < 2**16 - 1):
            raise ValueError("packet_id must be between 0 and 2^16-1")
        elif self.opcode_id is not None and not (0 <= self.opcode_id < 2**8 - 1):
            raise ValueError("opcode_id must be between 0 and 2^8-1")


@dataclass
class Dns:
    rcode_id: Optional[int] = field(metadata={"range": (0, 2 ** 8 - 1)})
    headerFlags: Optional[int] = field(metadata={"range": (0, 2 ** 8 - 1)})
    t_next: Optional['Dns'] = None
    t_prev: Optional['Dns'] = None
    query: Optional['DnsQuery'] = None
    answers: Optional['DnsAnswerHead'] = None
    hosts: Optional[dict] = None
    nsHosts: Optional[dict] = None
    mxHosts: Optional[dict] = None
    punyHosts: Optional[dict] = None
    ips: Optional[dict] = None
    nsIPs: Optional[dict] = None
    mxIPs: Optional[dict] = None
    rcode: Optional[str] = None


@dataclass
class DnsHead:
    t_next: Optional['Dns'] = None
    t_prev: Optional['Dns'] = None
    t_count: int = 0


# typedef HASH_VAR(t_, DNSHash_t, DNSHead_t, 1);
# typedef HASH_VAR(t_, DNSHashStd_t, DNSHead_t, 10);

class DnsInfo:
    def __init__(self):
        self.data = [bytearray(1024), bytearray(1024)]  # 动态二进制缓冲区
        self.size = [1024, 1024]
        self.pos = [0, 0]
        self.length = [0, 0]
        self.query = DnsQuery()

    def __post__init__(self):
        pass

    def __eq__(self, other: object) -> bool:
        """DNS 对象五维特征精确匹配"""
        if not isinstance(other, DnsInfo):
            return False

        return (self.query.packet_uid == other.query.packet_uid and
                self.query.opcode_id == other.query.opcode_id and
                self.query.class_id == other.query.class_id and
                self.query.type_id == other.query.type_id and
                self.query.hostname == other.query.hostname)


# 释放DNS解析过程中分配的资源
def dns_free(session, uw: DnsInfo):
    if uw.data:
        uw.data[0] = None  # 释放请求数据缓冲区
        uw.data[1] = None  # 释放响应数据缓冲区


def dns_name_element(nbsb: BSB, bsb: BSB) -> int:
    try:
        nlen: int = bsb.read_u8()
        if nlen == 0 or nlen > bsb.remaining():  # 检查标签有效性
            return 1
        for _ in range(nlen):
            c = bsb.read_u8()
            if c > 0x7F:
                nbsb.export_u8(ord('M'))
                nbsb.export_u8(ord('-'))
                c &= 0x7F
            if not (0x20 <= c <= 0x7E):
                nbsb.export_u8(ord('^'))
                c ^= 0x40  # 0x7F^0x40 = 0x3F = ?

            nbsb.export_u8(c)

        return 0
    except:
        return 1


def dns_name(full: bytearray, fulllen: int, inbsb: BSB, name: bytearray, namelen: list):
    didpointer = 0  # 指针跳转计数
    nbsb = BSB(name, len(name))
    tmpbsb = BSB(bytearray(), 0)  # 处理指针跳转
    curbsb = inbsb  # 初始当前缓冲区指向输入缓冲区

    while curbsb.remaining() > 0:
        ch = curbsb.import_u8()
        if ch == 0:  # 遇到空字符结束
            break
        curbsb.rewind(1)  # 回退一个字节
        """inbsb是输入：当输入是www.example.com时，curbsb是指向inbsb的位置
        然后ch是读取到输入缓冲区的下一个字节，所以要回退一个字节
        取了字节的前两位做压缩指针的标志
        """
        if not isinstance(ch, int):
            break

        if ch & 0xc0:  # 取前2位11 压缩指针标识
            if didpointer > 5:
                return ''
            didpointer += 1

            tpos = curbsb.import_u16()  # 读取压缩指针的位置
            tpos &= 0x3fff  # 计算并保留当前缓冲区指针位置的偏移量
            tmpbsb = BSB(full[tpos:], fulllen - tpos)  # 临时缓冲区指向报文起始位置
            curbsb = tmpbsb  # 指针指向报文起始位置
            continue  # 立即处理新位置数据
            """
            原始报文结构：
                +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
                | 3 | w | w | w | 7 | e | x | a | m | p | l | e | 3 | c | o | m | 0 |
                +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
                  ▲     ▲           ▲           ▲           ▲ 
                  │     │           │           │           └── 第三个组件 "com"
                  │     │           │           │           └── 第二个组件 "example"
                  │     │           └── 第一个组件 "www" 的长度字节
                  │     └── 根组件（空标签，表示域名结束）
                  └── 所有组件的存储结构
            """
        if nbsb.remaining() > 0:
            nbsb.export_u8(ord('.'))  # 给报文添加分隔符
        if not dns_name_element(nbsb, curbsb):
            break
    namelen[0] = nbsb.ptr
    nbsb.export_u8(0)
    return name[:namelen[0]].decode('ascii', 'replace')
    # 字节转成字符串返回


def dns_parser_rr_svcb(data: bytearray, length: int) -> Optional['DnsAnswerSvcbRData']:
    if length < 10:  # 确保数据长度至少包括优先级和初始域名部分
        return None
    svcb_data = DnsAnswerSvcbRData(0)
    svcb_data.fieldValues = DnsAnswerSvcbRDataFieldHead()  # 修复：初始化fieldValues
    bsb = BSB(data, length)
    svcb_data.priority = bsb.read_u16()  # 读取SVCB_RR优先级
    namebuf = bytearray(8000)
    namelen = [len(namebuf)]
    name = dns_name(data, length, bsb, namebuf, namelen)  # 解析域名
    if bsb.error or not name:
        return None  # 修复：直接返回None，避免后续访问svcb_data
    if not namelen[0]:
        svcb_data.dname = "."  # 设置为根域名
        namelen[0] = 1
    else:
        try:
            svcb_data.dname = name.encode('idna').decode('utf-8')  # 转化为IDN
        except UnicodeDecodeError:
            return None
        if not svcb_data.dname:
            return None
    while bsb.remaining() > 4 and not bsb.error:
        key = bsb.read_u16()  # 读取SVCB字段键
        length = bsb.import_u16()  # 读取SVCB字段值长度
        logger.debug("DNSDEBUG: HTTPS key: %s, len: %s", key, length)  # 调试日志输出
        if length > bsb.remaining():
            return svcb_data
        field_value = DnsAnswerSvcbRDataFieldValue(DnsSvcbParamKey.SVCB_PARAM_KEY_ALPN)
        ptr = bsb.work_ptr()
        match key:
            case DnsSvcbParamKey.SVCB_PARAM_KEY_ALPN:
                field_value.key = DnsSvcbParamKey.SVCB_PARAM_KEY_ALPN
                field_value.value = []
                absb = BSB(ptr, length)
                while absb.remaining() > 1:
                    alen = absb.import_u8()
                    data = absb.import_ptr(alen)
                    if data:
                        apln = data.decode('utf-8', errors='ignore')
                        field_value.value.append(apln)
                        logger.debug("DNSDEBUG: HTTPS ALPN: %s", apln)
            case DnsSvcbParamKey.SVCB_PARAM_KEY_PORT:
                if len != 2:
                    break
                port = ((ptr[0] << 8) | ptr[1])
                field_value.key = DnsSvcbParamKey.SVCB_PARAM_KEY_PORT
                field_value.value = port  # 存储端口号
                logger.debug("DNSDEBUG: HTTPS PORT: %s", field_value.value)
            case DnsSvcbParamKey.SVCB_PARAM_KEY_IPV4_HINT:
                if len != 4:
                    break
                field_value.key = DnsSvcbParamKey.SVCB_PARAM_KEY_IPV4_HINT
                field_value.value = []
                absb = BSB(ptr, length)
                while absb.remaining() > 3 and not absb.error:
                    data = absb.import_ptr(4)
                    if data:
                        ip = int.from_bytes(data, byteorder='big')
                        ip_str = "%u.%u.%u.%u" % (ip & 0xff, 
                                               (ip >> 8 & 0xff if ip >= 0 else 0), 
                                               (ip >> 16 & 0xff if ip >= 0 else 0), 
                                               (ip >> 24 & 0xff if ip >= 0 else 0))
                        field_value.value.append(ip_str)
                        try:
                            logger.debug("DNSDEBUG: HTTPS IPV4: %u.%u.%u.%u", ip & 0xff, 
                                      (ip >> 8) & 0xff if ip >= 0 else 0, 
                                      (ip >> 16) & 0xff if ip >= 0 else 0, 
                                      (ip >> 24) & 0xff if ip >= 0 else 0)
                        except Exception as e:
                            logger.debug(f"处理IPV4地址时出错: {e}, 原始值: {ip}")
            case DnsSvcbParamKey.SVCB_PARAM_KEY_IPV6_HINT:
                field_value.key = DnsSvcbParamKey.SVCB_PARAM_KEY_IPV6_HINT
                absb = BSB(ptr, length)
                while absb.remaining() > 15 and not absb.error:  # ipv6地址长度为16字节
                    data = absb.import_ptr(16)
                    if data:
                        ip = ipaddress.IPv6Address(data)
                        field_value.value.append(ip)
                        logger.debug("DNSDEBUG: HTTPS IPV6: %s", ip)
        bsb.skip(length)
        # 修改后的链表插入操作
        if svcb_data.fieldValues.t_count == 0:
            # 空链表初始化
            svcb_data.fieldValues.t_next = field_value
            svcb_data.fieldValues.t_prev = field_value
        else:
            # 连接新旧尾节点
            field_value.t_prev = svcb_data.fieldValues.t_prev
            svcb_data.fieldValues.t_prev.t_next = field_value
            svcb_data.fieldValues.t_prev = field_value
        svcb_data.fieldValues.t_count += 1
    return svcb_data


# 处理DNS域名解析中的主机名转换、验证和存储逻辑
def dns_add_host(session, dns, hosts, field, uni_set, json_len, string, length):
    if length == -1:
        length = len(string)
    # 转换国际化域名
    try:
        host = string[:length].encode('utf-8').decode('idna')
    except UnicodeError:
        host = None
    if uni_set:  # 返回unicode域名
        uni_set[0] = host
    if host:
        hostlen = len(host)
    if not host or not is_valid_utf8(host):  # 域名有效性检查
        # 添加错误标签
        if length > 4 and 'xn--' in string[:4]:
            session.add_tag("bad-punnycode")
        else:
            session.add_tag("bad-hostname")
        return 1
    if hosts is not None:
        key = host.lower()
        # 将有效域名添加到哈希表 去重 高速
        if key not in hosts:
            # 初始化域名
            hosts[key] = {
                'str': host,
                'len': len(host),
                'utf8': True
            }
            json_len[0] += HOST_IP_JSON_LEN
    # 处理包含Punycode前缀（xn--）的原始域名
    if length > 4 and string.startswith('xn--'):
        puny_key = string.lower()
        if dns and dns.punyHosts and puny_key not in dns.punyHosts:
            dns.punyHosts[puny_key] = {
                'str': puny_key,
                'len': length
            }
            if session and field:
                session.run_rules(field, puny_key)
    return 0


def is_valid_utf8(s):
    try:
        s.encode('utf-8').decode('utf-8', 'strict')
        return True
    except UnicodeDecodeError:
        return False


def dns_parser(session: Session, kind: int, data: bytearray, length: int, metadata: dict):
    print(f"[解析器] 收到 {length} 字节数据 | 源IP: {metadata.get('src_ip', '未知')}")

    # Basic validation: DNS header
    if length < 12:
        print(f"无效数据长度: {length}")
        return

    # Parse DNS header
    transaction_id = (data[0] << 8) | data[1]
    flags = (data[2] << 8) | data[3]
    qd_count = (data[4] << 8) | data[5]
    an_count = (data[6] << 8) | data[7]
    ns_count = (data[8] << 8) | data[9]
    ar_count = (data[10] << 8) | data[11]

    # Ensure only one query is present
    if qd_count != 1:
        print("不支持多个查询")
        return

    # Parse the query section
    offset = 12
    qname = []
    while offset < length and data[offset] != 0:
        label_length = data[offset]
        if offset + label_length + 1 >= length:
            print("数据包不完整或格式错误")
            return
        try:
            qname.append(data[offset + 1:offset + 1 + label_length].decode('ascii'))
        except UnicodeDecodeError:
            qname.append(data[offset + 1:offset + 1 + label_length].decode('ascii', errors='replace'))
        offset += label_length + 1
    qname = '.'.join(qname)
    offset += 1  # Skip the null byte

    if offset + 4 > length:
        print("数据包不完整或格式错误")
        return

    qtype = (data[offset] << 8) | data[offset + 1]
    qclass = (data[offset + 2] << 8) | data[offset + 3]
    offset += 4

    # Store the parsed DNS data in the session
    session.fields['dnsField'] = {
        'transaction_id': transaction_id,
        'flags': flags,
        'qname': qname,
        'qtype': qtype,
        'qclass': qclass,
        'an_count': an_count,
        'ns_count': ns_count,
        'ar_count': ar_count
    }

    print(f"查询域名: {qname}")
    print(f"查询类型: {qtype}")
    print(f"查询类: {qclass}")

# DNS-over-TCP协议解析
def dns_tcp_parser(session,uw,data,length,which):
    if uw.length[which] == 0:
        dns_length=((data[0]&0xff)<<8|(data[1]&0xff)) #解析DNS消息长度（大端序）
        if dns_length<18: #DNS头部最小长度校验（12字节头部+至少6字节查询字段）
            session.parser_active=False
            return 0
        #完整数据包处理 当前TCP段包含完整DNS消息
        if dns_length <= length - 2: #检查数据完整性
            dns_parser(session, 0, data[2:2+dns_length], dns_length, {'src_ip': '127.0.0.1'}) #添加metadata参数
            data = data[2+dns_length:]  # 移动数据指针，使用切片操作
            length -= 2 + dns_length #更新剩余长度
            return 1 #处理完成一个完整DNS消息
        #处理分片数据（需要保存部分数据）
        if uw.size[which] == 0:
            uw.size[which] = max(1024,dns_length) # 分配至少1KB或消息长度的空间
            uw.data[which] = bytearray(uw.size[which]) #动态内存分配
        elif uw.size[which] < dns_length:
            # 修复bytearray调用语法，分配一个新的更大的缓冲区
            new_data = bytearray(dns_length)
            # 如果原缓冲区中有数据，则复制到新缓冲区
            if uw.data[which] and uw.pos[which] > 0:
                new_data[:uw.pos[which]] = uw.data[which][:uw.pos[which]]
            uw.data[which] = new_data
            if not uw.data[which]:
                # 内存分配失败处理
                session.parser_active=False
                return 0
            uw.size[which]=dns_length # 更新缓冲区尺寸
        uw.data[which][:length - 2] = data[2:]  # 将data从第2字节开始复制到缓冲区
        uw.length[which]=dns_length # 设置预期总长度
        uw.pos[which]=length - 2 # 记录已接收数据位置
        return 0
    else:
        rem = uw.length[which] - uw.pos[which] #计算剩余需要的数据量
        if rem <= length:
            uw.data[which][uw.pos[which]:uw.pos[which]+rem] = data[:rem]  # 拼装完整消息
            length -= rem # 更新剩余长度
            data = data[rem:] # 移动数据指针，使用切片操作
            dns_parser(session, 0, uw.data[which], uw.length[which], {'src_ip': '127.0.0.1'}) #添加metadata参数
            uw.length[which] = 0 # 重置分片状态
            return 1 # 处理完成一个完整DNS消息
        else:
            uw.data[which][uw.pos[which]:uw.pos[which] +length] = data[:length]#追加部分数据
            uw.pos[which] += length # 更新已接收位置
            return 0

# DNS-over-TCP流量处理
def dns_tcp_classify(session,uw,data,length,which):
    # 检查目标端口是否为53且会话尚未标记DNS协议
    if session.port2 == 53 and "dns" not in session.protocols:
        session.protocols.add("dns")  # 添加协议标记
        info = DnsInfo()
        session.register_parser(dns_tcp_parser, info, dns_free) # 注册TCP解析器

# DNS-over-UDP流量处理
def dns_udp_parser(session,uw,data,length,which):
    #仅处理未关联用户数据或非标准端口的UDP流量
    if uw == 0 or (session.port1 != 53 and session.port2 != 53):
        dns_parser(session, uw, data, length, {'src_ip': '127.0.0.1'}) #添加metadata参数
    return 0

# DNS over UDP流量注册解析器
def dns_udp_classify(session, data, length, which, uw):
    session.register_parser(dns_udp_parser, uw, 0)
    session.add_protocol("dns")


class JsonSerializer:
    @staticmethod
    def save_string_head(jbsb, head_list, field_name):
        """处理链表类型数据结构"""
        if len(head_list) == 0:
            return

        jbsb.export_cstr(f'"{field_name}":[')
        for string in head_list:
            # 安全编码字符串并添加
            jbsb.export_sprintf("%s,", json.dumps(string.str, ensure_ascii=False))

        # 修正JSON格式：移除最后一个逗号，闭合数组
        jbsb.rewind(1)
        jbsb.export_cstr("],")

    @staticmethod
    def save_string_hash(jbsb, hash_dict, field_name):
        """处理哈希表类型数据结构"""
        count = len(hash_dict)
        if count == 0:
            return

        jbsb.export_sprintf("\"%sCnt\":%d,", field_name, count)
        jbsb.export_sprintf("\"%s\":[", field_name)

        # 遍历并清空哈希表
        for key, string in hash_dict.items():
            # 安全编码并添加
            jbsb.export_sprintf("%s,", json.dumps(string.get('str', ''), ensure_ascii=False))
            
        # 修正JSON格式：移除最后一个逗号，闭合数组
        jbsb.rewind(1)
        jbsb.export_cstr("],")

# IP地址转换为JSON格式
def dns_save_ip_ghash(jbsb,session:Session,ip_dict,key):
    # # 生成IP计数
    count = len(ip_dict)
    if count == 0:
        return
    MAX_IPS = 50
    
    # 生成IP列表数组（如"ip":["1.1.1.1","2606:4700::1111"]）
    jbsb.export_cstr(f'"{key}Ct":{count},"{key}":[')
    proceseed = 0
    for ip_bytes in list(ip_dict.keys())[:MAX_IPS]:
        #转换IP格式
        try:
            ip_obj=ipaddress.ip_address(ip_bytes)
            if ip_obj.version == 6 and ip_obj.ipv4_mapped:
                ip_str = str(ip_obj.ipv4_mapped)
            else:
                ip_str = str(ip_obj)
        except:
            ip_str = "invalid_ip"

        jbsb.export_cstr(f'"{ip_str}",')
        
        proceseed += 1
        if proceseed >= MAX_IPS:
            break

    # 修正末尾逗号
    if jbsb.ptr > 0:
        jbsb.rewind(1)  # 回退一个字符（逗号）
        jbsb.export_cstr("]")
    else:
        jbsb.export_cstr("]")

    # 清空原始字典
    ip_dict.clear()

# DNS解析结果转换为结构化的JSON格式
def dns_save(jbsb,obj:FieldObject,session:Session):
    if obj.objcet is None: #// 空对象检查（防御性编程）
        return
    ipAAAA=[]
    Dns.dns=obj.objcet
    jbsb.export_cstr("{") # 开始生成JSON对象，使用export_cstr代替export_u8
    
    # 使用正确的属性名访问
    if Dns.dns.query and hasattr(Dns.dns.query, 'hostname'):
        jbsb.export_sprintf("\"queryHost\":\"%s\",", Dns.dns.query.hostname) # 查询域名
    
    if Dns.dns.query and hasattr(Dns.dns.query, 'opcode'):
        jbsb.export_sprintf("\"opcode\":\"%s\",", Dns.dns.query.opcode) # DNS操作码
    
    if Dns.dns.query and hasattr(Dns.dns.query, 'class_id'):
        jbsb.export_sprintf("\"qc\":\"%d\",", Dns.dns.query.class_id) # 查询类别ID
    
    if Dns.dns.query and hasattr(Dns.dns.query, 'type_id'):
        jbsb.export_sprintf("\"qt\":\"%d\",", Dns.dns.query.type_id) # 查询类型ID

    if Dns.dns.hosts:
        # 输出为 "host":["example.com","test.com"]
        JsonSerializer.save_string_hash(jbsb,Dns.dns.hosts,"host")
    if Dns.dns.nsHosts:
        # 输出为 "nameserverHost":["ns1.example"]
        JsonSerializer.save_string_hash(jbsb,Dns.dns.nsHosts,"nameserverHost")
    if Dns.dns.mxHosts:
        # 输出为 "mailserverHost":["mail.example"]
        JsonSerializer.save_string_hash(jbsb,Dns.dns.mxHosts,"mailserverHost")
    if Dns.dns.punyHosts:
        # 输出为 "puny":["xn--example.com"]
        JsonSerializer.save_string_hash(jbsb,Dns.dns.punyHosts,"puny")
    if Dns.dns.ips and len(Dns.dns.ips) > 0:
        dns_save_ip_ghash(jbsb, session, Dns.dns.ips, "ip")  # 输出为 "ip": ["1.1.1.1"]
        Dns.dns.ips = {}  # 置空防止重复处理
    if Dns.dns.nsIPs and len(Dns.dns.nsIPs) > 0:
        dns_save_ip_ghash(jbsb, session, Dns.dns.nsIPs, "nameserverIP") # // 输出为 "nameserverIp": ["9.9.9.9"]
        Dns.dns.nsIPs = {}
    if Dns.dns.mxIPs and len(Dns.dns.mxIPs) > 0:
        dns_save_ip_ghash(jbsb, session, Dns.dns.mxIPs, "mailserverIP") # // 输出为 "mailserverIp":
        Dns.dns.mxIPs = {}
    if Dns.dns.headerFlags:
        jbsb.export_cstr("\"headerFlags\": [")
        #遍历DNS头部的7个标志位（从最高位QR到最低位RA）
        for i in range(0,7):
            # 检查第(6-i)位是否置位（例如i=0时检查第6位QR标志）
            if Dns.dns.headerFlags & (1 << (6 - i)):
                # 添加对应的标志字符串（如QR/AA/TC等）
                jbsb.export_sprintf("\"%s\",", flagsStr[i])
        # 修正JSON格式：移除最后一个逗号，闭合数组
        jbsb.rewind(1)
        jbsb.export_cstr("],")

    #处理DNS响应状态码和应答记录
    if Dns.dns.rcode_id != -1:
        #  序列化响应状态（如NOERROR / SERVFAIL）
        jbsb.export_sprintf("\"status\":\"%s\",", Dns.dns.rcode)
        if dnsOutputAnswers: #配置允许输出应答记录时
            #生成应答总数字段（如"answersCnt":3）
            if Dns.dns.answers and hasattr(Dns.dns.answers, 'get_count'):
                answers_count = Dns.dns.answers.get_count()
                jbsb.export_sprintf("\"answersCnt\":%d,", answers_count)
                if answers_count > 0:
                    jbsb.export_cstr("\"answers\":[") # 开始应答数组
                    #遍历DNS应答记录
                    for answer in Dns.dns.answers:
                        jbsb.export_cstr("{") # 开始应答对象
                        match answer.type_id:
                            case DnsType.DNS_RR_A:
                                #处理A记录（IPv4地址）,将 IP 地址信息以 JSON 键值对形式写入 BSB 缓冲区
                                try:
                                    if answer.ipA is not None and isinstance(answer.ipA, int) and answer.ipA >= 0:
                                        ip_str = f"\"ipA\":\"{(answer.ipA >> 24) & 0xff}.{(answer.ipA >> 16) & 0xff}.{(answer.ipA >> 8) & 0xff}.{answer.ipA & 0xff}\","
                                        jbsb.export_sprintf(ip_str)
                                    else:
                                        # 如果IP地址为负数或None，使用安全格式
                                        jbsb.export_sprintf("\"ip\":\"0.0.0.0\",")
                                        logger.debug(f"无效的IPv4地址值: {answer.ipA}")
                                except Exception as e:
                                    # 捕获所有异常并提供安全输出
                                    jbsb.export_sprintf("\"ip\":\"0.0.0.0\",")
                                    logger.debug(f"处理IPv4地址时出错: {e}")
                                break
                            case DnsType.DNS_RR_NS:
                                jbsb.export_sprintf("\"nameserver\":\"%s\",", answer.nsdname)
                                break
                            case DnsType.DNS_RR_CNAME:
                                jbsb.export_sprintf("\"cname\":\"%s\",", answer.cname)
                                break
                            case DnsType.DNS_RR_MX:
                                jbsb.export_sprintf("\"priority\":%u,\"mx\":\"%s\",", answer.mx.preference,answer.mx.exchange)
                                break
                            case DnsType.DNS_RR_AAAA:
                                #处理AAAA记录（IPv6地址）
                                if isinstance(answer.ipAAAA, ipaddress.IPv6Address):
                                    if answer.ipAAAA.ipv4_mapped:
                                        # 提取内嵌的 IPv4 地址并格式化为点分十进制
                                        ipv4_str = str(answer.ipAAAA.ipv4_mapped)
                                        jbsb.export_sprintf("\"ip\":\"%s\",", ipv4_str)
                                    else:
                                        # 纯 IPv6 地址直接转换为字符串
                                        ipv6_str = str(answer.ipAAAA)
                                        jbsb.export_sprintf("\"ip\":\"%s\",", ipv6_str)
                                break
                            case DnsType.DNS_RR_TXT:
                                if answer.txt:
                                    # 解码字节数据并转义特殊字符
                                    txt_str = answer.txt.decode('utf-8', errors='replace').strip()
                                    jbsb.export_sprintf("\"txt\":%s,", json.dumps(txt_str))
                                break
                            case DnsType.DNS_RR_HTTPS:
                                # 解码原始值并执行URL安全编码
                                value_str = answer.caa.value.decode('utf-8', errors='replace').strip()
                                encoded_value = urllib.parse.quote(value_str, safe='')
                                jbsb.export_sprintf("\"caa\":\"CAA %d %s %s\",",
                                                    answer.caa.flags, answer.caa.tag, encoded_value)
                                jbsb.export_sprintf("\",")
                                break
                        if answer.class_:
                            jbsb.export_sprintf("\"class\":\"%s\",", answer.class_) #资源记录类（如IN）
                        if answer.type:
                            jbsb.export_sprintf("\"type\":\"%s\",", answer.type) # 资源记录类型（如A/AAAA）
                        jbsb.export_sprintf("\"ttl\":%u,", answer.ttl)
                        jbsb.export_sprintf("\"name\":\"%s\",", answer.name) # 域名
                        if answer.name and answer.name != root:
                            answer.name = None
                        jbsb.rewind(1)
                        jbsb.export_cstr("}") # 使用export_cstr代替export_u8
                        jbsb.export_cstr(",") # 使用export_cstr代替export_u8
                    jbsb.rewind(1)
                    jbsb.export_cstr("}")  # 闭合JSON对象，使用export_cstr

# 高效存储和检索DNS记录
def dns_hash(*args):
    from .singleton import field_manager
    # Implementation...

# 收集DNS会话中的所有相关主机名
def dns_getcb_host(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    host_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    # 直接访问FieldObject的属性
    try:
        # 如果是标准对象集合
        if hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 添加查询主机名
                if dns.query and dns.query.hostname:
                    host_set.add(dns.query.hostname)

                # 添加各类记录中的主机名
                for hash_table in [dns.hosts, dns.nsHosts, dns.mxHosts]:
                    if hash_table:
                        host_set.update(hash_table.keys())
        # 如果是直接存储的简单字典数据
        elif hasattr(dns_data, 'qname') and dns_data.qname:
            host_set.add(dns_data.qname)
        # 尝试作为字典访问
        elif isinstance(dns_data, dict) and 'qname' in dns_data:
            host_set.add(dns_data['qname'])
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return host_set

# 收集会话中所有邮件服务器主机名
def dns_getcb_host_mailserver(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    mail_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是FieldObject对象
        if hasattr(dns_data, 'object') and dns_data.object:
            dns = dns_data.object
            # 处理MX记录中的主机名
            if hasattr(dns, 'mxHosts') and dns.mxHosts:
                mail_set.update(dns.mxHosts.keys())
        # 如果是标准对象集合
        elif hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 仅处理MX记录中的主机名
                if hasattr(dns, 'mxHosts') and dns.mxHosts:
                    mail_set.update(dns.mxHosts.keys())
        # 直接访问字典
        elif isinstance(dns_data, dict) and 'mail_servers' in dns_data:
            mail_servers = dns_data.get('mail_servers')
            if isinstance(mail_servers, list):
                mail_set.update(mail_servers)
            elif isinstance(mail_servers, dict):
                mail_set.update(mail_servers.keys())
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return mail_set

"""收集会话中所有权威名称服务器主机名"""
def dns_getcb_host_nameserver(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    nameserver_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是FieldObject对象
        if hasattr(dns_data, 'object') and dns_data.object:
            dns = dns_data.object
            # 处理NS记录中的主机名
            if hasattr(dns, 'nsHosts') and dns.nsHosts:
                nameserver_set.update(dns.nsHosts.keys())
        # 如果是标准对象集合
        elif hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 仅处理NS记录中的主机名
                if hasattr(dns, 'nsHosts') and dns.nsHosts:
                    nameserver_set.update(dns.nsHosts.keys())
        # 直接访问字典
        elif isinstance(dns_data, dict) and 'name_servers' in dns_data:
            name_servers = dns_data.get('name_servers')
            if isinstance(name_servers, list):
                nameserver_set.update(name_servers)
            elif isinstance(name_servers, dict):
                nameserver_set.update(name_servers.keys())
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return nameserver_set

"""收集会话中所有Punycode编码域名"""
def dns_getcb_puny(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    puny_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是FieldObject对象
        if hasattr(dns_data, 'object') and dns_data.object:
            dns = dns_data.object
            # 处理Punycode编码域名
            if hasattr(dns, 'punyHosts') and dns.punyHosts:
                puny_set.update(dns.punyHosts.keys())
        # 如果是标准对象集合
        elif hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 仅处理Punycode编码域名
                if hasattr(dns, 'punyHosts') and dns.punyHosts:
                    puny_set.update(dns.punyHosts.keys())
        # 直接访问字典
        elif isinstance(dns_data, dict) and 'puny_hosts' in dns_data:
            puny_hosts = dns_data.get('puny_hosts')
            if isinstance(puny_hosts, list):
                puny_set.update(puny_hosts)
            elif isinstance(puny_hosts, dict):
                puny_set.update(puny_hosts.keys())
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return puny_set

"""收集会话中所有DNS响应状态码"""
def dns_getcb_status(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    status_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是FieldObject对象
        if hasattr(dns_data, 'object') and dns_data.object:
            dns = dns_data.object
            # 收集响应状态码（如 NOERROR、SERVFAIL）
            if hasattr(dns, 'rcode') and dns.rcode:
                status_set.add(dns.rcode)
        # 如果是标准对象集合
        elif hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 收集响应状态码（如 NOERROR、SERVFAIL）
                if hasattr(dns, 'rcode') and dns.rcode:
                    status_set.add(dns.rcode)
        # 直接访问字典
        elif isinstance(dns_data, dict) and 'status' in dns_data:
            status = dns_data.get('status')
            if status:
                status_set.add(status)
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return status_set

"""收集会话中所有DNS操作码"""
def dns_getcb_opcode(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    opcode_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是FieldObject对象
        if hasattr(dns_data, 'object') and dns_data.object:
            dns = dns_data.object
            # 收集操作码
            if hasattr(dns, 'query') and dns.query and hasattr(dns.query, 'opcode') and dns.query.opcode:
                opcode_set.add(dns.query.opcode)
        # 如果是标准对象集合
        elif hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 收集操作码（如 QUERY、STATUS）
                if hasattr(dns, 'query') and dns.query and hasattr(dns.query, 'opcode') and dns.query.opcode:
                    opcode_set.add(dns.query.opcode)
        # 直接访问字典
        elif isinstance(dns_data, dict) and 'opcode' in dns_data:
            opcode = dns_data.get('opcode')
            if opcode:
                opcode_set.add(opcode)
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return opcode_set

"""收集会话中所有DNS查询类型"""
def dns_getcb_query_type(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    query_type_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是标准对象集合
        if hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 收集查询类型（如 A、AAAA、MX）
                if dns.query and dns.query.type:
                    query_type_set.add(dns.query.type)
        # 尝试属性访问
        elif hasattr(dns_data, 'qtype'):
            qtype = dns_data.qtype
            if isinstance(qtype, int):
                # 尝试将整数转换为更友好的表示
                if qtype == 1:
                    query_type_set.add('A')
                elif qtype == 28:
                    query_type_set.add('AAAA')
                else:
                    query_type_set.add(str(qtype))
            elif qtype:
                query_type_set.add(str(qtype))
        # 尝试字典访问
        elif isinstance(dns_data, dict) and 'qtype' in dns_data:
            qtype = dns_data['qtype']
            if isinstance(qtype, int):
                if qtype == 1:
                    query_type_set.add('A')
                elif qtype == 28:
                    query_type_set.add('AAAA')
                else:
                    query_type_set.add(str(qtype))
            elif qtype:
                query_type_set.add(str(qtype))
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return query_type_set

"""收集会话中所有DNS查询类"""
def dns_getcb_query_class(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    query_class_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是标准对象集合
        if hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 收集查询类（如 IN、CH、HS）
                if dns.query and dns.query.class_:
                    query_class_set.add(dns.query.class_)
        # 尝试属性访问
        elif hasattr(dns_data, 'qclass'):
            qclass = dns_data.qclass
            if isinstance(qclass, int):
                # 尝试将整数转换为更友好的表示
                if qclass == 1:
                    query_class_set.add('IN')
                else:
                    query_class_set.add(str(qclass))
            elif qclass:
                query_class_set.add(str(qclass))
        # 尝试字典访问
        elif isinstance(dns_data, dict) and 'qclass' in dns_data:
            qclass = dns_data['qclass']
            if isinstance(qclass, int):
                if qclass == 1:
                    query_class_set.add('IN')
                else:
                    query_class_set.add(str(qclass))
            elif qclass:
                query_class_set.add(str(qclass))
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return query_class_set

"""收集会话中所有DNS查询域名"""
def dns_getcb_query_host(session: Session) -> set:
    if not session.fields.get('dnsField'):
        return set()

    host_set = set()

    # 遍历所有DNS对象
    dns_data = session.fields.get('dnsField')
    
    try:
        # 如果是标准对象集合
        if hasattr(dns_data, 'objects') and dns_data.objects:
            for dns_obj in dns_data.objects.values():
                dns = dns_obj.object
                # 收集查询域名（保留大小写敏感）
                if dns.query and dns.query.hostname:
                    host_set.add(dns.query.hostname)
        # 尝试属性访问
        elif hasattr(dns_data, 'qname') and dns_data.qname:
            host_set.add(dns_data.qname)
        # 尝试字典访问
        elif isinstance(dns_data, dict) and 'qname' in dns_data:
            host_set.add(dns_data['qname'])
    except (AttributeError, TypeError):
        # 捕获任何访问错误
        pass

    return host_set

def field_object_register(name, description, save_func, hash_func,cmp_func):
    """模拟字段对象注册"""
    field_registry[name] = {
        'save': save_func,
        'hash': hash_func,
        'cmp': cmp_func,
        'description': description
    }
    return name  # 返回字段名称作为标识符
