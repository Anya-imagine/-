import ipaddress
import socket
import struct
from typing import Optional
from urllib.parse import unquote
import enum

from _socket import inet_pton, ntohs

from analyzers import BSB
from analyzers.base import FieldObject, Session as BaseSession, ParserInfo


class SessionTypes(enum.Enum):
    SESSION_TCP = 0
    SESSION_UDP = 1
    SESSION_ICMP = 2
    SESSION_SCTP = 3
    SESSION_ESP = 4
    SESSION_OTHER = 5
    SESSION_MAX = 6


class SessionIdTracking(enum.Enum):
    TRACKING_NONE = 0
    TRACKING_VLAN = 1
    TRACKING_VNI = 2


protocol_field = 0
SESSION_ID4_LEN = 40
SESSION_ID6_LEN = 40
session_id_tracking = SessionIdTracking.TRACKING_NONE


class Session(BaseSession):
    def __init__(self):
        super().__init__()
        self.parser_active = True
        self.tags = []
        self.rules = []
        self.protocols = set()
        self.parsers = []  # 解析器注册表
        self.max_fields = 0
        self.mid_save = 0
        self.headers = {'request': {}, 'response': {}}
        self.cookies = {}
        self.params = {}
        self.config = {'parse_cookie_value': True}
        self.fields = {
            "dnsField": FieldObject(ohash={
                "default_key": "8.8.8.8"
            })
        }
        self.addr1 = ipaddress.IPv6Address('::')
        self.addr2 = ipaddress.IPv6Address('::')
        self.port1 = 0
        self.port2 = 0
        self.parser_num = 0
        self.parser_info = None
        self.parser_len = 0
        self.ip_protocol = 0
        self.thread = 0
        self.databytes = 0
        self.session_id = 0
        self.is_session_v6 = False  # IPv6会话标志

    def get_readable_fields(self):
        """将字段转换为可读的JSON格式"""
        result = {}
        
        # 转换基本字段
        for field_name, field_value in self.fields.items():
            if isinstance(field_value, FieldObject):
                try:
                    result[field_name] = field_value.ohash
                except:
                    result[field_name] = str(field_value.ohash)
            else:
                result[field_name] = str(field_value)
        
        # 添加其他重要属性，安全地处理可能为None的值
        result.update({
            "tags": [str(tag) for tag in self.tags] if self.tags else [],
            "protocols": [str(proto) for proto in self.protocols] if self.protocols else [],
            "headers": {
                "request": {str(k): str(v) for k, v in self.headers['request'].items()} if 'request' in self.headers else {},
                "response": {str(k): str(v) for k, v in self.headers['response'].items()} if 'response' in self.headers else {}
            },
            "cookies": {str(k): str(v) for k, v in self.cookies.items()} if self.cookies else {},
            "params": {str(k): str(v) for k, v in self.params.items()} if self.params else {},
            "src_ip": str(self.addr1) if self.addr1 else "::",
            "dst_ip": str(self.addr2) if self.addr2 else "::",
            "src_port": int(self.port1) if self.port1 is not None else 0,
            "dst_port": int(self.port2) if self.port2 is not None else 0,
            "ip_protocol": int(self.ip_protocol) if self.ip_protocol is not None else 0,
            "is_ipv6": bool(self.is_session_v6) if self.is_session_v6 is not None else False,
            "session_id": str(self.session_id) if self.session_id else None,
            "parser_num": int(self.parser_num) if self.parser_num is not None else 0,
            "parser_len": int(self.parser_len) if self.parser_len is not None else 0,
            "thread": int(self.thread) if self.thread is not None else 0,
            "databytes": int(self.databytes) if isinstance(self.databytes, (int, float, str)) else 0
        })
        
        return result

    def add_tag(self, tag):
        self.tags.append(tag)

    def add_rule(self, rule_func):
        self.rules.append(rule_func)

    def run_rules(self, field, value):
        for rule in self.rules:
            rule(field, value)

    def add_protocol(self, protocol):
        self.protocols.add(protocol)

    def register_parser(self, parser, info, cleanup):
        self.parsers.append((parser, info, cleanup))

    def add_value(self, field_type, name, value):
        if name not in self.fields:
            self.fields[name] = []
        self.fields[name].append((field_type, value))

    def has_protocol(self, protocol):
        return protocol in self.protocols

    def pretty_string(self, buf, length):
        try:
            return buf[:length].decode('utf-8', errors='replace')
        except:
            return str(buf[:length])

    def is_session_v6(session):
        return session.session_id[0] == SESSION_ID6_LEN


def session_id4(self, buf, addr1, port1, addr2, port2, vlan, vni):
    buf[0] = SESSION_ID4_LEN
    collapse_table = {}
    if addr1 < addr2:
        buf[1:1 + 4] = buf[0:4]  # addr1
        buf[5:5 + 2] = buf[4:6]  # port1
        buf[7:7 + 4] = buf[6:10]  # addr2
        buf[11:11 + 2] = buf[10:12]  # port2
    elif addr1 > addr2:
        buf[1:1 + 4] = buf[0:4]  # addr2
        buf[5:5 + 2] = buf[4:6]  # port2
        buf[7:7 + 4] = buf[6:10]  # addr1
        buf[11:11 + 2] = buf[10:12]  # port1
    elif ntohs(port1) < ntohs(port2):
        buf[1:1 + 4] = buf[0:4]  # addr1
        buf[5:5 + 2] = buf[4:6]  # port1
        buf[7:7 + 4] = buf[6:10]  # addr2
        buf[11:11 + 2] = buf[10:12]  # port2
    else:
        buf[1:1 + 4] = buf[0:4]  # addr2
        buf[5:5 + 2] = buf[4:6]  # port2
        buf[7:7 + 4] = buf[6:10]  # addr1
        buf[11:11 + 2] = buf[10:12]  # port1

    match session_id_tracking:
        case SessionIdTracking.TRACKING_NONE:
            buf[13:16] = b'\x00\x00\x00'
        case SessionIdTracking.TRACKING_VLAN:
            buf[13] = 0
            if collapse_table:
                value = collapse_table.get(vlan)
                if value:
                    value -= 1
                    buf[14:14 + 2] = value.to_bytes(2, 'big')
            else:
                buf[14:16] = vni.to_bytes(2, 'big')
        case SessionIdTracking.TRACKING_VNI:
            if collapse_table:
                value = collapse_table.get(vni)
                if value:
                    value -= 1
                    buf[13:13 + 3] = value.to_bytes(3, 'big')
            else:
                buf[13:13 + 3] = vni.to_bytes(3, 'big')


def session_id6(self, buf, addr1, port1, addr2, port2, vlan, vni):
    buf[0] = SESSION_ID6_LEN
    collapse_table = {}
    if addr1 < addr2:
        cmp = -1
    elif addr1 > addr2:
        cmp = 1
    else:
        cmp = 0
    addr1 = inet_pton(socket.AF_INET6, addr1)
    addr2 = inet_pton(socket.AF_INET6, addr2)

    data = struct.pack(f"!16sH16sH", addr1, port1, addr2, port2)

    if cmp < 0:
        buf[1:1 + 16] = data[0:16]  # addr1
        buf[17:17 + 2] = data[16:18]  # port1
        buf[19:19 + 16] = data[18:34]  # addr2
        buf[35:35 + 2] = data[34:36]  # port2
    elif cmp > 0:
        buf[1:1 + 16] = data[0:16]  # addr1
        buf[17:17 + 2] = data[16:18]  # port1
        buf[19:19 + 16] = data[18:34]  # addr2
        buf[35:35 + 2] = data[34:36]  # port2
    elif ntohs(port1) < ntohs(port2):
        buf[1:1 + 16] = data[0:16]  # addr1
        buf[17:17 + 2] = data[16:18]  # port1
        buf[19:19 + 16] = data[18:34]  # addr2
        buf[35:35 + 2] = data[34:36]  # port2
    else:
        buf[1:1 + 16] = data[0:16]  # addr1
        buf[17:17 + 2] = data[16:18]  # port1
        buf[19:19 + 16] = data[18:34]  # addr2
        buf[35:35 + 2] = data[34:36]  # port2

    match session_id_tracking:
        case SessionIdTracking.TRACKING_NONE:
            buf[37:40] = b'\x00\x00\x00'
        case SessionIdTracking.TRACKING_VLAN:
            buf[37] = 0
            if collapse_table:
                value = collapse_table.get(vlan)
                if value:
                    value -= 1
                    buf[38:38 + 2] = value.to_bytes(2, 'big')
            else:
                buf[38:40] = vni.to_bytes(2, 'big')
        case SessionIdTracking.TRACKING_VNI:
            if collapse_table:
                value = collapse_table.get(vni)
                if value:
                    value -= 1
                    buf[37:37 + 3] = value.to_bytes(3, 'big')
            else:
                buf[37:37 + 3] = vni.to_bytes(3, 'big')


def session_hash(self, key):
    p = key + key[0]
    h = 0
    while p < self.end:
        h = (h + p) * 0xc6a5a793
        h ^= h >> 16
        p += 1
    h ^= self.hash_salt
    return h
