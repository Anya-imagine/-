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
        FIELD_FLAG_IPPRE,
        FIELD_FLAG_FAKE,
        Session
    )
except ImportError:
    from analyzers.imports import (
        FieldType,
        FIELD_FLAG_IPPRE,
        FIELD_FLAG_FAKE,
        Session
    )

import struct

from analyzers.session import Session
from analyzers.field import field_manager, FieldType, FIELD_FLAG_IPPRE, FIELD_FLAG_FAKE
from analyzers.parsers import parsers_classify_tcp, parsers_unregister, parsers_register, \
    parsers_classifier_register_tcp, API_VERSION


class SocksInfo:
    def __init__(self):
        self.user = None
        self.host = None
        self.ip = 0
        self.port = 0
        self.user_len = 0
        self.host_len = 0
        self.which = 0
        self.state4 = 0
        self.state5 = []


ip_field = 0
port_field = 0
user_field = 0
host_field = 0

SOCKS4_STATE_REPLY = 0
SOCKS4_STATE_DATA = 1


def socks4_parser(session: Session, uw, data, remaining, which):
    socks = uw
    if socks.state4 == SOCKS4_STATE_REPLY:
        if which == socks.which:
            return 0
        if remaining >= 8 and data[0] == 0 and data[1] >= 0x5a and data[1] <= 0x5d:
            if socks.ip:
                field_manager.field_ip4_add(ip_field, session, socks.ip)
            field_manager.field_int_add(port_field, session, socks.ip)
            session.add_protocol("socks")

            if socks.user:
                socks.user = 0

            if socks.host:
                socks.host = 0

            parsers_classify_tcp(session, data + 8, remaining - 8, which)
            socks.state4 = SOCKS4_STATE_DATA
            return 8
    elif socks.state4 == SOCKS4_STATE_DATA:
        parsers_classify_tcp(session, data, remaining, which)
        parsers_unregister(session, uw)

    return 0


SOCKS5_STATE_VER_REQUEST = 1
SOCKS5_STATE_VER_REPLY = 2
SOCKS5_STATE_USER_REQUEST = 3
SOCKS5_STATE_USER_REPLY = 4
SOCKS5_STATE_CONN_REQUEST = 5
SOCKS5_STATE_CONN_REPLY = 6
SOCKS5_STATE_CONN_DATA = 7


def socks5_parser(session: Session, uw, data, remaining, which):
    socks = uw
    consumed = 0
    
    state = socks.state5[which]
    
    if state == SOCKS5_STATE_VER_REQUEST:
        if remaining < 3:
            parsers_unregister(session, uw)
            return 0
        if data[2] == 0:
            socks.state5[which] = SOCKS5_STATE_CONN_REQUEST
        else:
            socks.state5[which] = SOCKS5_STATE_USER_REQUEST

        socks.state5[(which + 1) % 2] = SOCKS5_STATE_VER_REPLY
        
    elif state == SOCKS5_STATE_VER_REPLY:
        if remaining != 2 or data[0] != 5 or data[1] > 2:
            parsers_unregister(session, uw)
            return 0
        session.add_protocol("socks")
        if socks.state5[socks.which] == SOCKS5_STATE_CONN_DATA:
            # Other side of connection already in data state
            socks.state5[socks.which] = SOCKS5_STATE_CONN_REPLY
        elif data[1] == 0:
            socks.state5[socks.which] = SOCKS5_STATE_CONN_REQUEST
            socks.state5[which] = SOCKS5_STATE_CONN_REPLY
        elif data[1] == 2:
            socks.state5[socks.which] = SOCKS5_STATE_USER_REQUEST
            socks.state5[which] = SOCKS5_STATE_USER_REPLY
        else:
            parsers_unregister(session, uw)

        return 2
        
    elif state == SOCKS5_STATE_USER_REQUEST:
        if remaining < 2 or (3 + data[1] > remaining) or (2 + data[1] + 1 + data[data[1] + 2] > remaining):
            parsers_unregister(session, uw)
            return 0
        field_manager.field_str_add(user_field, session, data + 2, data[1], True)
        session.add_tag("socks:password")
        socks.state5[socks.which] = SOCKS5_STATE_CONN_REQUEST
        return data[1] + 1 + data[data[1] + 2]
        
    elif state == SOCKS5_STATE_USER_REPLY:
        socks.state5[which] = SOCKS5_STATE_CONN_REPLY
        return 2
        
    elif state == SOCKS5_STATE_CONN_REQUEST:
        if remaining < 6 or data[0] != 5 or data[1] != 1 or data[2] != 0:
            parsers_unregister(session, uw)
            return 0

        socks.state5[which] = SOCKS5_STATE_CONN_DATA
        if data[3] == 1:  # IPv4
            if remaining < 10:
                parsers_unregister(session, uw)
                return 0
            socks.port = (data[8] & 0xff) << 8 | (data[9] & 0xff)
            socks.ip = struct.unpack("!I", data[4:8])[0]  # 处理IPv4地址（大端序）
            field_manager.field_ip4_add(ip_field, session, socks.ip)
            field_manager.field_int_add(port_field, session, socks.port)
            consumed = 4 + 4 + 2
        elif data[3] == 3:  # Domain name
            if remaining < data[4] + 7:
                parsers_unregister(session, uw)
                return 0
            socks.port = data[5 + data[4] & 0xff] << 8 | data[6 + data[4] & 0xff]

            field_manager.field_str_add_lower(host_field, session, data + 5, data[4])
            field_manager.field_int_add(port_field, session, socks.port)
        elif data[3] == 4:  # IPv6
            if remaining < 22:
                parsers_unregister(session, uw)
                return 0
            consumed = 4 + 16 + 2
        else:
            return 0

        parsers_classify_tcp(session, data + consumed, remaining - consumed, which)
        return consumed

    elif state == SOCKS5_STATE_CONN_REPLY:
        if remaining < 6:
            parsers_unregister(session, uw)
            return 0

        socks.state5[which] = SOCKS5_STATE_CONN_DATA
        if data[3] == 1:
            consumed = 4 + 4 + 2
        elif data[3] == 3:
            consumed = 4 + 1 + data[4] + 2
        elif data[3] == 4:
            consumed = 4 + 16 + 2
        else:
            return 0

        if remaining < consumed:
            parsers_unregister(session, uw)
            return 0
        parsers_classify_tcp(session, data + consumed, remaining - consumed, which)
        return consumed
        
    elif state == SOCKS5_STATE_CONN_DATA:
        parsers_classify_tcp(session, data + consumed, remaining - consumed, which)
        parsers_unregister(session, uw)
        return 0
        
    else:
        parsers_unregister(session, uw)

    return 0


def socks4_classify(session: Session, data, length, which, uw):
    if length < 8 or data[length - 1] != 0:
        return
    socks = SocksInfo()
    socks.which = which
    socks.port = (data[2] & 0xff) << 8 | (data[3] & 0xff)
    if data[4] == 0 and data[5] == 0 and data[6] == 0 and data[7] == 0:
        socks.ip = 0
    else:
        socks.ip = struct.unpack("!I", data[4:8])[0]

    i = 8
    while i < length and data[i] != 0:
        socks.user = data[8:i].decode('latin1', errors='ignore').rstrip('\x00')
        socks.user_len = i - 8
        i += 1
    if socks.ip == 0:
        i += 1
        start = i
        while i < length and data[i] != 0:
            i += 1
        if i > start and i != length:
            socks.host_len = i - start
            socks.host = data[start:i].decode('latin1', errors='ignore').rstrip('\x00')

    parsers_register(session, socks4_parser, socks, i - start)


def socks5_classify(session: Session, data, length, which, uw):
    if (3 <= length <= 5) and data[1] == length - 2 and data[2] <= 3:
        socks = SocksInfo()
        socks.which = which
        socks.state5[which] = SOCKS5_STATE_VER_REQUEST
        parsers_register(session, socks5_parser, socks)
        return
    return


def parser_init():
    from analyzers.parsers import API_VERSION
    
    ip_field = field_manager.field_define("socks", "ip",
                                          "ip.socks", "IP", "socks.ip",
                                          "SOCKS destination IP",
                                          FieldType.FIELD_TYPE_IP_GHASH,
                                          FIELD_FLAG_IPPRE,
                                          None)

    host_field = field_manager.field_define("socks", "lotermfield",
                                            "host.socks", "Host", "socks.host",
                                            "SOCKS destination host",
                                            FieldType.FIELD_TYPE_STR_HASH,
                                            FIELD_FLAG_IPPRE,
                                            None)

    field_manager.field_define("socks", "lotextfield",
                               "host.socks.tokens", "Hostname Tokens", "socks.hostTokens",
                               "SOCKS Hostname Tokens",
                               FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_FAKE,
                               None)

    user_field = field_manager.field_define("socks", "termfield",
                                            "socks.user", "User", "socks.user",
                                            "SOCKS authenticated user",
                                            FieldType.FIELD_TYPE_STR_HASH, 0,
                                            None)
                                            
    parsers_classifier_register_tcp("socks4", None, 0, "\\x04", 1, socks4_classify, 0, API_VERSION)
    parsers_classifier_register_tcp("socks5", None, 0, "\\x05", 1, socks5_classify, 0, API_VERSION)
