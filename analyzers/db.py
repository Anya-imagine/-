import configparser
import sys
import os
import logging
import threading
import time
import ipaddress
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

# Remove the direct import of field_manager
# from .field import field_manager

from .BSB import BSB
from .field import FieldManager
from .session import Session

field_bsb = BSB()
field_bsb_time_out = None

config = configparser.ConfigParser()
es_server = 0


class PatriciaTree:
    def __init__(self):
        self.head = PatriciaNode()
        self.max_bits = 0
        self.num_active_node = 0


class Prefix:
    def __init__(self):
        self.family = ''
        self.bit_len = ''
        self.ref_count = 0
        self.sin = ipaddress.IPv4Address('0.0.0.0')
        self.sin6 = ipaddress.IPv6Address('::')


class PatriciaNode:
    def __init__(self):
        self.prefix = Prefix()
        self.l = None  # Left child
        self.r = None  # Right child
        self.parent = None  # Parent node
        self.data = None
        self.bit = 0


def http_get_buffer():
    # 临时实现，后续再完善
    return bytearray(1024)


def http_schedule(server, method, path, path_len, data, data_len, headers, priority, callback, user_data):
    # 临时实现，后续再完善
    pass


def db_json_str(bsb: BSB, In, utf8: bool):
    bsb.export_u8('"')
    while In:
        match In:
            case '\b':
                bsb.export_u8('\\b')
                break
            case '\n':
                bsb.export_u8('\\n')
                break
            case '\r':
                bsb.export_u8('\\r')
                break
            case '\f':
                bsb.export_u8('\f')
                break
            case '\t':
                bsb.export_u8('\t')
                break
            case '"':
                bsb.export_u8("\\")
                break
            case '\\':
                bsb.export_u8("\\\\")
                break
            case '/':
                bsb.export_u8("/")
                break
            case _:
                if In < 32:
                    bsb.export_sprintf("\\u%04x", In)
                elif utf8:
                    if (In & 0xf0) == 0xf0:
                        bsb.ptr = In[:4]
                        In += 3
                    elif In & 0xf0 == 0xe0:
                        bsb.ptr = In[:3]
                        In += 2
                    elif In & 0xf0 == 0xd0:
                        bsb.ptr = In[:2]
                        In += 1
                    else:
                        bsb.ptr = In[:1]
                else:
                    if In & 0x80:
                        bsb.export_u8((0xc0 | (In >> 6)))
                        bsb.export_u8((0x80 | (In & 0x3f)))
                    else:
                        bsb.export_u8(In)
                break
        In += 1


def db_fields_bsb_timeout(user_data):
    if field_bsb.buf and field_bsb.length > 0:
        if user_data == 0:
            http_schedule(es_server, "POST", "/_bulk", 6, field_bsb.buf, field_bsb.length(), None, 0, None, None)
        else:
            data = http_send_sync(es_server, "POST", "/_bulk", 6, field_bsb.buf, field_bsb.length(), None, None, None)

        field_bsb = BSB(http_get_buffer(), config.db_bulk_size)
    return False


def start_timeout_thread():
    global field_bsb_time_out
    if field_bsb_time_out is None:
        field_bsb_time_out = threading.Timer(1.0, db_fields_bsb_timeout, args=(None,))
        field_bsb_time_out.start()


def stop_timeout_thread():
    global field_bsb_time_out
    if field_bsb_time_out is not None:
        field_bsb_time_out.cancel()
        field_bsb_time_out = None


def db_field_bsb_make():
    db_bulk_size = config.getint('settings', 'db_bulk_size', fallback=0)
    if not field_bsb.buf:
        field_bsb = BSB(http_get_buffer(), db_bulk_size)
        start_timeout_thread()
    elif field_bsb.remaining() < 1000:
        stop_timeout_thread()
        db_fields_bsb_timeout(None)
        start_timeout_thread()


def db_add_field(group, kind, expression, friendly_name, db_field, help, have_ap, ap, *args):
    dry_run = config.getboolean('settings', 'dry_run', fallback=False)
    if config.dry_run:
        return
    db_field_bsb_make()
    field_bsb.export_sprintf("{\"index\": {\"_index\": \"%sfields\", \"_id\": \"%s\"}}\n", config.prefix, expression)
    field_bsb.export_sprintf(
        "{\"friendlyName\": \"%s\", \"group\": \"%s\", \"help\": \"%s\", \"dbField2\": \"%s\", \"type\": \"%s\"",
        friendly_name,
        group,
        help,
        db_field,
        kind)
    args_iter = iter(args)

    if have_ap:
        while (1):
            field = next(args_iter)
            value = next(args_iter)

            if field is None or value is None:
                break
            field_bsb.export_sprintf(", \"%s\": ", field)
            if value == '{' or value == '[':
                field_bsb.export_sprintf("%s", value)
            else:
                field_bsb.export_sprintf("\"%s\"", value)

    field_bsb.export_sprintf("}\n")


def db_update_field(expression, name, value):
    from .singleton import field_manager
    dry_run = config.getboolean('settings', 'dry_run', fallback=False)
    if config.dry_run:
        return
    db_field_bsb_make()
    field_bsb.export_sprintf("{\"update\": {\"_index\": \"%sfields\", \"_id\": \"%s\"}}\n", config.prefix, expression)
    field_bsb.export_sprintf("{\"doc\": {\"%s\":", name)
    if value == '[':
        field_bsb.export_sprintf("%s", value)
    else:
        db_json_str(field_bsb, value, True)
    field_bsb.export_cstr("}}\n")


def comp_with_mask(addr, dest, mask):
    if addr[:mask / 8] == dest[:mask / 8]:
        return 1
    n = mask / 8
    m = ((-1) << (8 - (mask % 8)))
    if (addr[n] & m) == (dest[n] & m):
        return 1
    return 0


def patricia_search_best3(patricia: PatriciaTree, addr, bit_len):
    node = PatriciaNode()
    stack = PatriciaNode()
    cnt = 0
    if not patricia or not addr:
        return None
    if patricia.head == None:
        return None
    node = patricia.head
    while node.bit < bit_len:
        if node.prefix:
            stack[cnt] = node
            cnt += 1
        if addr[node.bit >> 3] & (0x80 >> (node.bit & 0x07)) != 0:
            node = node.r
        else:
            node = node.l
        if node == None:
            break
    if node and node.prefix:
        stack[cnt] = node
        cnt += 1
    if cnt <= 0:
        return None
    while cnt >= 0:
        cnt -= 1
        node = stack[cnt]
        if comp_with_mask(prefix.add.sin(node.prefix), addr, node.prefix.bit_len):
            return node
    return None


oui_tree = PatriciaTree()


def db_oui_lookup(field, session: Session, mac):
    from .singleton import field_manager
    node = PatriciaNode()
    if not oui_tree:
        return
    node = patricia_search_best3(oui_tree, mac, 48)
    if node == None:
        return
    field_manager.field_str_add(field, session, node.data, -1, True)
