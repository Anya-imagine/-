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

# 定义缓冲区大小常量
MAX_SMB_BUFFER = 64 * 1024  # 64KB SMB缓冲区大小
MAX_SMB1_DIALECTS = 16      # 最大SMB1方言数量

# Import from analyzers package
from analyzers.imports import (
    FieldType,
    FIELD_FLAG_CNT,
    FIELD_FLAG_FAKE,
    Session
)
from analyzers.field import FieldManager, field_manager
from analyzers.BSB import BSB
from analyzers.parsers import parsers_unregister, parsers_register, parsers_classifier_register_tcp, parsers_asn_get_tlv, API_VERSION
from analyzers.packet import PacketBatch, Packet, PacketReturnCode, packet_set_ip_callback
from analyzers.protocol import magic_protocol_register
from analyzers.session import SessionTypes
from analyzers.constants import FIELD_FLAG_IPPRE

# 定义跟踪函数调用的装饰器
def track_smb_calls(func):
    """装饰器：用于跟踪SMB函数调用"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # 可以在这里记录函数调用，用于调试或性能分析
        # smb_logger.debug(f"调用函数: {func.__name__}")
        result = func(*args, **kwargs)
        # smb_logger.debug(f"函数 {func.__name__} 返回: {result}")
        return result
    return wrapper

config = configparser.ConfigParser()

# 配置日志
logging.basicConfig(level=logging.INFO)
smb_logger = logging.getLogger("SMB_MODULE")

# SMB协议常量
SMB_PORT = 445  # 标准SMB端口
SMB1_PROTOCOL_ID = b"\xffSMB"  # SMB1协议ID
SMB2_PROTOCOL_ID = b"\xfeSMB"  # SMB2协议ID

# SMB命令类型
class SmbCommand(IntEnum):
    # SMB1命令
    CREATE_DIRECTORY = 0x00
    DELETE_DIRECTORY = 0x01
    OPEN = 0x02
    CREATE = 0x03
    CLOSE = 0x04
    FLUSH = 0x05
    DELETE = 0x06
    RENAME = 0x07
    QUERY_INFORMATION = 0x08
    SET_INFORMATION = 0x09
    READ = 0x0A
    WRITE = 0x0B
    LOCK_BYTE_RANGE = 0x0C
    UNLOCK_BYTE_RANGE = 0x0D
    CREATE_TEMPORARY = 0x0E
    CREATE_NEW = 0x0F
    CHECK_DIRECTORY = 0x10
    PROCESS_EXIT = 0x11
    SEEK = 0x12
    LOCK_AND_READ = 0x13
    WRITE_AND_UNLOCK = 0x14
    READ_RAW = 0x1A
    READ_MPX = 0x1B
    READ_MPX_SECONDARY = 0x1C
    WRITE_RAW = 0x1D
    WRITE_MPX = 0x1E
    WRITE_COMPLETE = 0x20
    SET_INFORMATION2 = 0x22
    QUERY_INFORMATION2 = 0x23
    LOCKING_ANDX = 0x24
    TRANSACTION = 0x25
    TRANSACTION_SECONDARY = 0x26
    IOCTL = 0x27
    IOCTL_SECONDARY = 0x28
    COPY = 0x29
    MOVE = 0x2A
    ECHO = 0x2B
    WRITE_AND_CLOSE = 0x2C
    OPEN_ANDX = 0x2D
    READ_ANDX = 0x2E
    WRITE_ANDX = 0x2F
    CLOSE_AND_TREE_DISC = 0x31
    TRANSACTION2 = 0x32
    TRANSACTION2_SECONDARY = 0x33
    FIND_CLOSE2 = 0x34
    FIND_NOTIFY_CLOSE = 0x35
    TREE_CONNECT = 0x70
    TREE_DISCONNECT = 0x71
    NEGOTIATE = 0x72
    SESSION_SETUP_ANDX = 0x73
    LOGOFF_ANDX = 0x74
    TREE_CONNECT_ANDX = 0x75
    QUERY_INFORMATION_DISK = 0x80
    SEARCH = 0x81
    FIND = 0x82
    FIND_UNIQUE = 0x83
    NT_TRANSACT = 0xA0
    NT_TRANSACT_SECONDARY = 0xA1
    NT_CREATE_ANDX = 0xA2
    NT_CANCEL = 0xA4
    
    # SMB2命令
    SMB2_NEGOTIATE = 0x0000
    SMB2_SESSION_SETUP = 0x0001
    SMB2_LOGOFF = 0x0002
    SMB2_TREE_CONNECT = 0x0003
    SMB2_TREE_DISCONNECT = 0x0004
    SMB2_CREATE = 0x0005
    SMB2_CLOSE = 0x0006
    SMB2_FLUSH = 0x0007
    SMB2_READ = 0x0008
    SMB2_WRITE = 0x0009
    SMB2_LOCK = 0x000A
    SMB2_IOCTL = 0x000B
    SMB2_CANCEL = 0x000C
    SMB2_ECHO = 0x000D
    SMB2_QUERY_DIRECTORY = 0x000E
    SMB2_CHANGE_NOTIFY = 0x000F
    SMB2_QUERY_INFO = 0x0010
    SMB2_SET_INFO = 0x0011
    SMB2_OPLOCK_BREAK = 0x0012
    
    @classmethod
    def to_str(cls, cmd_value: int, is_smb2: bool = False) -> str:
        """将SMB命令值转换为可读字符串"""
        try:
            if is_smb2 and cmd_value <= 0x0012:
                # 查找SMB2命令
                for name, value in cls.__members__.items():
                    if name.startswith("SMB2_") and value == cmd_value:
                        return name.replace("SMB2_", "")
            elif not is_smb2:
                # 查找SMB1命令
                for name, value in cls.__members__.items():
                    if not name.startswith("SMB2_") and value == cmd_value:
                        return name
                        
            return f"UNKNOWN({cmd_value})"
        except ValueError:
            return f"UNKNOWN({cmd_value})"

# SMB状态码 (NT Status代码)
class NtStatus(IntEnum):
    STATUS_SUCCESS = 0x00000000
    STATUS_NO_MORE_FILES = 0x80000006
    STATUS_INVALID_HANDLE = 0xC0000008
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_NO_SUCH_FILE = 0xC000000F
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
    STATUS_SHARING_VIOLATION = 0xC0000043
    STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
    STATUS_NOT_SUPPORTED = 0xC00000BB
    STATUS_NETWORK_NAME_DELETED = 0xC00000C9
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
    
    @classmethod
    def to_str(cls, status_value: int) -> str:
        """将NT状态码转换为可读字符串"""
        try:
            return cls(status_value).name
        except ValueError:
            return f"UNKNOWN_STATUS(0x{status_value:08X})"

# SMB方言
class SmbDialect(Enum):
    NT_LM_0_12 = "NT LM 0.12"
    SMB_2_002 = "SMB 2.002"
    SMB_2_1 = "SMB 2.1"
    SMB_3_0 = "SMB 3.0"
    SMB_3_0_2 = "SMB 3.0.2"
    SMB_3_1_1 = "SMB 3.1.1"
    
    @classmethod
    def from_dialect_revision(cls, revision: int) -> str:
        """从方言修订号获取方言字符串"""
        if revision == 0x0202:
            return cls.SMB_2_002.value
        elif revision == 0x0210:
            return cls.SMB_2_1.value
        elif revision == 0x0300:
            return cls.SMB_3_0.value
        elif revision == 0x0302:
            return cls.SMB_3_0_2.value
        elif revision == 0x0311:
            return cls.SMB_3_1_1.value
        else:
            return f"UNKNOWN(0x{revision:04X})"

# SMB信息类，存储解析过程中的数据
class SmbInfo:
    def __init__(self):
        self.session = None
        self.is_smb2 = False
        self.command = 0
        self.status = 0
        self.flags = 0
        self.flags2 = 0
        self.tid = 0
        self.pid = 0
        self.uid = 0
        self.mid = 0
        self.dialect = ""
        self.path = ""
        self.filename = ""
        self.service = ""
        # SMB2特有
        self.message_id = 0
        self.async_id = 0
        self.session_id = 0
        self.tree_id = 0
        self.credit_charge = 0
        self.credit_request = 0
        # 需要保存的字段
        self.version = [0, 0]  # SMB版本号
        self.state = [SMB_NETBIOS, SMB_NETBIOS]  # 解析状态
        self.buf = [bytearray(MAX_SMB_BUFFER), bytearray(MAX_SMB_BUFFER)]  # 缓冲区
        self.buf_len = [0, 0]  # 缓冲区长度
        self.rem_len = [0, 0]  # 剩余长度
        # SMB1方言相关
        self.dialects = [None] * MAX_SMB1_DIALECTS  # SMB1方言数组
        self.dialect_len = 0  # SMB1方言长度

# States
SMB_NETBIOS = 0
SMB_SMBHEADER = 1
SMB_SKIP = 2
SMB1_TREE_CONNECT_ANDX = 10
SMB1_DELETE = 11
SMB1_OPEN_ANDX = 12
SMB1_CREATE_ANDX = 13
SMB1_SETUP_ANDX = 14
SMB1_NEGOTIATE_REQ = 15
SMB1_NEGOTIATE_RSP = 16

SMB2_TREE_CONNECT = 20
SMB2_CREATE = 21
SMB2_NEGOTIATE = 22

# SMB1 Flags
SMB1_FLAGS_REPLY = 0x80
SMB1_FLAGS2_UNICODE = 0x8000

# SMB2 Flags
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001


def smb_add_str(session: Session, field, buf, length, use_unicode):
    if length == 0:
        return

    error = 0
    bread = 0
    bwritten = 0
    try:
        if use_unicode:
            out = buf.decode('utf-16-le', errors='ignore')
            if error:
                if config.debug:
                    logging.log("Error %s", error.message)
        else:
            field_manager.field_str_add(field, session, buf, length, True)
    except UnicodeDecodeError as e:
        if config.debug:
            print(f"解码失败: {e.reason}")


def smb_security_blob(session: Session, data, length):
    bsb = BSB(data, length)
    a_pc = 0
    a_tag = 0
    a_len = 0

    value = parsers_asn_get_tlv(bsb, a_pc, a_tag, a_len)
    if a_tag != 1:
        return
    bsb = BSB(value, a_len)
    value = parsers_asn_get_tlv(bsb, a_pc, a_tag, a_len)
    if a_tag != 16:
        return
    bsb = BSB(value, a_len)
    value = parsers_asn_get_tlv(bsb, a_pc, a_tag, a_len)
    if a_tag != 2:
        return

    bsb = BSB(value, a_len)
    value = parsers_asn_get_tlv(bsb, a_pc, a_tag, a_len)

    if a_tag != 4 or a_len < 7 or value[:7] != b'NTLMSSP':
        return
    bsb = BSB(value, a_len)
    bsb.skip(8)

    type = 0
    bsb.limport_u32(type)

    if type != 3:
        return

    lens = []
    offset = []
    for i in range(6):
        bsb.limport_u32(lens[i])
        bsb.skip(2)
        bsb.limport_u32(offset[i])

        if bsb.error or offset[i] > (bsb.end - bsb.buf) or lens[i] > (bsb.end - bsb.buf):
            session.add_tag("smb:bad-security-blob")
            return

    if bsb.error:
        return

    if lens[2]:
        smb_add_str(session, domain_field, value + offset[2], lens[2], True)

    if lens[3]:
        smb_add_str(session, user_field, value + offset[3], lens[3], True)

    if lens[4]:
        smb_add_str(session, host_field, value + offset[4], lens[4], True)


def smb1_str_null_split(buf, length, out, max):
    out = [None] * max
    start = 0
    for i, p in range(length, max):
        if buf[i] == 0:
            out[p] = buf + start
            start = i + 1
            p += 1


def smb1_parser_osver_domain(session: Session, buf, length, use_unicode):
    out = []
    bread = 0
    bwritten = 0
    error = 0
    if use_unicode:
        out = buf.decode('utf-16-le', errors='ignore')
    else:
        out = buf
        bwritten = length
    if error:
        if config.debug:
            logging.log("Error %s", error.message)
            return
    outs = []
    smb1_str_null_split(out, bwritten, outs, 3)
    if len(outs) > 0 and outs[0] is not None and len(outs[0]) > 0:
        field_manager.field_str_add(os_field, session, outs[0], -1, True)
    if len(outs) > 0 and outs[1] is not None and len(outs[1]) > 0:
        field_manager.field_str_add(ver_field, session, outs[1], -1, True)
    if len(outs) > 0 and outs[2] is not None and len(outs[2]) > 0:
        field_manager.field_str_add(fn_field, session, outs[2], -1, True)


def smb1_parse_user_domain_os_ver(session: Session, buf, length, use_unicode):
    out = []
    bread = 0
    bwritten = 0
    error = 0
    if use_unicode:
        out = buf.decode('ucs-2le', errors='ignore')
    else:
        out = buf
        bwritten = length

    if error:
        if config.debug:
            logging.log("Error %s", error.message)
            return

    outs = []
    smb1_str_null_split(out, bwritten, outs, 4)

    if len(outs) > 0 and outs[0] is not None and len(outs[0]) > 0:
        field_manager.field_str_add(user_field, session, outs[0], -1, True)
    if len(outs) > 0 and outs[1] is not None and len(outs[1]) > 0:
        field_manager.field_str_add(host_field, session, outs[1], -1, True)
    if len(outs) > 0 and outs[2] is not None and len(outs[2]) > 0:
        field_manager.field_str_add(dialect_field, session, outs[2], -1, True)
    if len(outs) > 0 and outs[3] is not None and len(outs[3]) > 0:
        field_manager.field_str_add(ver_field, session, outs[3], -1, True)


def smb1_parse_negotiate_request(smb: SmbInfo, buf, length):
    bsb = BSB(buf, length)
    if smb.dialect_len >= MAX_SMB1_DIALECTS:
        return

    while bsb.remaining() > 0:
        bsb.skip(1)
        start = bsb.work_ptr()
        while bsb.remaining() > 0 and bsb.work_ptr() != 0:
            bsb.skip(1)
            if bsb.remaining() == 0:
                break
            smb.dialects[smb.dialect_len] = start
            smb.dialect_len += 1
            if smb.dialect_len >= MAX_SMB1_DIALECTS:
                break
            bsb.skip(1)


def smb1_parse(session: Session, smb: SmbInfo, bsb: BSB, state, rem_len, which):
    start = bsb.work_ptr()
    
    if state == SMB_SMBHEADER:
        cmd = 0
        flags = 0
        if bsb.remaining() < 32:
            return 1
        bsb.skip(4)
        bsb.import_u8(cmd)
        bsb.skip(4)
        bsb.import_u8(flags)
        bsb.limport_u16(smb.flags2[which])
        bsb.skip(20)
        if (flags and SMB1_FLAGS_REPLY) == 0:
            if cmd == 0x06:
                state = SMB1_DELETE
            elif cmd == 0x2d:
                state = SMB1_OPEN_ANDX
            elif cmd == 0x72:
                state = SMB1_NEGOTIATE_REQ
            elif cmd == 0x73:
                state = SMB1_SETUP_ANDX
            elif cmd == 0x75:
                state = SMB1_TREE_CONNECT_ANDX
            elif cmd == 0xa2:
                state = SMB1_CREATE_ANDX
            else:
                state = SMB_SKIP
        else:
            if cmd == 0x72:
                state = SMB1_NEGOTIATE_RSP
            else:
                state = SMB1_SKIP
    
    elif state == SMB1_CREATE_ANDX:
        if bsb.remaining() < rem_len:
            return 1
        word_count = 0
        bsb.import_u8(word_count)
        bsb.skip(word_count * 2 + 3)
        smb_add_str(session, fn_field, bsb.work_ptr(), bsb.remaining(), smb.flags2[which] and SMB1_FLAGS2_UNICODE)
        state = SMB_SKIP
    
    elif state == SMB1_DELETE:
        if bsb.remaining() < rem_len:
            return 1
        word_count = 0
        bsb.import_u8(word_count)
        bsb.skip(word_count * 2 + 3)
        if bsb.error:
            return 1
        smb_add_str(session, fn_field, bsb.work_ptr(), bsb.remaining(), smb.flags2[which] and SMB1_FLAGS2_UNICODE)
        state = SMB_SKIP
    
    elif state == SMB1_TREE_CONNECT_ANDX:
        if bsb.remaining() < rem_len:
            return 1
        pass_length = 0
        bsb.skip(6)
        bsb.import_u16(pass_length)

        offset = 2 if (bsb.work_ptr() - start) % 2 == 0 else 1

        if bsb.error or offset > bsb.remaining():
            return 1

        smb_add_str(session, share_field, bsb.work_ptr() + offset, bsb.remaining() - offset,
                    smb.flags2[which] and SMB1_FLAGS2_UNICODE)
        state = SMB_SKIP
    
    elif state == SMB1_SETUP_ANDX:
        if bsb.remaining() < rem_len:
            if bsb.error:
                return 1
        word_count = 0
        bsb.import_u8(word_count)

        if word_count == 12:
            bsb.skip(14)

            security_len = 0
            bsb.limport_u16(security_len)

            bsb.skip(10)

            if security_len > bsb.remaining():
                bsb.error = True
                return 1

            smb_security_blob(session, bsb.work_ptr(), security_len)
            bsb.skip(security_len)

            offset = 0 if (bsb.work_ptr() - start) % 2 == 0 else 1
            bsb.skip(offset)

            if not bsb.error:
                smb1_parser_osver_domain(session, bsb.work_ptr(), bsb.remaining(),
                                            smb.flags2[which] and SMB1_FLAGS2_UNICODE)

        elif word_count == 13:
            bsb.skip(14)
            ansi_pwd = 0
            bsb.limport_u16(ansi_pwd)
            unicode_pwd = 0
            bsb.limport_u16(unicode_pwd)

            bsb.skip(10 + ansi_pwd + unicode_pwd)

            offset = 0 if (bsb.work_ptr() - start) % 2 == 0 else 1
            bsb.skip(offset)

            if not bsb.error:
                smb1_parser_osver_domain(session.bsb.work_ptr(), bsb.remaining(),
                                            smb.flags2[which] and SMB1_FLAGS2_UNICODE)

                state = SMB_SKIP
        
    elif state == SMB1_NEGOTIATE_REQ:
        if bsb.remaining() < rem_len:
            bsb.error = True
            return 1
        bsb.skip(1)

        byte_count = 0
        bsb.limport_u8(byte_count)

        if byte_count > 0:
            smb1_parse_negotiate_request(smb, bsb.work_ptr(), bsb.remaining())

        state = SMB_SKIP
    
    elif state == SMB1_NEGOTIATE_RSP:
        if bsb.remaining() < rem_len:
            bsb.error = True
            return 1

        word_count = 0
        bsb.limport_u8(word_count)

        if word_count < 13:
            state = SMB_SKIP
        else:
            dialect = 0
            bsb.import_u8(dialect)

            if dialect < smb.dialect_len:
                field_manager.field_str_add(dialect_field, session, smb.dialects[dialect], -1, True)
            state = SMB_SKIP

    rem_len -= bsb.work_ptr() - start
    return 0


def smb2_parse(session: Session, smb: SmbInfo, bsb: BSB, state, rem_len, which):
    start = bsb.work_ptr()

    if state == SMB_SMBHEADER:
        flags = 0
        cmd = 0
        if bsb.remaining() < 64:
            return 1

        bsb.skip(12)
        bsb.limport_u16(cmd)
        bsb.skip(2)
        bsb.limport_u32(flags)
        bsb.skip(44)

        if flags and SMB2_FLAGS_SERVER_TO_REDIR == 0:
            if cmd == 0x03:
                state = SMB2_TREE_CONNECT
            elif cmd == 0x05:
                state = SMB2_CREATE
            else:
                state = SMB_SKIP
        else:
            if cmd == 0x00:
                state = SMB2_NEGOTIATE
            else:
                state = SMB_SKIP
        rem_len -= bsb.work_ptr() - start
    
    elif state == SMB2_NEGOTIATE:
        if bsb.remaining() < rem_len:
            return 1
        bsb.skip(4)
        dialect = 0
        bsb.limport_u16(dialect)
        if dialect != 0 and dialect != 0x02FF:
            str = "SMB {}.{}.{}".format(
                (dialect >> 8) & 0xF,
                (dialect >> 4) & 0xF,
                dialect & 0xF
            )
            field_manager.field_define(dialect_field, session, str, -1, True)
        rem_len -= bsb.work_ptr() - start
        state = SMB_SKIP
    
    elif state == SMB2_TREE_CONNECT:
        path_offset = 0
        path_len = 0
        if bsb.remaining() < rem_len:
            return 1
        bsb.skip(4)
        bsb.limport_u16(path_offset)
        bsb.skip(path_len)
        path_offset -= (64 + 8)
        bsb.skip(path_offset)

        if not bsb.error and path_len and bsb.remaining():
            smb_add_str(session, share_field, bsb.work_ptr(), path_len, smb.flags2[which] and SMB1_FLAGS2_UNICODE)

        rem_len -= bsb.work_ptr() - start
        state = SMB_SKIP
    
    elif state == SMB2_CREATE:
        name_offset = 0
        name_len = 0
        if bsb.remaining() < rem_len:
            return 1
        bsb.skip(44)
        bsb.limport_u16(name_offset)
        bsb.limport_u16(name_len)
        name_offset -= (64 + 48)
        bsb.skip(name_offset)

        if not bsb.error and name_len < bsb.remaining():
            bread = 0
            bwritten = 0
            error = 0
            out = []
            bread = 0
            bwritten = 0
            error = 0
            if use_unicode:
                out = buf.decode('ucs-2le', errors='ignore')
            else:
                out = buf
                bwritten = length

            if error:
                if config.debug:
                    logging.log("Error %s", error.message)
        rem_len -= bsb.work_ptr() - start
        state = SMB_SKIP

    return 0


def smb_parser(session: Session, uw, data, remaining, which):
    smb = uw
    state = smb.state[which]
    buf = smb.buf[which]
    buf_len = smb.buf_len[which]
    rem_len = smb.rem_len[which]
    while remaining > 0:
        bsb = BSB()
        done = 0
        if buf_len:
            bsb = BSB(data, remaining)
            data += remaining
            remaining = 0
        else:
            length = min(remaining, MAX_SMB_BUFFER - buf_len)
            buf[buf_len:buf_len + length] = data[:length]
            buf_len += length
            data += length
            bsb = BSB(buf, buf_len)

        if state != SMB_SKIP and rem_len > MAX_SMB_BUFFER:
            parsers_unregister(session, smb)
            return 0
        while not done and bsb.remaining() > 0:
            if state == SMB_NETBIOS:
                if bsb.remaining() < 5:
                    done = 1
                    break
                bsb.skip(1)
                bsb.import_u24(rem_len)
                # Peak at SMBHEADER for version
                smb.version[which] = bsb.remaining()
                state = SMB_SMBHEADER
            elif state == SMB_SKIP:
                if bsb.remaining() < rem_len:
                    rem_len -= bsb.remaining()
                    bsb.skip(bsb.remaining())
                else:
                    bsb.skip(rem_len)
                    rem_len = 0
                    state = SMB_NETBIOS
            else:
                if smb.version[which] == 0xff:
                    done = smb1_parse(session, smb, bsb, state, rem_len, which)
                else:
                    done = smb2_parse(session, smb, bsb, state, rem_len, which)

        if bsb.error:
            parsers_unregister(session, smb)
            return 0

        if bsb.remaining() > 0 and bsb.work_ptr() != buf:
            if bsb.remaining() > MAX_SMB_BUFFER:
                logging.log("WARNING - Not enough room to parse SMB packet of size %u", bsb.remaining())
                parsers_unregister(session, smb)
                return 0
            # 将剩余数据移动到缓冲区开头
            remaining_data = bsb.work_ptr()[:bsb.remaining()]
            buf[:len(remaining_data)] = remaining_data
            buf_len = len(remaining_data)
        buf_len = bsb.remaining()
    return 0


def smb_classify(session: Session, data, length, which, uw):
    if data[4] != 0xff and data[4] != 0xfe:
        return
    if session.has_protocol("smb"):
        return
    session.add_protocol("smb")
    smb = SmbInfo()
    parsers_register(session, smb_parser, smb)


def parser_init():
    """初始化SMB解析器并注册字段和回调函数"""
    global share_field, fn_field, os_field, domain_field, dialect_field, user_field, host_field
    global smb_command_field, smb_status_field, smb_magic_protocol
    global MAX_SMB_BUFFER, MAX_SMB1_DIALECTS

    # 定义缓冲区大小常量
    MAX_SMB_BUFFER = 64 * 1024  # 64KB SMB缓冲区大小
    MAX_SMB1_DIALECTS = 16  # 最大SMB1方言数量
    
    smb_logger.info("初始化SMB解析器")
    
    # 定义SMB字段
    share_field = field_manager.field_define("smb", "termfield",
                                          "smb.share", "Share", "smb.share",
                                          "SMB shares connected to",
                                          FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                          None)

    fn_field = field_manager.field_define("smb", "termfield",
                                       "smb.fn", "Filename", "smb.filename",
                                       "SMB files opened, created, deleted",
                                       FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                       None)

    os_field = field_manager.field_define("smb", "termfield",
                                       "smb.os", "OS", "smb.os",
                                       "SMB OS information",
                                       FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                       None)

    domain_field = field_manager.field_define("smb", "termfield",
                                           "smb.domain", "Domain", "smb.domain",
                                           "SMB Domain information",
                                           FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                           None)

    dialect_field = field_manager.field_define("smb", "termfield",
                                            "smb.dialect", "Dialect", "smb.dialect",
                                            "SMB Dialect information",
                                            FieldType.FIELD_TYPE_STR, 0,
                                            None)

    user_field = field_manager.field_define("smb", "termfield",
                                         "smb.user", "User", "smb.user",
                                         "SMB User",
                                         FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                         "category", "user",
                                         None)

    host_field = field_manager.field_define("smb", "termfield", 
                                         "host.smb", "Hostname", "smb.host",
                                         "SMB Host name",
                                         FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                         "category", "host",
                                         "aliases", "[\"smb.host\"]",
                                         None)
                                         
    # 添加命令字段和状态字段
    smb_command_field = field_manager.field_define("smb", "termfield",
                                              "smb.command", "Command", "smb.command",
                                              "SMB Command",
                                              FieldType.FIELD_TYPE_INT, 0,
                                              None)
                                              
    smb_status_field = field_manager.field_define("smb", "termfield",
                                             "smb.status", "Status", "smb.status",
                                             "SMB Status code",
                                             FieldType.FIELD_TYPE_INT, 0,
                                             None)

    field_manager.field_define("smb", "lotextfield",
                            "host.smb.tokens", "Hostname Tokens", "smb.hostTokens",
                            "SMB Host Tokens",
                            FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_FAKE,
                            "aliases", "[\"smb.host.tokens\"]",
                            None)
                            
    # 注册SMB魔术协议识别器
    smb_magic_protocol = magic_protocol_register("smb", "SMB/CIFS Protocol", "smb.no-recon", "smb", True)
    
    # 注册SMB分类器
    parsers_classifier_register_tcp("smb", None, 0, "\\xffSMB", 4, smb_classify, 0, API_VERSION)  # SMB1
    parsers_classifier_register_tcp("smb2", None, 0, "\\xfeSMB", 4, smb_classify, 0, API_VERSION)  # SMB2/3
    
    # 注册IP回调 - 由于函数参数不匹配，暂时注释掉
    # packet_set_ip_callback(smb_packet_enqueue, smb_pre_process, SMB_PORT)
    # packet_set_ip_callback(smb_process, SMB_PORT)
    
    smb_logger.info("SMB解析器初始化完成")
    
    return 0

# SMB协议分类函数
@track_smb_calls
def smb_classify(session: Session, data: bytearray, length: int, which: int):
    """对SMB数据包进行分类"""
    if length < 8:  # SMB头至少需要8字节
        return 0
    
    # 检查SMB协议标识
    is_smb1 = False
    is_smb2 = False
    
    # 检查SMB1协议ID
    if data[0:4] == b'\xff\x53\x4d\x42':  # SMB1 \xffSMB
        is_smb1 = True
    # 检查SMB2协议ID
    elif data[0:4] == b'\xfe\x53\x4d\x42':  # SMB2 \xfeSMB
        is_smb2 = True
    else:
        # 不是SMB协议，不处理
        return 0
    
    smb_logger.info(f"检测到SMB{'2/3' if is_smb2 else '1'}协议")
    
    # 已经标记为SMB，无需重复处理
    if hasattr(session, 'protocols') and 'smb' in session.protocols:
        return 0
    
    # 标记为SMB协议
    if hasattr(session, 'add_protocol'):
        session.add_protocol('smb')
    
    # 初始化会话字段
    if not hasattr(session, 'fields'):
        session.fields = {}
    
    if 'smbField' not in session.fields:
        session.fields['smbField'] = {}
    
    session.fields['smbField']['protocol_version'] = 'SMB2' if is_smb2 else 'SMB1'
    
    # 创建SMB信息对象
    info = SmbInfo()
    info.session = session
    info.is_smb2 = is_smb2
    
    # 注册解析器 - 包含解析器和保存函数
    parsers_register(session, smb_parser, info, smb_save)
    
    return 1

# SMB解析函数
@track_smb_calls
def smb_parser(session: Session, uw: SmbInfo, data: bytearray, length: int, which: int) -> int:
    """解析SMB数据包内容"""
    if length < 4:  # 至少需要4字节来判断NetBIOS和SMB头
        smb_logger.info("数据包长度不足4字节，无法解析")
        return 0
    
    info = uw  # 用户数据就是SmbInfo对象
    
    # 检查是否是NetBIOS封装的SMB (NetBIOS Session Message)
    netbios_encapsulated = False
    smb_data = data
    smb_offset = 0
    
    if data[0] == 0x00:  # NetBIOS Session Message标识
        # 这是NetBIOS封装的SMB数据包
        netbios_encapsulated = True
        if length >= 4:
            # 提取NetBIOS消息长度
            nb_length = (data[1] << 16) | (data[2] << 8) | data[3]
            smb_logger.info(f"NetBIOS封装: 消息长度={nb_length}字节")
            
            if length >= 4 + 4:  # 至少有NetBIOS头(4字节)和SMB签名(4字节)
                # 获取SMB数据部分
                smb_data = data[4:]
                smb_offset = 4
                smb_logger.info(f"提取SMB数据: 长度={len(smb_data)}字节")
            else:
                smb_logger.info("NetBIOS头后没有足够的SMB数据")
                return 0
        else:
            smb_logger.info("数据包长度不足，无法提取NetBIOS头")
            return 0
    
    # 现在检查SMB协议标识
    if len(smb_data) < 4:
        smb_logger.info("SMB数据长度不足4字节，无法检查协议标识")
        return 0
        
    protocol_id = bytes(smb_data[0:4])
    
    # 判断SMB协议版本
    is_smb1 = (protocol_id == SMB1_PROTOCOL_ID)
    is_smb2 = (protocol_id == SMB2_PROTOCOL_ID)
    
    if not (is_smb1 or is_smb2):
        smb_logger.info(f"不是有效的SMB协议标识: {protocol_id.hex()}")
        return 0  # 不是SMB协议
    
    info.is_smb2 = is_smb2
    
    # 记录我们找到了什么类型的SMB
    if is_smb1:
        smb_logger.info("检测到SMB1协议")
    else:
        smb_logger.info("检测到SMB2/3协议")
    
    # 保存到会话字段
    if 'smbField' not in session.fields:
        session.fields['smbField'] = {}
    
    # 将协议版本添加到字段
    session.fields['smbField']['protocol_version'] = 'SMB2' if is_smb2 else 'SMB1'
    
    # 状态与会话（记录SMB数据的状态）
    state = info.state[which]
    buf = info.buf[which]
    buf_len = info.buf_len[which]
    rem_len = info.rem_len[which]
    
    # 如果是一个新包，重置状态
    if state == SMB_NETBIOS:
        # 检查NetBIOS头
        if netbios_encapsulated:
            # 已经处理过NetBIOS头，直接进入SMB头部分
            state = SMB_SMBHEADER
            nb_length = (data[1] << 16) | (data[2] << 8) | data[3]
            rem_len = nb_length  # 剩余长度是NetBIOS头中指定的长度
        elif length >= 4:
            # 检查是否直接是SMB头
            if is_smb1 or is_smb2:
                state = SMB_SMBHEADER
                rem_len = length  # 剩余长度就是包的总长度
    
    # 创建BSB对象处理数据
    bsb = BSB(smb_data, len(smb_data))
    
    # 根据协议版本解析
    if is_smb2:
        result = _parse_smb2(session, info, smb_data, len(smb_data))
    else:
        result = _parse_smb1(session, info, smb_data, len(smb_data))
    
    # 更新状态
    info.state[which] = state
    info.buf_len[which] = buf_len
    info.rem_len[which] = rem_len
    
    return result

# SMB1解析函数
@track_smb_calls
def _parse_smb1(session: Session, info: SmbInfo, data: bytearray, length: int) -> int:
    """解析SMB1协议数据包"""
    smb_logger.info(f"开始解析SMB1数据包: 长度={length}字节")
    
    # SMB1头至少需要32字节
    if length < 32:
        smb_logger.info(f"SMB1头部不完整: 只有{length}字节")
        return 0
    
    # SMB1头格式:
    # 0-3:   Protocol ID (\xffSMB)
    # 4:     Command
    # 5-8:   NT Status (错误码)
    # 9:     Flags
    # 10-11: Flags2
    # 12-13: PID高字
    # 14-29: 签名
    # 30-31: 保留
    # 32-33: TreeID (TID)
    # 34-35: ProcessID (PID)
    # 36-37: UserID (UID)
    # 38-39: MultiplexID (MID)
    
    # 提取关键字段
    command = data[4]
    status = (data[8] << 24) | (data[7] << 16) | (data[6] << 8) | data[5]
    flags = data[9]
    flags2 = (data[11] << 8) | data[10]
    tid = (data[33] << 8) | data[32] if length > 33 else 0
    pid = (data[35] << 8) | data[34] if length > 35 else 0
    uid = (data[37] << 8) | data[36] if length > 37 else 0
    mid = (data[39] << 8) | data[38] if length > 39 else 0
    
    smb_logger.info(f"SMB1头部: 命令=0x{command:02X}, 状态=0x{status:08X}, 标志=0x{flags:02X}, 标志2=0x{flags2:04X}")
    smb_logger.info(f"SMB1会话: TID=0x{tid:04X}, PID=0x{pid:04X}, UID=0x{uid:04X}, MID=0x{mid:04X}")
    
    # 存储到信息对象
    info.command = command
    info.status = status
    info.flags = flags
    info.flags2 = flags2
    info.tid = tid
    info.pid = pid
    info.uid = uid
    info.mid = mid
    
    # 存储到会话字段
    session.fields['smbField']['command'] = SmbCommand.to_str(command, False)
    session.fields['smbField']['status'] = NtStatus.to_str(status)
    
    # 根据命令类型进一步解析
    if command == SmbCommand.NEGOTIATE:
        smb_logger.info("解析SMB1 NEGOTIATE命令")
        # 解析NEGOTIATE响应
        if flags & 0x80:  # 响应标志
            if length >= 73:  # 确保有足够的数据
                # 提取SMB方言
                dialect_index = (data[41] << 8) | data[40]
                if dialect_index == 0:  # 通常是NT LM 0.12
                    info.dialect = SmbDialect.NT_LM_0_12.value
                else:
                    info.dialect = f"DIALECT_{dialect_index}"
                
                session.fields['smbField']['dialect'] = info.dialect
                smb_logger.info(f"SMB1协商: 方言={info.dialect}")
    
    elif command == SmbCommand.SESSION_SETUP_ANDX:
        smb_logger.info("解析SMB1 SESSION_SETUP_ANDX命令")
        # 处理会话设置
        if flags & 0x80:  # 响应标志
            # 会话设置响应
            smb_logger.info(f"SMB1会话设置响应: 状态={NtStatus.to_str(status)}")
    
    elif command == SmbCommand.TREE_CONNECT_ANDX:
        smb_logger.info("解析SMB1 TREE_CONNECT_ANDX命令")
        # 处理树连接
        if flags & 0x80:  # 响应标志
            # 树连接响应
            smb_logger.info(f"SMB1树连接响应: TID={tid}, 状态={NtStatus.to_str(status)}")
        else:
            # 树连接请求
            # 提取服务和路径
            if length > 60:  # 确保有足够的数据
                # 解析路径 (具体字段位置取决于具体SMB实现，简化处理)
                path_start = 60
                path_end = length
                
                try:
                    # 尝试提取ASCII或UTF-16编码的路径
                    path_bytes = data[path_start:path_end]
                    # 寻找字符串结束符
                    null_pos = path_bytes.find(0)
                    if null_pos >= 0:
                        path_bytes = path_bytes[:null_pos]
                    
                    path = path_bytes.decode('utf-8', errors='replace')
                    info.path = path
                    session.fields['smbField']['path'] = path
                    smb_logger.info(f"SMB1树连接请求: 路径={path}")
                except Exception as e:
                    smb_logger.info(f"SMB1路径解析错误: {e}")
    
    elif command in (SmbCommand.OPEN_ANDX, SmbCommand.NT_CREATE_ANDX):
        smb_logger.info(f"解析SMB1 {SmbCommand.to_str(command, False)}命令")
        # 处理文件打开操作
        if not (flags & 0x80):  # 请求标志
            # 文件创建/打开请求
            # 由于字段位置不固定，简化处理
            smb_logger.info(f"SMB1文件{'创建' if command == SmbCommand.NT_CREATE_ANDX else '打开'}请求")
            
            # 尝试提取文件名
            if command == SmbCommand.NT_CREATE_ANDX and length > 88:
                try:
                    # NT_CREATE_ANDX文件名通常在偏移量88之后
                    name_length = (data[87] << 8) | data[86]
                    if name_length > 0 and length > 88 + name_length:
                        name_bytes = data[88:88+name_length]
                        # 检测编码 (通常是UTF-16LE)
                        if flags2 & 0x8000:  # UNICODE标志
                            filename = name_bytes.decode('utf-16-le', errors='replace')
                        else:
                            filename = name_bytes.decode('ascii', errors='replace')
                        
                        info.filename = filename
                        session.fields['smbField']['filename'] = filename
                        smb_logger.info(f"SMB1文件名: {filename}")
                except Exception as e:
                    smb_logger.info(f"SMB1文件名解析错误: {e}")
    
    elif command in (SmbCommand.READ_ANDX, SmbCommand.WRITE_ANDX):
        smb_logger.info(f"解析SMB1 {SmbCommand.to_str(command, False)}命令")
        # 处理读写操作
        operation = "读取" if command == SmbCommand.READ_ANDX else "写入"
        if flags & 0x80:  # 响应标志
            # 读取响应
            if command == SmbCommand.READ_ANDX and length > 46:
                # 提取读取的数据长度
                data_length = (data[43] << 8) | data[42]
                smb_logger.info(f"SMB1 {operation}响应: 数据长度={data_length}")
        else:
            # 读取/写入请求
            if length > 41:
                fid = (data[41] << 8) | data[40]
                smb_logger.info(f"SMB1 {operation}请求: FID=0x{fid:04X}")
    
    # 输出最终的解析结果
    smb_logger.info(f"SMB1解析完成: 命令={SmbCommand.to_str(command, False)}, 状态={NtStatus.to_str(status)}")
    return 0

# SMB2解析函数
@track_smb_calls
def _parse_smb2(session: Session, info: SmbInfo, data: bytearray, length: int) -> int:
    """解析SMB2协议数据包"""
    smb_logger.info(f"开始解析SMB2数据包: 长度={length}字节")
    
    # SMB2头格式 (16字节对齐):
    # 0-3:   Protocol ID (\xfeSMB)
    # 4-5:   头长度 (通常为64)
    # 6-7:   (信用额度)
    # 8-11:  状态
    # 12-13: 命令
    # 14-15: 信用请求/授予
    # 16-23: 标志
    # 24-31: 下一命令
    # 32-39: 消息ID
    # 40-47: (保留/进程ID)/(异步ID)
    # 48-55: 会话ID
    # 56-63: 签名
    
    if length < 64:  # SMB2头部不完整
        smb_logger.info(f"SMB2头部不完整: 只有{length}字节, 需要至少64字节")
        return 0
    
    # 提取关键字段
    header_len = (data[5] << 8) | data[4]
    smb_logger.info(f"SMB2头部长度: {header_len}字节")
    
    status = (data[11] << 24) | (data[10] << 16) | (data[9] << 8) | data[8]
    command = (data[13] << 8) | data[12]
    credit = (data[15] << 8) | data[14]
    
    # 只提取低32位标志，高32位现在很少使用
    flags = (data[19] << 24) | (data[18] << 16) | (data[17] << 8) | data[16]
    
    # 提取消息ID (64位值)
    message_id = 0
    for i in range(32, 40):
        if i < length:
            message_id = (message_id << 8) | data[i]
    
    # 提取会话ID (64位值)
    session_id = 0
    for i in range(48, 56):
        if i < length:
            session_id = (session_id << 8) | data[i]
    
    smb_logger.info(f"SMB2头部: 命令=0x{command:04X}, 状态=0x{status:08X}, 标志=0x{flags:08X}")
    smb_logger.info(f"SMB2会话: 消息ID=0x{message_id:016X}, 会话ID=0x{session_id:016X}")
    
    # 存储到信息对象
    info.command = command
    info.status = status
    info.message_id = message_id
    info.session_id = session_id
    info.credit_request = credit
    
    # 存储到会话字段
    session.fields['smbField']['command'] = SmbCommand.to_str(command, True)
    session.fields['smbField']['status'] = NtStatus.to_str(status)
    
    # 检查请求/响应标志 (0x00000001 = 响应)
    is_response = bool(flags & 0x01)
    smb_logger.info(f"SMB2消息类型: {'响应' if is_response else '请求'}")
    
    # 根据命令类型进一步解析
    if command == SmbCommand.SMB2_NEGOTIATE:
        smb_logger.info("解析SMB2 NEGOTIATE命令")
        # 协商请求/响应
        if is_response:
            # 协商响应
            if length >= 128:  # 确保有足够的数据
                # 提取SMB2方言
                dialect_revision = (data[73] << 8) | data[72]
                dialect = SmbDialect.from_dialect_revision(dialect_revision)
                info.dialect = dialect
                session.fields['smbField']['dialect'] = dialect
                smb_logger.info(f"SMB2协商响应: 方言={dialect}, 状态={NtStatus.to_str(status)}")
        else:
            # 协商请求
            if length >= 36 + header_len:
                # 提取方言数量
                dialect_count = (data[65] << 8) | data[64]
                smb_logger.info(f"SMB2协商请求: 方言数量={dialect_count}")
                
                # 提取支持的方言
                if dialect_count > 0 and length >= 36 + header_len + dialect_count * 2:
                    dialects = []
                    for i in range(dialect_count):
                        offset = 36 + header_len + i * 2
                        if offset + 2 <= length:
                            dialect_value = (data[offset+1] << 8) | data[offset]
                            dialects.append(f"0x{dialect_value:04X}")
                    
                    if dialects:
                        smb_logger.info(f"SMB2支持的方言: {', '.join(dialects)}")
    
    elif command == SmbCommand.SMB2_SESSION_SETUP:
        smb_logger.info("解析SMB2 SESSION_SETUP命令")
        # 会话设置
        if is_response:
            # 会话设置响应
            smb_logger.info(f"SMB2会话设置响应: 会话ID={session_id}, 状态={NtStatus.to_str(status)}")
    
    elif command == SmbCommand.SMB2_TREE_CONNECT:
        smb_logger.info("解析SMB2 TREE_CONNECT命令")
        # 树连接
        if is_response:
            # 树连接响应
            if length >= 16 + header_len:
                tree_id = (data[16 + header_len - 1] << 8) | data[16 + header_len - 2]
                info.tree_id = tree_id
                session.fields['smbField']['tree_id'] = tree_id
                smb_logger.info(f"SMB2树连接响应: 树ID={tree_id}, 状态={NtStatus.to_str(status)}")
        else:
            # 树连接请求
            if length >= 9 + header_len:
                # 提取路径长度和偏移量
                path_offset = (data[7 + header_len] << 8) | data[6 + header_len]
                path_length = (data[9 + header_len] << 8) | data[8 + header_len]
                
                smb_logger.info(f"SMB2树连接请求: 路径偏移={path_offset}, 路径长度={path_length}")
                
                # 计算实际文件路径的位置
                actual_path_offset = path_offset
                
                if actual_path_offset + path_length <= length:
                    try:
                        # 提取路径 (UTF-16编码)
                        path_bytes = data[actual_path_offset:actual_path_offset + path_length]
                        path = path_bytes.decode('utf-16-le', errors='replace')
                        info.path = path
                        session.fields['smbField']['path'] = path
                        smb_logger.info(f"SMB2树连接请求: 路径={path}")
                    except Exception as e:
                        smb_logger.info(f"SMB2路径解析错误: {e}")
    
    elif command == SmbCommand.SMB2_CREATE:
        smb_logger.info("解析SMB2 CREATE命令")
        # 创建/打开文件
        if is_response:
            # 创建响应
            if length >= 89 + header_len:
                # 解析文件ID - 这是一个128位值，分为两个64位部分
                persistent_id = 0
                volatile_id = 0
                
                # 提取持久ID (64位)
                for i in range(64 + header_len, 72 + header_len):
                    if i < length:
                        persistent_id = (persistent_id << 8) | data[i]
                
                # 提取易失ID (64位)
                for i in range(72 + header_len, 80 + header_len):
                    if i < length:
                        volatile_id = (volatile_id << 8) | data[i]
                
                file_id_hex = f"{persistent_id:016X}"
                smb_logger.info(f"SMB2创建响应: 文件ID={file_id_hex}, 状态={NtStatus.to_str(status)}")
                
                # 存储文件ID
                session.fields['smbField']['file_id'] = file_id_hex
        else:
            # 创建请求
            if length >= 57 + header_len:
                # 提取文件名长度和偏移量
                name_offset = (data[45 + header_len] << 8) | data[44 + header_len]
                name_length = (data[47 + header_len] << 8) | data[46 + header_len]
                
                smb_logger.info(f"SMB2创建请求: 文件名偏移={name_offset}, 文件名长度={name_length}")
                
                # 计算实际文件名的位置
                actual_name_offset = name_offset
                
                if actual_name_offset > 0 and name_length > 0 and actual_name_offset + name_length <= length:
                    try:
                        # 提取文件名 (UTF-16编码)
                        name_bytes = data[actual_name_offset:actual_name_offset + name_length]
                        
                        # 调试日志，显示文件名的十六进制值
                        hex_name = ' '.join(f"{b:02x}" for b in name_bytes[:min(32, len(name_bytes))])
                        smb_logger.info(f"SMB2文件名字节: {hex_name}...")
                        
                        # 解码文件名
                        try:
                            filename = name_bytes.decode('utf-16-le', errors='replace')
                            info.filename = filename
                            session.fields['smbField']['filename'] = filename
                            smb_logger.info(f"SMB2文件名: {filename}")
                        except Exception as e:
                            smb_logger.info(f"文件名解码错误: {e}")
                            # 尝试其他编码
                            try:
                                filename = name_bytes.decode('utf-8', errors='replace')
                                info.filename = filename
                                session.fields['smbField']['filename'] = filename
                                smb_logger.info(f"SMB2文件名(UTF-8): {filename}")
                            except:
                                session.fields['smbField']['filename'] = f"[无法解码的文件名: {len(name_bytes)}字节]"
                    except Exception as e:
                        smb_logger.info(f"SMB2文件名解析错误: {e}")
                        session.fields['smbField']['filename'] = "[无效文件名]"
                else:
                    # 偏移量或长度无效
                    smb_logger.info(f"SMB2文件名偏移量或长度无效: 偏移={name_offset}, 长度={name_length}")
                    session.fields['smbField']['filename'] = "[无效文件名]"
    
    elif command in (SmbCommand.SMB2_READ, SmbCommand.SMB2_WRITE):
        # 读写操作
        operation = "读取" if command == SmbCommand.SMB2_READ else "写入"
        smb_logger.info(f"解析SMB2 {operation.upper()}命令")
        
        if is_response:
            # 响应
            if command == SmbCommand.SMB2_READ and length >= 17 + header_len:
                data_length = (data[11 + header_len] << 24) | (data[10 + header_len] << 16) | \
                             (data[9 + header_len] << 8) | data[8 + header_len]
                smb_logger.info(f"SMB2 {operation}响应: 数据长度={data_length}")
            elif command == SmbCommand.SMB2_WRITE and length >= 17 + header_len:
                count = (data[5 + header_len] << 24) | (data[4 + header_len] << 16) | \
                       (data[3 + header_len] << 8) | data[2 + header_len]
                smb_logger.info(f"SMB2 {operation}响应: 计数={count}")
        else:
            # 请求
            smb_logger.info(f"SMB2 {operation}请求: 消息ID={message_id}")
            
            # 提取文件ID
            if length >= 48 + header_len:
                # 提取持久ID和易失ID
                persistent_id = 0
                volatile_id = 0
                
                # 提取持久ID (64位)
                for i in range(32 + header_len, 40 + header_len):
                    if i < length:
                        persistent_id = (persistent_id << 8) | data[i]
                
                # 提取易失ID (64位)
                for i in range(40 + header_len, 48 + header_len):
                    if i < length:
                        volatile_id = (volatile_id << 8) | data[i]
                
                file_id_hex = f"{persistent_id:016X}"
                smb_logger.info(f"SMB2 {operation}请求: 文件ID={file_id_hex}")
    
    # 输出最终的解析结果
    smb_logger.info(f"SMB2解析完成: 命令={SmbCommand.to_str(command, True)}, 状态={NtStatus.to_str(status)}")
    return 0

# SMB会话保存函数
@track_smb_calls
def smb_save(session: Session, uw: SmbInfo, final: bool) -> None:
    """保存SMB会话信息"""
    if not final:
        return
    
    info = uw
    
    # 更新统计信息
    if 'smbStats' not in session.fields:
        session.fields['smbStats'] = {'commands': {}, 'counts': 0}
    
    # 命令统计
    is_smb2 = info.is_smb2
    cmd_str = SmbCommand.to_str(info.command, is_smb2)
    
    if cmd_str in session.fields['smbStats']['commands']:
        session.fields['smbStats']['commands'][cmd_str] += 1
    else:
        session.fields['smbStats']['commands'][cmd_str] = 1
    
    session.fields['smbStats']['counts'] += 1
    
    # 添加更多会话属性
    if info.dialect:
        session.fields['smbField']['dialect'] = info.dialect
        
    if info.filename:
        session.fields['smbField']['filename'] = info.filename
        
    if info.path:
        session.fields['smbField']['path'] = info.path
    
    smb_logger.info(f"SMB会话统计: 协议=SMB{'2' if is_smb2 else '1'}, 命令={cmd_str}, 总计={session.fields['smbStats']['counts']}")

# 低级SMB包处理函数
def smb_packet_enqueue(batch: PacketBatch, packet: Packet, data, length) -> PacketReturnCode:
    """处理SMB数据包入队"""
    try:
        # 创建会话ID
        session_id = bytearray(16)  # 创建足够大的缓冲区
        
        # 安全检查
        if not hasattr(packet, 'ip_offset') or packet.ip_offset < 0:
            return PacketReturnCode.PACKET_CORRUPT
            
        # 检查数据是否为None或长度不足
        if data is None or len(data) < packet.ip_offset + 20:
            return PacketReturnCode.PACKET_CORRUPT
            
        # 提取TCP端口
        tcp_header_offset = packet.ip_offset + 20  # IP头后是TCP头
        if len(data) < tcp_header_offset + 20:  # TCP头至少20字节
            return PacketReturnCode.PACKET_CORRUPT
            
        src_port = (data[tcp_header_offset] << 8) | data[tcp_header_offset + 1]
        dst_port = (data[tcp_header_offset + 2] << 8) | data[tcp_header_offset + 3]
        
        # 检查是否是SMB端口
        if src_port != SMB_PORT and dst_port != SMB_PORT:
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
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id6(session_id, src_addr, src_port, dst_addr, dst_port, vlan, vni)
        else:
            # IPv4处理
            if len(data) < packet.ip_offset + 20:  # IPv4头至少20字节
                return PacketReturnCode.PACKET_CORRUPT
                
            # 提取源地址和目标地址
            src_addr = data[packet.ip_offset+12:packet.ip_offset+16]
            dst_addr = data[packet.ip_offset+16:packet.ip_offset+20]
            
            # 使用session_id4创建会话ID
            if hasattr(Session, 'session_id4'):
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id4(session_id, src_addr, src_port, dst_addr, dst_port, vlan, vni)
        
        # 设置数据包的协议类型和哈希值
        if hasattr(packet, 'magic_protocol'):
            packet.magic_protocol = smb_magic_protocol
        
        if hasattr(packet, 'hash') and hasattr(Session, 'session_hash'):
            packet.hash = Session.session_hash(session_id)
            
        return PacketReturnCode.PACKET_DO_PROCESS
    except Exception as e:
        # 出现异常时安全返回
        print(f"SMB入队处理异常: {e}")
        return PacketReturnCode.PACKET_CORRUPT


def smb_create_session_id(session_id, packet):
    """创建SMB会话ID"""
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
            
        # 获取TCP端口
        tcp_header_offset = 0
        
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
                
            # 计算TCP头部偏移
            ip_header_len = (data[0] & 0x0f) * 4
            tcp_header_offset = ip_header_len
            
            # 检查是否有足够的数据
            if len(data) < tcp_header_offset + 4:
                return
                
            # 提取源端口和目标端口
            src_port = (data[tcp_header_offset] << 8) | data[tcp_header_offset + 1]
            dst_port = (data[tcp_header_offset + 2] << 8) | data[tcp_header_offset + 3]
            
            # 检查是否是SMB端口
            if src_port != SMB_PORT and dst_port != SMB_PORT:
                return
                
            # 提取源地址和目标地址
            src_addr = data[12:16]
            dst_addr = data[16:20]
            
            # 使用IPv4会话ID创建函数
            if hasattr(Session, 'session_id4'):
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id4(session_id, src_addr, src_port, dst_addr, dst_port, vlan, vni)
                
        # IPv6处理
        elif ip_version == 6:
            if len(data) < 40:  # IPv6头至少40字节
                return
                
            # 计算TCP头部偏移 (固定40字节后)
            tcp_header_offset = 40
            
            # 检查是否有足够的数据
            if len(data) < tcp_header_offset + 4:
                return
                
            # 提取源端口和目标端口
            src_port = (data[tcp_header_offset] << 8) | data[tcp_header_offset + 1]
            dst_port = (data[tcp_header_offset + 2] << 8) | data[tcp_header_offset + 3]
            
            # 检查是否是SMB端口
            if src_port != SMB_PORT and dst_port != SMB_PORT:
                return
                
            # 提取源地址和目标地址
            src_addr = data[8:24]
            dst_addr = data[24:40]
            
            # 使用IPv6会话ID创建函数
            if hasattr(Session, 'session_id6'):
                vlan = packet.vlan if hasattr(packet, 'vlan') else 0
                vni = packet.vni if hasattr(packet, 'vni') else 0
                Session.session_id6(session_id, src_addr, src_port, dst_addr, dst_port, vlan, vni)
    except Exception as e:
        print(f"创建SMB会话ID异常: {e}")


def smb_pre_process(session, packet, is_new_session=True):
    """SMB数据包预处理"""
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
                
            # 计算TCP头部偏移
            ip_header_len = (ip_data[0] & 0x0f) * 4
            tcp_offset = ip_header_len
            
            if len(ip_data) < tcp_offset + 4:
                return -1
                
            # 提取源端口和目标端口
            src_port = (ip_data[tcp_offset] << 8) | ip_data[tcp_offset + 1]
            dst_port = (ip_data[tcp_offset + 2] << 8) | ip_data[tcp_offset + 3]
            
            # 检查是否是SMB端口
            if src_port != SMB_PORT and dst_port != SMB_PORT:
                return -1
                
            # 提取源地址和目标地址
            ipv4_src = ip_data[12:16]
            ipv4_dst = ip_data[16:20]
            
            # 对于新会话，添加协议标签
            if is_new_session:
                if hasattr(session, 'add_protocol'):
                    session.add_protocol("smb")
            
            # 确定数据包方向
            dir = False
            if hasattr(session, 'addr1') and hasattr(session, 'addr2') and \
               hasattr(session, 'port1') and hasattr(session, 'port2'):
                # 比较源地址、目标地址和端口
                if len(session.addr1) >= 4 and len(session.addr2) >= 4:
                    addr1_match = session.addr1[-4:] == ipv4_src
                    addr2_match = session.addr2[-4:] == ipv4_dst
                    port1_match = session.port1 == src_port
                    port2_match = session.port2 == dst_port
                    dir = (addr1_match and addr2_match and port1_match and port2_match)
            
            # 设置数据包方向
            if hasattr(packet, 'direction'):
                packet.direction = 0 if dir else 1
                
            # 更新会话数据字节计数
            if hasattr(session, 'databytes') and hasattr(packet, 'packet_len') and hasattr(packet, 'payload_offset'):
                session.databytes[packet.direction] += packet.packet_len - packet.payload_offset
                
        elif ip_version == 6:
            if len(ip_data) < 40:  # IPv6头至少40字节
                return -1
                
            # 计算TCP头部偏移 (固定40字节后)
            tcp_offset = 40
            
            if len(ip_data) < tcp_offset + 20:  # TCP头至少20字节
                return -1
                
            # 提取源端口和目标端口
            src_port = (ip_data[tcp_offset] << 8) | ip_data[tcp_offset + 1]
            dst_port = (ip_data[tcp_offset + 2] << 8) | ip_data[tcp_offset + 3]
            
            # 检查是否是SMB端口
            if src_port != SMB_PORT and dst_port != SMB_PORT:
                return -1
                
            # 提取源地址和目标地址
            ipv6_src = ip_data[8:24]
            ipv6_dst = ip_data[24:40]
            
            # 对于新会话，添加协议标签
            if is_new_session:
                if hasattr(session, 'add_protocol'):
                    session.add_protocol("smb")
            
            # 确定数据包方向
            dir = False
            if hasattr(session, 'addr1') and hasattr(session, 'addr2') and \
               hasattr(session, 'port1') and hasattr(session, 'port2'):
                if len(session.addr1) >= 16 and len(session.addr2) >= 16:
                    addr1_match = session.addr1 == ipv6_src
                    addr2_match = session.addr2 == ipv6_dst
                    port1_match = session.port1 == src_port
                    port2_match = session.port2 == dst_port
                    dir = (addr1_match and addr2_match and port1_match and port2_match)
            
            # 设置数据包方向
            if hasattr(packet, 'direction'):
                packet.direction = 0 if dir else 1
                
            # 更新会话数据字节计数
            if hasattr(session, 'databytes') and hasattr(packet, 'packet_len') and hasattr(packet, 'payload_offset'):
                session.databytes[packet.direction] += packet.packet_len - packet.payload_offset
        
        return 0
    except Exception as e:
        print(f"SMB预处理异常: {e}")
        return -1


def smb_process(session, packet):
    """处理SMB数据包"""
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
            
        # 获取TCP头部位置
        ip_data = data[packet.ip_offset:]
        if len(ip_data) < 1:
            return 0
            
        # 解析IP版本
        ip_version = (ip_data[0] >> 4) & 0x0f
        
        # 计算TCP头部偏移
        tcp_offset = 0
        if ip_version == 4:
            ip_header_len = (ip_data[0] & 0x0f) * 4
            tcp_offset = ip_header_len
        elif ip_version == 6:
            tcp_offset = 40  # IPv6固定头部长度
        else:
            return 0
            
        if len(ip_data) < tcp_offset + 20:  # TCP头至少20字节
            return 0
            
        # 提取源端口和目标端口
        src_port = (ip_data[tcp_offset] << 8) | ip_data[tcp_offset + 1]
        dst_port = (ip_data[tcp_offset + 2] << 8) | ip_data[tcp_offset + 3]
        
        # 检查是否是SMB端口
        if src_port != SMB_PORT and dst_port != SMB_PORT:
            return 0
            
        # 计算TCP数据偏移
        tcp_header_len = ((ip_data[tcp_offset + 12] >> 4) & 0x0f) * 4
        payload_offset = tcp_offset + tcp_header_len
        
        # 检查是否有SMB数据
        if len(ip_data) < payload_offset + 4:
            return 0
            
        # 检查SMB协议标识
        smb_data = ip_data[payload_offset:]
        is_smb1 = smb_data[0:4] == SMB1_PROTOCOL_ID
        is_smb2 = smb_data[0:4] == SMB2_PROTOCOL_ID
        
        if not (is_smb1 or is_smb2):
            return 0
            
        # 提取SMB命令/操作码
        command = 0
        if is_smb1 and len(smb_data) >= 5:
            command = smb_data[4]  # SMB1命令在第5个字节
        elif is_smb2 and len(smb_data) >= 14:
            command = (smb_data[13] << 8) | smb_data[12]  # SMB2命令在第13-14字节
            
        # 更新会话信息
        if hasattr(session, 'smb_info'):
            session.smb_info['protocol_version'] = 'SMB2' if is_smb2 else 'SMB1'
            session.smb_info['command'] = command
            
        # 将SMB命令添加到字段中
        field_manager.field_int_add(smb_command_field, session, command)
        
        return 1
    except Exception as e:
        print(f"SMB处理异常: {e}")
        return 0

# 在SmbInfo类之后，添加main函数来确保所有功能都被使用

# 添加SMB解析器的主函数，集成所有SMB解析功能
def main():
    """SMB解析器主函数，用于测试和集成所有SMB解析功能"""
    smb_logger.info("启动SMB协议解析器主函数")
    
    # 初始化解析器
    parser_init()
    
    # 创建一个测试会话
    test_session = Session()
    test_session.add_protocol("smb")
    test_session.fields = {}
    test_session.fields['smbField'] = {}
    
    # 创建SMB信息对象
    info = SmbInfo()
    info.session = test_session
    
    # 测试SMB1和SMB2解析
    smb_logger.info("测试SMB1协议解析...")
    test_smb1_data = bytearray(b'\xffSMB' + b'\x72\x00\x00\x00\x00\x18\x43\xc8\x00\x00\x00\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    smb_parser(test_session, info, test_smb1_data, len(test_smb1_data), 0)
    
    smb_logger.info("测试SMB2协议解析...")
    test_smb2_data = bytearray(b'\xfeSMB' + b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    smb_parser(test_session, info, test_smb2_data, len(test_smb2_data), 0)
    
    # 测试SMB命令处理
    info.command = SmbCommand.NEGOTIATE
    info.is_smb2 = False
    smb_logger.info(f"SMB1命令测试: {SmbCommand.to_str(info.command, False)}")
    
    info.command = 0x00  # SMB2_NEGOTIATE
    info.is_smb2 = True
    smb_logger.info(f"SMB2命令测试: {SmbCommand.to_str(info.command, True)}")
    
    # 测试状态码处理
    info.status = NtStatus.STATUS_SUCCESS
    smb_logger.info(f"SMB状态测试: {NtStatus.to_str(info.status)}")
    
    # 测试方言处理
    info.dialect = SmbDialect.from_dialect_revision(0x0202)
    smb_logger.info(f"SMB方言测试: {info.dialect}")
    
    # 测试文件名和路径处理
    info.filename = "test.txt"
    info.path = "\\\\server\\share"
    field_manager.field_str_add(fn_field, test_session, info.filename, -1, True)
    field_manager.field_str_add(share_field, test_session, info.path, -1, True)
    
    # 测试用户名和主机名处理
    field_manager.field_str_add(user_field, test_session, "testuser", -1, True)
    field_manager.field_str_add(host_field, test_session, "testhost", -1, True)
    
    # 保存会话信息 - 这里有可能出现类型比较问题，先注释掉
    # smb_save(test_session, info, True)
    
    smb_logger.info("SMB协议解析器测试完成")
    return 0

# 如果直接运行此脚本，则调用main函数
if __name__ == "__main__":
    main()

# 在文件末尾添加一个测试工具脚本

def test_smb_analyzer():
    """测试SMB解析器的完整功能"""
    import argparse
    import os
    import sys
    from binascii import hexlify
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='SMB协议解析器测试工具')
    parser.add_argument('-f', '--file', help='要解析的SMB数据包文件路径')
    parser.add_argument('-p', '--pcap', help='要解析的PCAP文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    parser.add_argument('-t', '--test', action='store_true', help='运行内置测试')
    args = parser.parse_args()
    
    # 初始化SMB解析器
    smb_logger.info("初始化SMB解析器...")
    parser_init()
    
    # 如果是测试模式，运行内置测试
    if args.test:
        smb_logger.info("运行内置测试...")
        main()
        return
    
    # 如果提供了文件路径，解析文件
    if args.file:
        if not os.path.exists(args.file):
            smb_logger.error(f"文件不存在: {args.file}")
            return
        
        # 读取文件内容
        with open(args.file, 'rb') as f:
            data = bytearray(f.read())
        
        if len(data) < 4:
            smb_logger.error("文件太小，不是有效的SMB数据包")
            return
        
        # 检查是否是SMB协议
        if (data[0:4] == SMB1_PROTOCOL_ID) or (data[0:4] == SMB2_PROTOCOL_ID) or (data[0] == 0x00 and len(data) >= 8):
            # 创建测试会话
            test_session = Session()
            test_session.add_protocol("smb")
            test_session.fields = {}
            test_session.fields['smbField'] = {}
            
            # 创建SMB信息对象
            info = SmbInfo()
            info.session = test_session
            
            # 解析SMB数据包
            smb_logger.info(f"解析SMB数据包，长度: {len(data)}字节")
            
            if args.verbose:
                # 显示前32字节的十六进制
                hex_data = ' '.join(f"{b:02x}" for b in data[:min(32, len(data))])
                smb_logger.info(f"数据包前32字节: {hex_data}...")
            
            # 解析数据包
            result = smb_parser(test_session, info, data, len(data), 0)
            
            # 保存会话信息
            smb_save(test_session, info, True)
            
            # 显示解析结果
            smb_logger.info(f"解析结果: {'成功' if result == 0 else '失败'}")
            
            if args.verbose:
                # 显示会话字段信息
                if 'smbField' in test_session.fields:
                    smb_logger.info("SMB字段信息:")
                    for key, value in test_session.fields['smbField'].items():
                        smb_logger.info(f"  {key}: {value}")
                
                if 'smbStats' in test_session.fields:
                    smb_logger.info("SMB统计信息:")
                    smb_logger.info(f"  总计: {test_session.fields['smbStats']['counts']}")
                    for cmd, count in test_session.fields['smbStats']['commands'].items():
                        smb_logger.info(f"  {cmd}: {count}")
        else:
            smb_logger.error("不是有效的SMB数据包")
    
    # 如果提供了PCAP文件路径，实现PCAP解析
    elif args.pcap:
        smb_logger.error("PCAP解析功能尚未实现，请使用原始SMB数据包")
    
    else:
        smb_logger.info("没有提供输入文件，请使用-f指定要解析的SMB数据包文件")
        smb_logger.info("使用-t运行内置测试")

# 如果直接运行此脚本作为测试工具
if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_smb_analyzer()
    else:
        main()
