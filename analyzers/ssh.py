import base64
import configparser
import hashlib
import sys
import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Any, List, Tuple, Dict
from enum import Enum

try:
    from .imports import (
        field_manager,
        FieldType,
        FIELD_FLAG_CNT,
        Session
    )
except ImportError:
    from analyzers.imports import (
        field_manager,
        FieldType,
        FIELD_FLAG_CNT,
        Session
    )

from analyzers.BSB import BSB
from analyzers.field import FieldManager, FieldType, FIELD_FLAG_CNT, field_manager
from analyzers.parsers import parsers_call_named_func, parsers_register2, parsers_classifier_register_tcp, \
    parsers_get_named_func, API_VERSION
from analyzers.session import Session

# 添加NameInfo类定义，解决初始化错误
class NameInfo:
    def __init__(self, funcs, id):
        self.funcs = funcs
        self.id = id

config = configparser.ConfigParser()
ver_field = 0
key_field = 0
hassh_field = 0
hassh_sever_field = 0
ssh_counting200_func = 0

MAX_LENGTHS = 200
MAX_SSH_BUFFER = 8192


class SSHInfo:
    def __init__(self):
        self.buf = [bytearray(MAX_SSH_BUFFER) for _ in range(2)]  # 为两个方向创建缓冲区
        self.length = [0, 0]  # 两个方向的长度
        self.packets = [0, 0]  # 两个方向的包计数
        self.packets200 = [0, 0]  # 用于计数的包
        self.counts = [[0, 0], [0, 0]]  # 计数阈值
        self.lengths = [[0] * MAX_LENGTHS, [0] * MAX_LENGTHS]  # 长度列表
        self.done = 0  # 完成标志
        self.done_rs = 0  # 反向shell完成标志
        self.send_counting200 = ssh_send_counting200  # 直接保存函数引用


def ssh_parser_key_init(session: Session, data, remaining, is_dst):
    bsb = BSB(data, remaining)
    h_buf = []
    h_bsb = BSB(h_buf, len(h_buf))
    length = 0
    value = 0

    bsb.skip(16)

    bsb.import_u32(length)
    bsb.import_ptr(value, length)
    h_bsb.export_ptr(value, length)
    h_bsb.import_u8(';')

    bsb.import_u32(length)
    bsb.skip(length)

    bsb.import_u32(length)
    bsb.import_ptr(value, length)

    if bsb.error:
        return

    if not is_dst:
        h_bsb.export_ptr(value, length)
        h_bsb.export_u8(';')

    bsb.import_u32(length)
    bsb.import_ptr(value, length)

    if bsb.error:
        return
    if is_dst:
        h_bsb.export_ptr(value, length)
        h_bsb.export_u8(';')

    bsb.import_u32(length)
    bsb.import_ptr(value, length)

    if bsb.error:
        return
    if not is_dst:
        h_bsb.export_ptr(value, length)
        h_bsb.export_u8(';')

    bsb.import_u32(length)
    bsb.import_ptr(value, length)

    if bsb.error:
        return
    if is_dst:
        h_bsb.export_ptr(value, length)
        h_bsb.export_u8(';')

    bsb.import_u32(length)
    bsb.import_ptr(value, length)

    if bsb.error:
        return
    if not is_dst:
        h_bsb.export_ptr(value, length)

    bsb.import_u32(length)
    bsb.import_ptr(value, length)

    if bsb.error:
        return
    if is_dst:
        h_bsb.export_ptr(value, length)

    if not bsb.error and not h_bsb.error:
        h_buf = bytes(h_bsb.buf[:h_bsb.ptr])
        md5 = hashlib.md5(h_buf).hexdigest()


def ssh_send_counting200(session: Session, ssh: SSHInfo):
    parsers_call_named_func(ssh_counting200_func, session, None, 0, ssh)


def ssh_parser(session: Session, uw, data, remaining, which):
    ssh = uw
    ssh.packets[which] += 1
    ssh.packets200[which] += 1

    if ssh.packets200[0] + ssh.packets200[1] <= MAX_LENGTHS:
        ssh.lengths[which][ssh.packets200[which] - 1] = remaining
        if ssh.packets200[0] + ssh.packets200[1] >= MAX_LENGTHS:
            ssh.send_counting200(session, ssh)
            ssh.packets200[0] = ssh.packets200[1] = 0

    if not ssh.done_rs and ssh.packets[which] > 5:
        if remaining < 50:
            ssh.counts[which][0] += 1
        elif remaining < 100:
            ssh.counts[which][1] += 1

        if ssh.packets[which] > 15:
            if ssh.counts[0][1] > ssh.counts[0][0] and ssh.counts[1][1] > ssh.counts[1][0]:
                session.add_tag("ssh-reverse-shell")

            ssh.done_rs = 1
            return 0
    # ssh->done is set when are finished decoding
    if ssh.done:
        return 0
    # Version handshake
    if remaining > 3 and data[:3] == b'SSH':
        n = data.find(b'\x0a', 0, remaining)
        if n != -1:  # 修复找不到换行符的问题
            if n > 0 and data[n-1] == 0x0d:
                n -= 1
            length = n
            try:
                # 直接使用之前定义的函数
                field_str_add_lower(ver_field, session, data[:length], length)
            except Exception as e:
                print(f"SSH版本字段添加失败: {e}")
                
        return 0

    # Actual messages - 修复内存操作
    buf_space = len(ssh.buf[which]) - ssh.length[which]
    copy_len = min(remaining, buf_space)
    if copy_len > 0:
        ssh.buf[which][ssh.length[which]:ssh.length[which] + copy_len] = data[:copy_len]
        ssh.length[which] += copy_len

    while ssh.length[which] > 6:
        bsb = BSB(ssh.buf[which], ssh.length[which])

        ssh_len = 0
        bsb.import_u32(ssh_len)

        if ssh_len < 2 or ssh_len > MAX_SSH_BUFFER:
            ssh.done = 1
            return 0

        if ssh_len > bsb.remaining():
            return 0

        ssh_code = 0
        bsb.skip(1)  # padding length
        bsb.import_u8(ssh_code)

        if ssh_code == 20:
            ssh_parser_key_init(session, bsb.work_ptr(), bsb.remaining(), which)
        elif ssh_code == 33:
            ssh.done = 1
            key_len = 0
            bsb.import_u32(key_len)

            if not bsb.error and bsb.remaining() >= key_len:
                key_str = base64.b64encode(bsb.buf[bsb.ptr:bsb.ptr + key_len]).decode('ascii')
                # 保存密钥到会话
                try:
                    field_str_add(key_field, session, key_str, len(key_str))
                except Exception as e:
                    print(f"SSH密钥字段添加失败: {e}")
            break

        # 更新缓冲区
        if ssh.length[which] > ssh_len + 4:
            # 移动剩余数据到缓冲区开头
            remaining_data = ssh.buf[which][ssh_len + 4:ssh.length[which]]
            ssh.buf[which][:len(remaining_data)] = remaining_data
            ssh.length[which] -= (ssh_len + 4)
        else:
            # 缓冲区数据已处理完
            ssh.length[which] = 0

    return 0


def ssh_save(session: Session, uw, final):
    ssh = uw

    # Call on save incase it wasn't called based on number of packets above
    ssh.send_counting200(session, ssh)


def ssh_classify(session: Session, data, length, which, uw):
    """SSH协议分类器"""
    # 如果会话已经有SSH协议标记，直接返回
    if session.has_protocol("ssh"):
        return
    
    # 检查是否是SSH版本字符串
    is_ssh = False
    if length > 4 and data[:4] == b'SSH-':
        is_ssh = True
        # 添加SSH版本信息到会话
        try:
            version_str = data[:min(length, 50)].decode('utf-8', 'ignore').strip()
            if 'ssh.ver' not in session.fields:
                session.fields['ssh.ver'] = set()
            session.fields['ssh.ver'].add(version_str)
            print(f"检测到SSH版本: {version_str}")
        except Exception as e:
            print(f"处理SSH版本信息失败: {e}")
    
    # 判断是否在监听SSH隧道常见端口
    if uw and isinstance(uw, dict):
        port = uw.get('src_port', 0) if which == 0 else uw.get('dst_port', 0)
        if port == 22:
            is_ssh = True
    
    # 如果确定是SSH协议，添加标记并注册解析器
    if is_ssh:
        # 添加SSH协议标记
        session.add_protocol("ssh")
        
        # 不需要尝试注册解析器，只需标记协议即可
        # SSH数据已经在process_ssh_packet函数中处理
        # 避免重复处理可能导致的错误
        
        # 将信息存储在会话对象上，而不是创建单独的SSH实例
        if 'ssh_data' not in session.fields:
            session.fields['ssh_data'] = {
                'packets': [0, 0],
                'packets200': [0, 0],
                'lengths': [[], []],
                'done': 0,
                'done_rs': 0
            }
        
        return True
    
    return False


def parser_init():
    global ver_field, key_field, hassh_field, hassh_sever_field, ssh_counting200_func
    
    # 导入field_manager实例而不是类
    try:
        from analyzers.field import field_manager
    except ImportError:
        print("⚠️ SSH模块：无法导入field_manager")
        return
    
    # 使用field_manager实例定义字段
    try:
        ver_field = field_manager.field_define("ssh", "lotermfield",
                                          "ssh.ver", "Version", "ssh.version",
                                          "SSH Software Version",
                                          FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                          None)

        key_field = field_manager.field_define("ssh", "termfield",
                                          "ssh.key", "Key", "ssh.key",
                                          "SSH Key",
                                          FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                          None)

        hassh_field = field_manager.field_define("ssh", "lotermfield",
                                            "ssh.hasshServer", "HASSH Server", "ssh.hasshServer",
                                            "SSH HASSH Server field",
                                            FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                            None)

        hassh_sever_field = field_manager.field_define("ssh", "lotermfield",
                                                  "ssh.hasshServer", "HASSH Server", "ssh.hasshServer",
                                                  "SSH HASSH Server field",
                                                  FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                                  None)
    except Exception as e:
        print(f"⚠️ SSH模块：字段定义出错: {e}")
        return
    
    # 导入parsers模块中的函数
    try:
        from analyzers.parsers import parsers_classifier_register_tcp, parsers_get_named_func, API_VERSION
        
        # 使用固定值代替动态检查，避免getsizeof问题
        session_size = 0  # 默认值，实际上parsers函数现在会忽略这个参数
        
        # 注册SSH分类器，添加所需的session_size和api_version参数
        try:
            parsers_classifier_register_tcp("ssh", None, 0, "SSH", 3, ssh_classify, session_size, API_VERSION)
            print("✅ SSH分类器注册成功")
        except Exception as e:
            print(f"⚠️ SSH分类器注册错误: {e}")
        
        # 获取命名函数，如果失败则使用默认值
        try:
            ssh_counting200_func = parsers_get_named_func("ssh_counting200")
            print("✅ SSH命名函数获取成功")
        except Exception as e:
            print(f"⚠️ SSH命名函数获取错误: {e}")
            ssh_counting200_func = 0  # 使用默认值
            
    except ImportError as e:
        print(f"⚠️ SSH模块：无法导入parsers函数: {e}")
    except Exception as e:
        print(f"⚠️ SSH模块初始化错误: {e}")
        
    print("✅ SSH模块初始化完成")

# 创建顶层函数
def field_str_add(field_id, session, data, length):
    """将字符串添加到字段"""
    return field_manager.field_str_add(field_id, session, data, length)

def field_str_add_lower(field_id, session, data, length):
    """将小写字符串添加到字段"""
    # 转换为小写 - 对于bytes和str都处理
    if isinstance(data, bytes):
        try:
            data_str = data[:length].decode('utf-8', 'ignore').lower()
            return field_str_add(field_id, session, data_str, len(data_str))
        except:
            return False
    elif isinstance(data, str):
        data_lower = data[:length].lower()
        return field_str_add(field_id, session, data_lower, len(data_lower))
    return False
