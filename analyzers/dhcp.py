import configparser

from .field import field_manager
from analyzers.imports import (
    FieldType,
    FIELD_TYPE_IP_GHASH,
    FIELD_FLAG_CNT,
    FIELD_FLAG_IPPRE,
    FIELD_FLAG_FAKE,
    FIELD_TYPE_STR_HASH,
    FIELD_FLAG_FORCE_UTF8,
    FieldObject,
    Session
)
from analyzers.BSB import BSB
from analyzers.parsers import parsers_register, parsers_classifier_register_port, PARSERS_PORT_UDP

config = configparser.ConfigParser()
type_field = 0
host_field = 0
mac_field = 0
oui_field = 0
id_field = 0


def dhcpv6_udp_classify(session: Session, data, length, which, uw):
    if (data[0] != 1 and data[0] != 11) or not session.is_session_v6:
        return
    session.add_protocol("dhcpv6")


def dhcp_udp_parser(session: Session, uw, data, length, which):
    names = [
        "",
        "DISCOVER",
        "OFFER",
        "REQUEST",
        "DECLINE",
        "ACK",
        "NAK",
        "RELEASE",
        "INFORM",
        "FORCE_RENEW",
        "LEASE_QUERY",
        "LEASE_UNASSIGNED",
        "LEASE_UNKNOWN",
        "LEASE_ACTIVE",
        "BULK_LEASE_QUERY",
        "LEASE_QUERY_DONE",
        "ACTIVE_LEASE_QUERY",
        "LEASE_QUERY_STATUS",
        "TLS"
    ]
    if length < 256:
        return 0
    
    # 创建BSB对象
    bsb = BSB(data, length)
    
    # 检查硬件类型
    hard_ware_type = data[1]
    if hard_ware_type == 1:
        # 使用切片获取MAC地址
        mac_data = data[28:34]
        field_manager.field_mac_oui_add(session, mac_field, oui_field, mac_data)

    # 跳过前4个字节
    bsb.skip(4)
    
    # 读取事务ID
    id_value = bsb.read_u32()
    str_value = f"{id_value:x}"
    field_manager.field_str_add(id_field, session, str_value, -1, True)
    
    # 跳到选项开始位置
    # 236是选项区的偏移，+4是Magic Cookie的长度，-4是跳过的4字节，-4是读取的u32
    bsb.skip(236 + 4 - 4 - 4)
    
    # 处理DHCP选项
    while bsb.remaining() >= 2:
        # 读取选项类型
        t = bsb.read_u8()
        
        # 结束选项标记
        if t == 255:
            break
            
        # 读取选项长度
        l = bsb.read_u8()
        
        # 检查错误或长度无效
        if bsb.error or l > bsb.remaining() or l == 0:
            break
            
        # 根据选项类型处理
        if t == 12:  # 主机名
            # 获取主机名字符串
            host_str = bsb.get_bytes(l)
            if host_str:
                try:
                    host_name = host_str.decode('utf-8', errors='replace')
                    field_manager.field_str_add(host_field, session, host_name, -1)
                except Exception as e:
                    print(f"解析主机名错误: {e}")
                    
        elif t == 53 and l == 1:  # 消息类型
            # 读取类型值
            value = bsb.read_u8()
            if value < len(names):
                field_manager.field_str_add(type_field, session, names[value], -1, True)
            else:
                bsb.skip(l - 1)  # 已读取一个字节，跳过剩余
                
        elif t == 61 and l == 7:  # 客户端标识符
            # 读取硬件类型
            hwtype = bsb.read_u8()
            if hwtype == 1:  # 以太网
                # 获取MAC地址
                mac_str = bsb.get_bytes(6)
                if mac_str and len(mac_str) == 6:
                    field_manager.field_mac_oui_add(session, mac_field, oui_field, mac_str)
            else:
                bsb.skip(l - 1)  # 已读取一个字节，跳过剩余
                
        elif t == 81 and l >= 3:  # FQDN
            # 读取标志
            flags = bsb.read_u8()
            # 跳过两个保留字节
            bsb.skip(2)
            
            if flags == 0:  # 不支持任何编码
                # 获取域名
                fqdn_bytes = bsb.get_bytes(l - 3)
                if fqdn_bytes:
                    try:
                        fqdn = fqdn_bytes.decode('utf-8', errors='replace')
                        field_manager.field_str_add_lower(host_field, session, fqdn, -1)
                    except Exception as e:
                        print(f"解析FQDN错误: {e}")
            else:
                bsb.skip(l - 3)  # 已读取3个字节，跳过剩余
                
        else:
            # 跳过未知选项
            bsb.skip(l)
            
    return 0


def dhcp_udp_classify(session: Session, data, length, which, uw):
    # 检查必要条件：
    # 1. 长度至少为256字节
    # 2. 操作码是1(请求)或2(响应)
    # 3. 不是IPv6会话
    # 4. Magic Cookie在236偏移处正确
    if length < 256:
        print("分类失败: 数据包长度太短")
        return
        
    if data[0] != 1 and data[0] != 2:
        print("分类失败: 操作码既不是请求也不是响应")
        return
        
    if hasattr(session, 'is_session_v6') and session.is_session_v6:
        print("分类失败: 这是IPv6会话")
        return
        
    # 检查Magic Cookie (注意条件取反，应为相等才是DHCP协议)
    magic_cookie = data[236:240]
    expected = bytearray([0x63, 0x82, 0x53, 0x63])
    if magic_cookie != expected:
        print(f"分类失败: Magic Cookie不匹配 (实际={magic_cookie.hex()}, 期望={expected.hex()})")
        return

    # 通过所有检查，注册解析器
    print("分类成功: 所有条件都满足")
    parsers_register(session, dhcp_udp_parser, 0, 0)
    session.add_protocol("dhcp")


def dhcp_parser():
    global type_field, host_field, mac_field, oui_field, id_field
    
    type_field = field_manager.field_str_add("dhcp", "uptermfield",
                                            "dhcp.type", "Type", "dhcp.type",
                                            "DHCP Type",
                                            FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                            None)

    host_field = field_manager.field_str_add("dhcp", "lotermfield",
                                            "dhcp.host", "Host", "dhcp.host",
                                            "DHCP Host",
                                            FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                            "aliases", "[\"host.dhcp\"]",
                                            "category", "host",
                                            None)

    field_manager.field_define("dhcp", "lotextfield",
                              "dhcp.host.tokens", "Hostname Tokens", "dhcp.hostTokens",
                              "DHCP Hostname Tokens",
                              FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_FAKE,
                              "aliases", "[\"host.dhcp.tokens\"]",
                              None)

    mac_field = field_manager.field_str_add("dhcp", "lotermfield",
                                           "dhcp.mac", "Client MAC", "dhcp.mac",
                                           "Client ethernet MAC ",
                                           FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                           None)

    oui_field = field_manager.field_str_add("dhcp", "termfield",
                                           "dhcp.oui", "Client OUI", "dhcp.oui",
                                           "Client ethernet OUI ",
                                           FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                           None)

    id_field = field_manager.field_str_add("dhcp", "lotermfield",
                                          "dhcp.id", "Transaction id", "dhcp.id",
                                          "DHCP Transaction Id",
                                          FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                          None)

    # Add the missing session_size and api_version parameters
    parsers_classifier_register_port("dhcpv6", None, 547, PARSERS_PORT_UDP, dhcpv6_udp_classify, 0, 542)
    parsers_classifier_register_port("dhcp", None, 67, PARSERS_PORT_UDP, dhcp_udp_classify, 0, 542) 