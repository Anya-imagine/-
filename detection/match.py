from detection.Build_Trie import *
from detection.load_rule import *
from ipaddress import ip_network
import re
from detection.PacketParser import Packet

class RuleMatch:
    """
    规则匹配引擎类
    负责将数据包与Snort规则进行匹配，使用AC自动机实现高效的多模式字符串匹配
    """
    def __init__(self):
        """
        初始化规则匹配引擎
        :param rules: 一组已解析的RuleParse规则对象列表
        """
        load_rules = Load()
        rules = load_rules.load_rule()

        # 按规则ID建立索引，便于快速查找
        self.rules = {str(rule.options.get('sid', None)): rule for rule in rules}

        # 缓存已编译的正则表达式
        self.pcre_cache = {}

        #按规则的正则表达式建立索引
        self.pcre_index = {}

        for rule in rules:
            pcre_pattern = rule.options.get('pcre')
            if pcre_pattern:
                self.pcre_index[str(pcre_pattern)] = rule
        
    @staticmethod
    def _ip_in_network(pkt_ip, rule_net):
        """
        判断一个IP地址是否属于指定的网络范围
        :param ip_addr: 要检查的IP地址
        :param network: IP网络对象或None（表示匹配任何IP）
        :return: 布尔值，表示是否匹配
        """
        if rule_net is None:
            return True
        
        # 处理单个IP地址的情况
        for net in rule_net:
            start, end = net
            if  start <= ip_network(pkt_ip) <= end:
                return True
            
        return False

    def _check_direction(self, pkt_session, rule):
        """检查数据包方向是否匹配规则方向"""

        if not rule.direction:
            return True

        # 处理双向规则
        if rule.direction == '<>':
            # 正向或反向都匹配
            return ((self._ip_in_network(pkt_session.src_ip, rule.src_net) and
                    self._ip_in_network(pkt_session.dst_ip, rule.dst_net)) or
                    (self._ip_in_network(pkt_session.dst_ip, rule.src_net) and
                     self._ip_in_network(pkt_session.src_ip, rule.dst_net)))
        # 处理单向规则（->）
        return (self._ip_in_network(pkt_session.src_ip, rule.src_net) and 
                self._ip_in_network(pkt_session.dst_ip, rule.dst_net))

    @staticmethod
    def _port_in_range(pkt_port, rule_port_range):
        """
        检查数据包的端口是否在规则定义的端口范围内
        :param pkt_port: 数据包的端口号
        :param rule_port_range: 规则中定义的端口范围元组(最小值,最大值)或None（表示匹配任何端口）
        :return: 布尔值，表示端口是否匹配
        """


        if rule_port_range is None:
            return True
        
        T_port = rule_port_range.get(True)
        F_port = rule_port_range.get(False)

        
        if T_port:
            for port in T_port:
                start, end = port
                if start <= pkt_port <= end:
                    return True

        if F_port:
            for port in F_port:
                start,end = port
                if start <= pkt_port <= end:
                    return False
            return True
        
        return False




    @staticmethod
    def _check_protocol(protocols, rule_protocol):
        """检查协议是否匹配"""
        # protocols 应该是一个集合，包含所有检测到的协议
        # rule_protocol 是规则中指定的协议
        if rule_protocol == 'tcp':
            # 如果规则是 TCP，那么 HTTP/SOCKS/SSH/TLS/SMB 都应该匹配
            return ('tcp' in protocols or 
                    'http' in protocols or 
                    'socks' in protocols or 
                    'ssh' in protocols or 
                    'tls' in protocols or 
                    'smb' in protocols)
        return rule_protocol in protocols
    
    def _check_pcre(self, payload, rule):
        """
        检查正则表达式匹配
        支持Snort PCRE语法，针对不同数据部分进行匹配
        
        :param pkt_info: 解析后的数据包信息
        :param rule: 要匹配的规则
        :return: 布尔值，表示正则表达式是否匹配
        """
        pcre_pattern = rule.options.get('pcre')
        if not pcre_pattern:
            return True  # 没有PCRE选项，默认匹配
            
        # 尝试从缓存获取编译好的正则表达式
        if pcre_pattern not in self.pcre_cache:
            try:
                # 解析Snort PCRE语法
                pattern, flags = self._parse_snort_pcre(pcre_pattern)
                self.pcre_cache[pcre_pattern] = re.compile(pattern, flags)
            except Exception as e:
                print(f"PCRE编译错误: {str(e)} in {pcre_pattern}")
                return False
                
        compiled_re = self.pcre_cache[pcre_pattern]
        
        
        # 默认匹配原始载荷
        payload_text = payload.decode('utf-8', errors='ignore')
        return bool(compiled_re.search(payload_text))
        
    def _parse_snort_pcre(self, pcre_pattern):
        """
        解析Snort PCRE语法
        转换Snort格式的PCRE为Python正则表达式
        
        :param pcre_pattern: Snort PCRE语法的正则表达式
        :return: (pattern, flags) 元组，包含处理后的模式和标志
        """
        # Snort PCRE格式: /pattern/flags

        pcre_pattern = pcre_pattern.strip()

        if pcre_pattern.startswith('"'):
            pcre_pattern = pcre_pattern[1:-1]

        pcre_pattern = pcre_pattern.strip()

        if not pcre_pattern.startswith('/'):
            return pcre_pattern, 0
            
        # 找到最后一个斜杠的位置
        last_slash = pcre_pattern.rindex('/')
        if last_slash <= 0:
            return pcre_pattern, 0
            
        pattern = pcre_pattern[1:last_slash]
        flags_str = pcre_pattern[last_slash+1:]
        
        # 转换标志
        flags = 0
        if 'i' in flags_str:  # 不区分大小写
            flags |= re.IGNORECASE
        if 'm' in flags_str:  # 多行模式
            flags |= re.MULTILINE
        if 's' in flags_str:  # 点匹配所有字符包括换行
            flags |= re.DOTALL
        if 'x' in flags_str:  # 忽略空白字符
            flags |= re.VERBOSE
        if 'A' in flags_str:  # 只匹配字符串开头
            pass
        if 'G' in flags_str:  # 全局匹配
            pass

        return pattern, flags
        
        
    def _check_flow(self, pkt_session, rule):
        """检查流量状态是否匹配"""
        if not rule.flow:  # 如果规则没有指定流状态，则匹配所有状态
            return True
            
        # 根据不同协议检查流状态
        if pkt_session.has_protocol('tls'):
            if rule.flow == 'established' and 'tls.cipher' in pkt_session.fields:
                return True  # TLS 握手完成
        elif pkt_session.has_protocol('ssh'):
            if rule.flow == 'established' and pkt_session.ssh_client_version:
                return True  # SSH 版本交换完成
        elif pkt_session.has_protocol('http'):
            return True  # HTTP 是无状态的
        
        return False
        
    def _check_rule_conditions(self, pkt_session, rule):
        """
        检查所有规则条件
        集中检查所有匹配条件，包括协议、方向、内容等
        
        :param pkt_info: 解析后的数据包信息
        :param rule: 要匹配的规则
        :return: 布尔值，表示是否满足所有条件
        """
        # 检查基本条件（协议、方向、端口）
        if not self._check_protocol(pkt_session.protocols, rule.protocol):
            return False
            
        if not self._check_direction(pkt_session, rule):
            return False
            
        # 检查源端口和目标端口
        if hasattr(pkt_session, 'src_port') and pkt_session.src_port is not None:
            if not self._port_in_range(pkt_session.src_port, rule.src_port):
                return False
            
        if hasattr(pkt_session, 'dst_port') and pkt_session.dst_port is not None:
            if not self._port_in_range(pkt_session.dst_port, rule.dst_port):
                return False
            
        # 检查流量状态
        if not self._check_flow(pkt_session, rule):
            return False
            
        return True
        
    def match_check(self, pkt_session):
        matched_rules = set()
        potential_rules = set()
        AC_rules = []
        payload_str = set()

        try:
            # 根据 session 中的协议标记来判断是什么协议
            if pkt_session.has_protocol("icmp"):
                # ICMP session 属性
                session_attrs = {
                    'icmp_type': pkt_session.icmp_type,
                    'icmp_code': pkt_session.icmp_code,
                    'icmp_type_name': pkt_session.icmp_type_name,
                    'icmp_src_ip': pkt_session.icmp_src_ip,
                    'icmp_dst_ip': pkt_session.icmp_dst_ip,
                    'icmp_timestamp': pkt_session.icmp_timestamp,
                    'icmp_id': pkt_session.icmp_id,
                    'icmp_seq': pkt_session.icmp_seq
                }
                if hasattr(pkt_session, 'icmp_payload'):
                    payload_str.add(pkt_session.icmp_payload)
                
                # 添加 ICMP 规则
                for rule in self.rules.values():
                    if rule.protocol == 'icmp':
                        AC_rules.append(rule)

            elif pkt_session.has_protocol("http"):
                # HTTP session 属性
                session_attrs = {
                    'http_methods': pkt_session.fields.get('http.method', set()),
                    'http_status': pkt_session.fields.get('http.status', set()),
                    'http_hosts': pkt_session.fields.get('http.host', set()),
                    'http_user_agents': pkt_session.fields.get('http.user_agent', set()),
                    'http_content_types': pkt_session.fields.get('http.content_type', set())
                }
                if hasattr(pkt_session, 'http_obj') and hasattr(pkt_session.http_obj, 'payload'):
                    payload_str.add(pkt_session.http_obj.payload)

                # 添加 HTTP 和 TCP 规则
                for rule in self.rules.values():
                    if rule.protocol in ('http', 'tcp'):
                        AC_rules.append(rule)

            elif pkt_session.has_protocol("smb"):
                # SMB session 属性
                session_attrs = {
                    'smb_command': getattr(pkt_session, 'command', None),
                    'smb_status': getattr(pkt_session, 'status', None),
                    'smb_dialect': getattr(pkt_session, 'dialect', None),
                    'smb_path': getattr(pkt_session, 'path', None),
                    'smb_filename': getattr(pkt_session, 'filename', None),
                    'smb_domain': getattr(pkt_session, 'domain', None)
                }
                if hasattr(pkt_session, 'smb_payload'):
                    payload_str.add(pkt_session.smb_payload)

                # 添加 SMB 和 TCP 规则
                for rule in self.rules.values():
                    if rule.protocol in ('smb', 'tcp'):
                        AC_rules.append(rule)

            elif pkt_session.has_protocol("socks"):
                # SOCKS session 属性
                session_attrs = {
                    'socks_hosts': pkt_session.fields.get('host.socks', set()),
                    'socks_users': pkt_session.fields.get('socks.user', set())
                }

                # 添加 SOCKS 和 TCP 规则
                for rule in self.rules.values():
                    if rule.protocol in ('socks', 'tcp'):
                        AC_rules.append(rule)

            elif pkt_session.has_protocol("ssh"):
                # SSH session 属性
                session_attrs = {
                    'ssh_client_version': getattr(pkt_session, 'ssh_client_version', None),
                    'ssh_server_version': getattr(pkt_session, 'ssh_server_version', None),
                    'ssh_versions': pkt_session.fields.get('ssh.ver', set())
                }
                if hasattr(pkt_session, 'ssh_payload'):
                    payload_str.add(pkt_session.ssh_payload)

                # 添加 SSH 和 TCP 规则
                for rule in self.rules.values():
                    if rule.protocol in ('ssh', 'tcp'):
                        AC_rules.append(rule)

            elif pkt_session.has_protocol("tls"):
                # TLS session 属性
                session_attrs = {
                    'tls_versions': pkt_session.fields.get('tls.ver', set()),
                    'tls_ja3': pkt_session.fields.get('tls.ja3', set()),
                    'tls_ja4': pkt_session.fields.get('tls.ja4', set()),
                    'tls_ja3s': pkt_session.fields.get('tls.ja3s', set()),
                    'tls_cipher': pkt_session.fields.get('tls.cipher', set())
                }
                if hasattr(pkt_session, 'tls_payload'):
                    payload_str.add(pkt_session.tls_payload)

                # 添加 TLS 和 TCP 规则
                for rule in self.rules.values():
                    if rule.protocol in ('tls', 'tcp'):
                        AC_rules.append(rule)

            # 创建自动机
            insens_automaton = ACAutomaton(AC_rules, case_sensitive=True)
            sens_automaton = ACAutomaton(AC_rules, case_sensitive=False)

            # 如果没有payload，检查不需要内容匹配的规则
            if not payload_str:
                for rule in AC_rules:
                    if not rule.options.get('content') and not rule.options.get('pcre'):
                        if self._check_session_attrs(session_attrs, rule):
                            potential_rules.add(rule)
            else:
                # 处理所有payload
                for payload in payload_str:
                    # 检查正则表达式规则
                    for rule in self.pcre_index.values():
                        if self._check_pcre(payload, rule) and self._check_session_attrs(session_attrs, rule):
                            potential_rules.add(rule)

                    # 转换为字符串进行内容匹配
                    try:
                        payload_text = payload.decode('utf-8', errors='ignore')
                        matches = insens_automaton.search(payload_text)
                        matches.update(sens_automaton.search(payload_text))
                        for rule in matches:
                            if self._check_session_attrs(session_attrs, rule):
                                potential_rules.add(rule)
                    except (AttributeError, UnicodeDecodeError):
                        continue

            # 最终规则条件检查
            for rule in potential_rules:
                if self._check_rule_conditions(pkt_session, rule):
                    matched_rules.add(rule)

        except ValueError as e:
            raise ValueError(f'错误：{e}')

        return matched_rules
        
    def process_packet_batch(self, pkt_info, auto_log=False):

        try:
            if pkt_info.icmp:
                pkt_session = pkt_info.icmp
            elif pkt_info.http:
                pkt_session = pkt_info.http
            elif pkt_info.smb:
                pkt_session = pkt_info.smb
            elif pkt_info.socks:
                pkt_session = pkt_info.socks
            elif pkt_info.ssh:
                pkt_session = pkt_info.ssh
            elif pkt_info.tls:
                pkt_session = pkt_info.tls
        except Exception as e:
            raise Exception(f'错误：{e}')

        results = set()
        try:
            matches = self.match_check(pkt_session)
            if matches:
                results.add(matches)
        except Exception as e:
            raise Exception(f'错误：{e}')
                
        return results
        
    
def test():
    run_match = RuleMatch()
    pkt_info = Packet()
    parse_pkt = pkt_info.get_info()
    match_rule = run_match.process_packet_batch(parse_pkt)
    return match_rule

if __name__ == "__main__":
    test()

        



