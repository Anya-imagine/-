import re
from ipaddress import ip_network
from dataclasses import dataclass, field
from typing import Dict, Any
from collections import defaultdict

@dataclass
class ContentParser:
    """内容解析器类，用于存储解析后的内容信息"""
    raw_value: str = ""  # 原始字符串值
    byte_value: bytes = b''  # 转换后的字节流
    modifiers: Dict[str, Any] = field(default_factory=dict)  # 修饰符列表
    negated_value: bool = False  # 是否否定匹配




class RuleParser:
    """
    Snort规则解析器的核心类，负责存储解析后的规则各个组件
    """
    def __init__(self, rule_str):

        self.rule_str = rule_str
        # 基本规则头部属性
        self.action = None        # 规则动作（alert, block, drop, log, pass, react）
        self.protocol = None      # 协议类型
        self.src_net = None       # 源网络
        self.src_port = None      # 源端口
        self.direction = None     # 方向操作符
        self.dst_net = None       # 目标网络
        self.dst_port = None      # 目标端口
        self.http_modifiers = []            # 用于存储 HTTP 相关选项
        # 规则选项
        self.options = defaultdict(list)
        # 规则内容
        self.parse_contents = []        # 初始化为空列表          # 添加 http 列表用于存储 HTTP 相关选项


class SnortRules:
    """
    Snort规则解析器类，负责解析规则字符串并提取各部分
    """
    def __init__(self, rule_str):
        """初始化Snort规则解析器"""
        self.rule_str = rule_str.strip()
        self.rule = RuleParser(rule_str)  # 创建RuleParser实例存储解析结果
        
        # 解析规则
        self._parse_rule()
 
        
    def is_standard(self, rule_str):
        """判断是否是标准Snort规则"""       
        is_standard_1 = re.match(r'(alert)\s+(udp|ip|icmp|ssl|tcp|http|ttl)\s+\((.*)\)', rule_str)
        is_standard_2 = re.match(r'(alert)\s+(udp|ip|icmp|ssl|tcp|http|ttl)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s+\((.*)\)', rule_str)

        if is_standard_1:
            header = [is_standard_1.group(1), is_standard_1.group(2), False, False, False, False, False]
            options = is_standard_1.group(3)
            return header, options
        elif is_standard_2:
            header = [is_standard_2.group(1), is_standard_2.group(2), is_standard_2.group(3), 
                     is_standard_2.group(4), is_standard_2.group(5), is_standard_2.group(6), 
                     is_standard_2.group(7)]
            options = is_standard_2.group(8)
            return header, options
        else:
            raise ValueError(f"无效的Snort规则格式: {rule_str}")
    


    def _parse_rule(self):
        """解析Snort规则字符串，提取头部和选项部分"""
        # 处理规则字符串，为解析做准备
        rule_str = self.rule_str.replace('\n', '')  # 替换任何换行为空格
        rule_str = rule_str.strip()

        # 检查是否是Snort 3的简化规则格式
        header, options = self.is_standard(rule_str)
        
        # 解析头部和选项部分
        self._parse_header(header)
        self._parse_options(options)
        
    def _parse_header(self, header):
        """解析规则头部: 动作 协议 源地址 源端口 方向 目标地址 目标端口"""
        
        # 处理新版本Snort的HTTP/SSL特定规则格式
        # 例如: alert http $EXTERNAL_NET any -> $HOME_NET any
        self.rule.action = header[0]      # 动作(alert, log, drop等)
        self.rule.protocol = header[1]    # 协议(http, ssl等)
        self.rule.src_net = self._parse_network(header[2]) if header[2] else None # 源网络
        self.rule.src_port = self._parse_port(header[3]) if header[3] else None # 源端口
        self.rule.direction = header[4] if header[4] else None   # -> 或 <>
        self.rule.dst_net = self._parse_network(header[5]) if header[5] else None  # 目标网络
        self.rule.dst_port = self._parse_port(header[6]) if header[6] else None    # 目标端口
                             
        
    def _parse_network(self, net_str):
        """解析IP网络地址，支持CIDR、IP列表、变量和'any'标记"""
        if not net_str or len(net_str) < 3:  # 添加长度检查
            return None
        
        net = set()  # 改为使用集合而不是字典

        try:
            if net_str == 'any':
                return None
                
            # 处理变量如 $HOME_NET
            if net_str.startswith('$'):
                return {net_str}
                
            #处理列表[ip1,ip2-ip3]
            if net_str.startswith('[') and net_str.endswith(']'):
                net_str = net_str[1:-1]
                net_str = net_str.split(',')
                for i in net_str:
                    if '-' in i:
                        start, end = i.split('-')
                        net.add((ip_network(start), ip_network(end)))
                    else:
                        net.add((ip_network(i), ip_network(i)))

            elif '-' in net_str:
                net_str = net_str.split('-')
                start, end = net_str
                net.add((ip_network(start), ip_network(end)))

            else:
                net.add((ip_network(net_str), ip_network(net_str)))
            
            return net
        
        except ValueError as e:
            raise ValueError(f"无效的IP地址格式: {net_str}, 错误信息: {str(e)}")
        
    def _parse_port(self, port_str):
        """解析端口表示，支持单个端口、端口范围、端口列表和'any'标记"""

        port_str = port_str.strip()

        # 处理变量如 $HTTP_PORTS
        if port_str.startswith('$'):
            return port_str
        
        port_str = port_str.strip()
        if re.search(r'\b(any|!any)\b', port_str, flags=re.IGNORECASE):
            return None
            
        result = {True: [], False: []}
        parts = re.findall(r'\[.*?\]|!?[\d:-]*', port_str.replace(',', ' '))

        for part in [p.strip() for p in parts if p.strip()]:
            # 处理列表元素 (如 [!1024:, 80])
            if part.startswith('[') and part.endswith(']'):
                for inner in re.findall(r'!?[\d:-]+', part[1:-1]):
                    inner = inner.strip()
                    if not re.fullmatch(r'!?\d+(?::\d*)?', inner):
                        raise ValueError(f"列表格式错误: {inner}")
                    if inner.count('!') > 1:
                        raise ValueError(f"列表中存在多重否定符: {inner}")

                    is_negated = inner.startswith('!')
                    content = inner[1:] if is_negated else inner

                    # 解析端口范围
                    if ':' in content:
                        start_str, end_str = content.split(':', 1)
                        start = int(start_str) if start_str else 1
                        end = int(end_str) if end_str else 65535
                    else:
                        start = end = int(content)

                    # 校验范围有效性
                    if not (0 <= start <= 65535) or not (0 <= end <= 65535):
                        raise ValueError(f"端口值越界: {start}:{end}")
                    if start > end:
                        raise ValueError(f"无效范围: {start}:{end}")

                    result[not is_negated].append((start, end))
                continue

            # 处理独立元素 (如 !1024:)
            if not re.fullmatch(r'!?\d+(?::\d*)?', part):
                raise ValueError(f"元素格式错误: {part}")
            if part.count('!') > 1:
                raise ValueError(f"多重否定符: {part}")

            is_negated = part.startswith('!')
            content = part[1:] if is_negated else part

            # 解析端口范围
            if ':' in content:
                start_str, end_str = content.split(':', 1)
                start = int(start_str) if start_str else 1
                end = int(end_str) if end_str else 65535
            else:
                start = end = int(content)

            # 校验范围有效性
            if not (0 <= start <= 65535) or not (0 <= end <= 65535):
                raise ValueError(f"端口值越界: {start}:{end}")
            if start > end:
                raise ValueError(f"无效范围: {start}:{end}")

            result[not is_negated].append((start, end))

        
        final = {
            True: result[True] if result[True] else None,
            False: result[False] if result[False] else None
        }
        return final if final[True] or final[False] else None


    def _parse_options(self, options_str):
        """解析规则选项部分，处理由分号分隔的键值对"""
        if not options_str:  # 处理选项为空的情况
            raise ValueError(f"无效的选项格式: {options_str}")
            
        options_str = options_str.strip()
        options = options_str.split(';')
        for option in options:
            try:
                option = option.strip()
                if option.startswith('http_'):
                    self.rule.http_modifiers.append(option)
                    continue
                
                if re.match(r'\S+', option) and ':' not in option:
                    self.rule.options[option] = True
                    continue


                if ':' in option:
                    key, value = option.split(':', 1)
                    key = key.strip()
                    value = value.strip()

                    if value.startswith('!'):
                        value = value[1:]
                        negated = True
                    else:
                        negated = False

                    if ',' in value and not (value.startswith('"')  and value.endswith('"')):
                        
                        parts = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', value)
                        value_str = [part.strip() for part in parts if part.strip()]

                        for v in value_str:
                            if v:
                                self.rule.options[key].append(v.strip())
                                if key == 'content':
                                    self.rule.parse_contents.append(self._parse_contents(self.rule.options.get('content', []), negated))

                        continue
                    else:
                        self.rule.options[key].append(value)
                        if key == 'content':
                            self.rule.parse_contents.append(self._parse_contents(self.rule.options.get('content', []), negated))

                        continue

                if not option:
                    continue

            except ValueError:
                raise ValueError(f"无效的选项格式: {option}")
            
            
            
    def _parse_contents(self, content_str, negated) -> ContentParser:
        """解析内容匹配选项，处理content"""
        try:
            parser = ContentParser()
            parser.negated_value = negated
            for content in content_str:
                if content.startswith('"') and content.endswith('"'):
                    parser.raw_value = content.strip('"')
                    parser.byte_value = self._parse_content(content)
                else:
                    key, value = self._parse_modifiers(content)
                    parser.modifiers[key] = value
        except ValueError:
            raise ValueError(f"无效的内容格式: {content_str, self.rule.options}")
        return parser

    def _parse_modifiers(self, content_str):
        """解析内容修饰符"""

        content_str = content_str.strip()
        if re.match(r'\S+\s+\S+', content_str):
            key, value = content_str.split(' ')
            return key, value
        else:
            key = content_str
            return key, True
        

        
    def _parse_content(self,content_str) -> bytes:
        hex_values = b''
        char_str = ''
        try:
            content_str = content_str.strip('"')
            if '|' in content_str:
                for char in content_str:
                    if char == '|':
                        if re.match(r'[0-9A-Fa-f]{2}\s[0-9A-Fa-f]{2}', char_str):
                            hex_values += bytes.fromhex(char_str.replace(' ', ''))

                        elif len(char_str) == 2 and re.match(r'[0-9A-Fa-f]{2}', char_str):
                            hex_values += bytes.fromhex(char_str)

                        else:
                            hex_values += bytes(char_str, 'utf-8')

                        char_str = ''
                    else:
                        char_str += char
                hex_values += bytes(char_str, 'utf-8')
            

            else:
                hex_values += bytes(content_str, 'utf-8')

        except ValueError:
                raise ValueError(f"无效的十六进制值: {content_str}")

        return hex_values

    def get_rule_parse(self):
        """返回解析后的规则对象"""
        return self.rule


def  test():
    """测试Snort规则解析器"""
    rules = []
    with open('./ruleset/community.rules', 'r') as f:
        for line in f:
            if not line.startswith('#') and line:
                rule = SnortRules(line)
                rules.append(rule.get_rule_parse())
    return rules


if __name__ == "__main__":

    rules = test()
    print(len(rules))
    print(type(rules[0]))
    all = set()

    #获取所有规则选项
    # for rule in rules:
    #     for key,value in rule.options.items():
    #         all.add(key)
    # print(all)


    #获取协议
    # for rule in rules:
    #     if rule.protocol:
    #         all.add(rule.protocol)
    # print(all)
    

    # 获取所有源网络
    # for rule in rules:
    #     if rule.src_net is not None:  # 添加 None 检查
    #         all.update(rule.src_net)
    # print(all)

    # 获取源端口
    # for rule in rules:
    #     # print(rule.src_port)
    #     if rule.src_port.startswith('$'):
    #         all.add(rule.src_port)
    #     else:
    #         if rule.src_port is not None:
    #             for port in rule.src_port.get(True,[]):
    #                 all.add(port)
    # print(all)

    # 获取所有目标网络
    # for rule in rules:
    #     if rule.dst_net is not None:  # 添加 None 检查
    #         all.update(rule.dst_net)
    # print(all)

    # 获取所有pcre
    # for rule in rules:
    #     #print(rule.src_port,rule.dst_port)
    #     pcre_str = rule.options.get('pcre')
    #     if pcre_str:
    #         index = pcre_str[0].rfind('/')
    #         all.add(pcre_str[0][index:])
    # print(all)
    #print(all)

    # 获取所有http修饰符
    # for rule in rules:
    #     for modifier in rule.http_modifiers:
    #         all.add(modifier)

    # print(all)

      

            

