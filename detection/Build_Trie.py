from collections import deque
import time
import logging
from typing import Dict, List, Tuple, Union, Set, Optional
from collections import defaultdict

# 配置日志 - 设置级别为 CRITICAL 以禁用大多数日志输出

class TrieNode:
    """
    AC自动机的Trie树节点类
    是AC自动机算法的基本构件，每个节点存储字符转换关系和匹配状态
    """
    __slots__ = ('children', 'fail', 'output', 'is_end', 'depth', 'value')
    
    def __init__(self, value=None, depth=0):
        """
        初始化Trie树节点
        
        :param value: 节点对应的字符值
        :param depth: 节点在Trie树中的深度
        """
        self.children: Dict[int, TrieNode] = {}  # 子节点字典（字符:节点）
        self.fail: Optional[TrieNode] = None  # 失败指针（类似KMP的失效函数）
        self.output: Set = set()  # 存储匹配成功的规则对象
        self.is_end: bool = False  # 标记是否为模式串终点
        self.depth: int = depth  # 节点深度，用于优化
        self.value = value  # 节点值，调试用


class ACAutomaton:
    """
    Aho-Corasick自动机实现类
    实现了一种高效的多模式字符串匹配算法，可以同时匹配多个模式串
    广泛用于入侵检测系统中的字符串匹配
    支持大规模规则集，具有内存优化和性能优化
    """
    def __init__(self, rules, case_sensitive=False):
        """
        初始化AC自动机
        
        :param case_sensitive: 是否区分大小写，默认不区分
        """
        self.case_sensitive = case_sensitive
        self.root = TrieNode(depth=0)  # 初始化根节点
        self.patterns = defaultdict(set) # 存储所有待匹配模式
        self.case_sensitive = case_sensitive

        self.build_from_rules(rules)

    def add_pattern(self, pattern: bytes, rule, nocase=False):
        """
        添加单个模式串到Trie树
        
        :param pattern: 模式字符串或字节串
        :param rule: 与模式关联的规则对象
        :return: 是否成功添加（重复返回False）
        """
        if not self.case_sensitive or nocase:
            pattern = pattern.lower()

        # 处理空模式
        if not pattern:
            return False

        # 转换字符串为字节串
        if not isinstance(pattern, bytes):
            pattern = bytes(pattern, 'utf-8')
        
        # 检查是否已存在该模式
        is_new_pattern = False
        if not self._pattern_exists(pattern):
            # 逐字节构建Trie树
            current_node = self.root
            for depth, char in enumerate(pattern, 1):
                if char not in current_node.children:
                    current_node.children[char] = TrieNode(value=char, depth=depth)
                current_node = current_node.children[char]
            current_node.is_end = True
            is_new_pattern = True

        #添加规则到模式中
        success = self._add_rule_to_pattern(pattern, rule)

        # 记录模式和规则
        self.patterns[pattern].add(rule)
        
        return is_new_pattern

    def _pattern_exists(self,pattern):
        current_node = self.root
        for char in pattern:
            if char not in current_node.children:
                return False
            current_node = current_node.children[char]
        return current_node.is_end


    def _add_rule_to_pattern(self, pattern, rule):
        
        """添加规则到现有模式节点"""
        current_node = self.root
        for char in pattern:
            if char not in current_node.children:
                return False
            current_node = current_node.children[char]
        if rule not in current_node.output:
            current_node.output.add(rule)
            return True
        return False
    


    def _build_failure_links(self):
        """
        使用BFS构建失败指针
        """
        queue = deque()

        for char, node in self.root.children.items():
            node.fail = self.root
            queue.append(node)

        while queue:
            current_node = queue.popleft()

            for char, child in current_node.children.items():
                fail_node = current_node.fail

                # 正确回溯失败链
                while fail_node is not None and char not in fail_node.children:
                    fail_node = fail_node.fail

                # 确定失败指针指向
                if fail_node:
                    child.fail = fail_node.children.get(char, self.root)
                else:
                    child.fail = self.root

                # 继承整个失败链的输出
                fail_output = set()
                temp_node = child.fail
                while temp_node is not self.root:
                    if temp_node.is_end:
                        fail_output.update(temp_node.output)
                    temp_node = temp_node.fail
                child.output.update(fail_output)

                queue.append(child)

    def build_from_rules(self, rules):
        """
        从Snort规则集合构建AC自动机
        提取规则中的所有content和HTTP选项，添加到AC自动机中
        
        :param rules: SnortRules实例列表
        :return: 构建成功的标志
        """
        if not rules:
            return False
            
        for rule in rules:
            for content in rule.parse_contents:
                self.add_pattern(content.byte_value, rule.rule_str, content.modifiers.get('nocase', False))

        self._build_failure_links()

        return True
            
    def search(self, text):
        """
        在文本中搜索所有模式
        返回匹配到的规则集合
        
        :param text: 要搜索的文本，可以是字符串或字节串
        :return: 匹配到的规则集合
        """
        if not text:
            return set()
        
        if not self.case_sensitive:
            text = text.lower()

        # 将字符串转换为字节串
        if isinstance(text, str):
            text = text.encode('utf-8')
            
            
        matched_rules = set()
        current_node = self.root
        
        # 使用AC算法进行匹配
        for i, char in enumerate(text):
            # 按照AC算法沿着失败指针回溯
            while current_node is not self.root and char not in current_node.children:
                current_node = current_node.fail
            
            # 如果在当前节点找到转移，移动到下一个节点
            if char in current_node.children:
                current_node = current_node.children[char]
                matched_rules.update(current_node.output)
                
                # 如果当前节点是某个模式的结束节点，收集输出
                if current_node.is_end and current_node.output:
                    for rule in current_node.output:
                        matched_rules.add(rule)
                
                # 检查失败链上的节点是否也有匹配
                fail_node = current_node.fail
                while fail_node and fail_node is not self.root:
                    if fail_node.is_end and fail_node.output:
                        for rule in fail_node.output:
                            matched_rules.add(rule)
                    fail_node = fail_node.fail
        
        return matched_rules
    
    
    



"""
使用示例
a_c = ACAutomaton()
a_c.build_from_rules(rules) #rules是SnortRule实例
"""