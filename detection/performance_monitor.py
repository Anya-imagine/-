import time
import datetime
import logging
import json
import os
from collections import defaultdict, deque


class ThroughputCounter:
    """
    性能监控计数器类
    用于跟踪和记录系统吞吐量和规则匹配统计数据
    提供实时的性能指标，便于优化和监控
    支持统计周期性数据，生成性能报告，导出性能指标
    """
    def __init__(self, history_size=60):
        """
        初始化性能计数器
        设置起始时间和各类计数器
        
        :param history_size: 历史记录保留的数据点数量（用于计算平均值和趋势）
        """
        # 基本计时器
        self.start_time = time.time()
        self.last_update_time = self.start_time
        
        # 数据统计
        self.bytes_count = 0         # 处理的总字节数
        self.packet_count = 0        # 处理的数据包数量
        self.invalid_packet_count = 0  # 无效数据包数量
        self.last_packet_time = 0    # 最后一个数据包处理时间
        
        # 规则匹配统计
        self.alert_count = 0         # 产生告警的规则数量
        self.total_match_count = 0   # 总匹配规则数量
        
        # 告警级别统计
        self.high_alert_count = 0    # 高危告警数量
        self.medium_alert_count = 0  # 中危告警数量
        self.low_alert_count = 0     # 低危告警数量
        self.info_alert_count = 0    # 信息告警数量
        
        # 协议统计
        self.protocol_stats = defaultdict(int)  # 按协议统计数据包
        self.port_stats = defaultdict(int)      # 按端口统计数据包
        
        # 性能指标
        self.processing_times = []  # 每个数据包的处理时间
        self.max_processing_time = 0  # 最大处理时间
        self.min_processing_time = float('inf')  # 最小处理时间
        
        # 历史记录（用于计算趋势）
        self.history_size = history_size
        self.packet_rate_history = deque(maxlen=history_size)  # 每秒包数历史
        self.byte_rate_history = deque(maxlen=history_size)    # 每秒字节数历史
        self.match_rate_history = deque(maxlen=history_size)   # 匹配率历史
        self.last_history_update = self.start_time
        
        # 报警阈值
        self.packet_rate_threshold = float('inf')  # 最大包处理速率阈值
        self.match_rate_threshold = 0.8  # 匹配率阈值（超过80%可能需要优化）
        
        # 日志记录
        self.log_enabled = False
        self.log_interval = 60  # 日志记录间隔（秒）
        self.last_log_time = self.start_time
        
        # 状态标志
        self.is_overloaded = False  # 系统是否过载
        
        # 初始化日志
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("performance_monitor")

    def match_type(self, match_rules):
        """
        统计规则匹配的数量和类型
        根据规则的严重程度更新相应的计数器
        
        :param match_rules: 匹配到的规则列表
        """
        if not match_rules:
            return
            
        # 更新总匹配计数
        self.total_match_count += len(match_rules)
        
        # 统计告警
        for rule in match_rules:
            action = rule.action.lower() if hasattr(rule, 'action') else 'unknown'
            
            # 现在只有alert一种动作类型
            if action == 'alert':
                self.alert_count += 1
                
                # 获取规则严重级别
                severity = self._get_rule_severity(rule).lower()
                
                if severity == 'high' or severity == 'critical':
                    self.high_alert_count += 1
                elif severity == 'medium':
                    self.medium_alert_count += 1
                elif severity == 'low':
                    self.low_alert_count += 1
                else:
                    self.info_alert_count += 1
    
    def _get_rule_severity(self, rule):
        """
        根据规则的classtype或优先级确定告警严重级别
        与alert_logger中的方法类似
        
        :param rule: 匹配的规则对象
        :return: 严重级别字符串（HIGH/MEDIUM/LOW）
        """
        # 首先尝试从classtype判断
        classtype = rule.options.get('classtype')
        if classtype:
            # 定义高危类型列表
            high_severity = ['exploitation', 'backdoor', 'trojan', 'exploit-kit',
                            'web-application-attack', 'exploit']
            # 定义中危类型列表
            medium_severity = ['policy-violation', 'attempted-admin', 'attempted-user',
                            'misc-attack', 'denial-of-service']
            
            # 检查是否属于高危类型
            for severity_type in high_severity:
                if severity_type in classtype:
                    return 'HIGH'
                    
            # 检查是否属于中危类型
            for severity_type in medium_severity:
                if severity_type in classtype:
                    return 'MEDIUM'
        
        # 如果没有classtype或无法判断，尝试从priority判断
        priority = rule.options.get('priority')
        if priority:
            try:
                # 尝试将优先级转换为整数
                pri_num = int(priority)
                # 优先级1或以下为高危
                if pri_num <= 1:
                    return 'HIGH'
                # 优先级2为中危
                elif pri_num == 2:
                    return 'MEDIUM'
                # 优先级3或以上为低危
                else:
                    return 'LOW'
            except (ValueError, TypeError):
                # 转换失败则跳过（如非数字优先级）
                pass
                
        # 默认返回MEDIUM作为兜底策略
        return 'MEDIUM'

    def update(self, packet, processing_time=None, protocol=None, is_match=False):
        """
        更新流量统计数据
        增加数据包计数和字节计数，更新性能指标
        
        :param packet: 捕获的原始数据包或其大小
        :param processing_time: 处理此数据包所花费的时间（秒）
        :param protocol: 数据包的协议（如TCP, UDP, ICMP等）
        :param is_match: 是否匹配了任何规则
        """
        now = time.time()
        
        # 更新基本计数器
        self.packet_count += 1
        
        # 更新字节计数
        if isinstance(packet, int):
            # 如果直接传入大小
            packet_size = packet
        else:
            # 如果传入的是数据包对象
            try:
                packet_size = len(packet)
            except (TypeError, AttributeError):
                packet_size = 0
                self.invalid_packet_count += 1
        
        self.bytes_count += packet_size
        
        # 更新协议统计
        if protocol:
            self.protocol_stats[protocol] += 1
            
            # 如果数据包有端口信息，更新端口统计
            if hasattr(packet, 'sport') and hasattr(packet, 'dport'):
                self.port_stats[packet.sport] += 1
                self.port_stats[packet.dport] += 1
        
        # 更新处理时间统计
        if processing_time is not None:
            self.processing_times.append(processing_time)
            self.max_processing_time = max(self.max_processing_time, processing_time)
            self.min_processing_time = min(self.min_processing_time, processing_time)
        
        # 更新历史记录（每秒）
        if now - self.last_history_update >= 1.0:
            delta_time = now - self.last_history_update
            packets_per_second = (self.packet_count - sum(self.packet_rate_history)) / delta_time
            bytes_per_second = (self.bytes_count - sum(self.byte_rate_history)) / delta_time
            
            # 计算匹配率（如果有足够样本）
            if self.packet_count > 0:
                match_rate = self.total_match_count / self.packet_count
            else:
                match_rate = 0
                
            # 更新历史队列
            self.packet_rate_history.append(packets_per_second)
            self.byte_rate_history.append(bytes_per_second)
            self.match_rate_history.append(match_rate)
            
            self.last_history_update = now
            
            # 检查是否超过阈值
            avg_packet_rate = sum(self.packet_rate_history) / len(self.packet_rate_history) if self.packet_rate_history else 0
            if avg_packet_rate > self.packet_rate_threshold:
                self.is_overloaded = True
                self.logger.warning(f"系统负载过高: {avg_packet_rate:.2f} 包/秒")
        
        # 定期记录日志
        if self.log_enabled and now - self.last_log_time >= self.log_interval:
            self.log_statistics()
            self.last_log_time = now
        
        self.last_update_time = now
        self.last_packet_time = now

    def throughput(self):
        """
        计算系统吞吐量
        
        :return: 每秒处理的字节数（字节/秒）
        """
        duration = time.time() - self.start_time
        if duration <= 0:
            return 0  # 防止除以零
            
        return self.bytes_count / duration
    
    def packet_rate(self):
        """
        计算数据包处理速率
        
        :return: 每秒处理的数据包数量（包/秒）
        """
        duration = time.time() - self.start_time
        if duration <= 0:
            return 0  # 防止除以零
            
        return self.packet_count / duration
    
    def match_rate(self):
        """
        计算规则匹配率
        
        :return: 匹配规则的数据包占比（百分比）
        """
        if self.packet_count == 0:
            return 0
            
        return (self.total_match_count / self.packet_count) * 100
    
    def avg_processing_time(self):
        """
        计算平均数据包处理时间
        
        :return: 平均处理时间（毫秒）
        """
        if not self.processing_times:
            return 0
            
        return (sum(self.processing_times) / len(self.processing_times)) * 1000  # 转换为毫秒
    
    def get_top_protocols(self, n=5):
        """
        获取流量最高的前N个协议
        
        :param n: 返回的协议数量
        :return: 协议及其数据包数量的列表
        """
        return sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_top_ports(self, n=10):
        """
        获取流量最高的前N个端口
        
        :param n: 返回的端口数量
        :return: 端口及其数据包数量的列表
        """
        return sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_statistics(self):
        """
        获取完整统计信息
        
        :return: 包含所有统计数据的字典
        """
        now = time.time()
        duration = now - self.start_time
        
        stats = {
            "general": {
                "start_time": datetime.datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
                "current_time": datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S'),
                "duration_seconds": duration,
                "duration_formatted": str(datetime.timedelta(seconds=int(duration))),
                "is_overloaded": self.is_overloaded
            },
            "traffic": {
                "total_packets": self.packet_count,
                "invalid_packets": self.invalid_packet_count,
                "total_bytes": self.bytes_count,
                "bytes_per_second": self.throughput(),
                "packets_per_second": self.packet_rate(),
                "avg_packet_size": self.bytes_count / self.packet_count if self.packet_count > 0 else 0
            },
            "matches": {
                "total_matches": self.total_match_count,
                "alert_count": self.alert_count,
                "high_alerts": self.high_alert_count,
                "medium_alerts": self.medium_alert_count,
                "low_alerts": self.low_alert_count,
                "info_alerts": self.info_alert_count,
                "match_rate_percent": self.match_rate()
            },
            "performance": {
                "avg_processing_time_ms": self.avg_processing_time(),
                "max_processing_time_ms": self.max_processing_time * 1000 if self.max_processing_time else 0,
                "min_processing_time_ms": self.min_processing_time * 1000 if self.min_processing_time < float('inf') else 0
            },
            "protocols": dict(self.get_top_protocols()),
            "top_ports": dict(self.get_top_ports())
        }
        
        return stats
    
    def log_statistics(self):
        """
        将当前统计信息记录到日志
        """
        stats = self.get_statistics()
        self.logger.info(f"性能统计: "
                        f"运行时间={stats['general']['duration_formatted']}, "
                        f"数据包={stats['traffic']['total_packets']}, "
                        f"流量={stats['traffic']['bytes_per_second']/1024:.2f} KB/s, "
                        f"匹配={stats['matches']['total_matches']}, "
                        f"匹配率={stats['matches']['match_rate_percent']:.2f}%, "
                        f"处理时间={stats['performance']['avg_processing_time_ms']:.3f} ms")
    
    def export_statistics(self, filename=None):
        """
        导出统计数据到JSON文件
        
        :param filename: 输出文件名，默认为'performance_stats_YYYYMMDD_HHMMSS.json'
        :return: 保存的文件路径
        """
        if filename is None:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"performance_stats_{timestamp}.json"
        
        stats = self.get_statistics()
        
        try:
            with open(filename, 'w') as f:
                json.dump(stats, f, indent=2)
            self.logger.info(f"性能统计数据已导出到: {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"导出统计数据失败: {str(e)}")
            return None
    
    def reset(self, keep_history=False):
        """
        重置所有计数器
        
        :param keep_history: 是否保留历史数据
        """
        self.start_time = time.time()
        self.last_update_time = self.start_time
        
        # 重置计数器
        self.bytes_count = 0
        self.packet_count = 0
        self.invalid_packet_count = 0
        
        self.alert_count = 0
        self.high_alert_count = 0
        self.medium_alert_count = 0
        self.low_alert_count = 0
        self.info_alert_count = 0
        self.total_match_count = 0
        
        # 重置性能指标
        self.processing_times = []
        self.max_processing_time = 0
        self.min_processing_time = float('inf')
        
        if not keep_history:
            # 重置历史记录
            self.protocol_stats = defaultdict(int)
            self.port_stats = defaultdict(int)
            self.packet_rate_history.clear()
            self.byte_rate_history.clear()
            self.match_rate_history.clear()
        
        self.is_overloaded = False
        self.logger.info("性能监控计数器已重置")
    
    def enable_logging(self, enabled=True, interval=60):
        """
        启用或禁用定期日志记录
        
        :param enabled: 是否启用日志
        :param interval: 日志记录间隔（秒）
        """
        self.log_enabled = enabled
        self.log_interval = interval
        
        if enabled:
            self.logger.info(f"已启用性能监控日志记录，间隔={interval}秒")
        else:
            self.logger.info("已禁用性能监控日志记录")
    
    def set_thresholds(self, packet_rate=None, match_rate=None):
        """
        设置性能监控阈值
        
        :param packet_rate: 数据包处理速率阈值（包/秒）
        :param match_rate: 规则匹配率阈值（0-1之间）
        """
        if packet_rate is not None:
            self.packet_rate_threshold = packet_rate
            
        if match_rate is not None:
            self.match_rate_threshold = match_rate
            
        self.logger.info(f"性能监控阈值已更新: 包速率={self.packet_rate_threshold}/秒, 匹配率={self.match_rate_threshold*100}%")