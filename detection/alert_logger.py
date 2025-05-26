import logging  # 导入Python标准日志库
import json      # 导入JSON处理库，用于生成JSON格式日志
import os        # 导入操作系统库，用于文件路径操作
import sys       # 导入sys模块，用于获取系统信息
from datetime import datetime  # 导入日期时间库，用于生成时间戳
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler  # 导入日志轮转处理器


class AlertLogger:
    """
    规则匹配告警日志记录器
    负责将检测到的恶意流量告警信息写入日志文件
    支持多种日志格式、日志轮转和不同级别的告警记录
    """
    def __init__(self, log_file="ids_alert.log", log_level=logging.INFO, max_size=10*1024*1024, 
                 backup_count=5, console_output=True, json_format=False, daily_rotate=False):
        """
        初始化日志记录器
        
        :param log_file: 日志文件路径，默认为"ids_alert.log"
        :param log_level: 日志记录级别，默认为INFO
        :param max_size: 单个日志文件最大大小(字节)，默认10MB
        :param backup_count: 备份文件数量，默认5个
        :param console_output: 是否同时输出到控制台，默认True
        :param json_format: 是否使用JSON格式记录日志，默认False
        :param daily_rotate: 是否按天轮转日志，默认False（按大小轮转）
        """
        # 创建一个名为'ids_alert'的日志器
        self.logger = logging.getLogger('ids_alert')
        # 设置日志器的记录级别
        self.logger.setLevel(log_level)
        # 清除已有的处理器，避免重复添加
        self.logger.handlers = []
        # 存储JSON格式选项供后续使用
        self.json_format = json_format
        
        # 创建日志目录（如果不存在）
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            # 递归创建目录结构
            os.makedirs(log_dir)
        
        # 配置日志格式
        if json_format:
            # JSON格式不需要额外格式化，直接输出消息内容
            formatter = logging.Formatter('%(message)s')
        else:
            # 标准格式：时间 [级别] 消息内容
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', 
                                          datefmt='%Y-%m-%d %H:%M:%S')
        
        # 配置文件处理器（按大小或按时间轮转）
        if daily_rotate:
            # 创建按时间轮转的处理器，每天午夜创建新文件
            file_handler = TimedRotatingFileHandler(
                filename=log_file,       # 日志文件路径
                when='midnight',         # 午夜进行轮转
                interval=1,              # 轮转间隔为1天
                backupCount=backup_count, # 保留的备份文件数
                encoding='utf-8'         # 使用UTF-8编码
            )
        else:
            # 创建按大小轮转的处理器，文件达到指定大小时创建新文件
            file_handler = RotatingFileHandler(
                filename=log_file,        # 日志文件路径
                maxBytes=max_size,        # 单个日志文件最大字节数
                backupCount=backup_count, # 保留的备份文件数
                encoding='utf-8'          # 使用UTF-8编码
            )
            
        # 将格式化器应用到文件处理器
        file_handler.setFormatter(formatter)
        # 将文件处理器添加到日志器
        self.logger.addHandler(file_handler)
        
        # 可选配置控制台输出
        if console_output:
            # 创建控制台处理器
            console_handler = logging.StreamHandler()
            # 应用相同的格式化器
            console_handler.setFormatter(formatter)
            
            # 在Windows平台上处理编码问题
            if sys.platform == 'win32':
                # 设置控制台编码为utf-8，避免GBK编码错误
                console_handler.stream.reconfigure(encoding='utf-8', errors='backslashreplace')
                
            # 将控制台处理器添加到日志器
            self.logger.addHandler(console_handler)
    
    def log_alert(self, pkt_info, matched_rule, log_level=logging.INFO, additional_info=None):
        """
        记录告警详情
        将匹配到的规则和相关数据包信息写入日志
        
        :param pkt_info: 解析后的数据包信息对象
        :param matched_rule: 匹配到的规则对象
        :param log_level: 此条告警的日志级别
        :param additional_info: 额外需要记录的信息字典
        """
        # 生成当前时间戳
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 构建基本告警信息字典
        alert_info = {
            'timestamp': timestamp,                                   # 时间戳
            'action': matched_rule.action,                            # 规则动作(alert/block/drop等)
            'message': matched_rule.options.get('msg', 'Unknown Alert'), # 规则消息内容
            'sid': matched_rule.options.get('sid', 'Unknown'),        # 规则ID
            'rev': matched_rule.options.get('rev', '1'),              # 规则版本
            'protocol': pkt_info.protocol,                            # 协议(TCP/UDP等)
            'src_ip': str(pkt_info.src_ip),                           # 源IP地址
            'src_port': pkt_info.src_port,                            # 源端口
            'dst_ip': str(pkt_info.dst_ip),                           # 目标IP地址
            'dst_port': pkt_info.dst_port,                            # 目标端口
            'severity': self._get_severity(matched_rule)              # 告警严重级别
        }
        
        # 添加HTTP特定信息（如果是HTTP流量）
        if pkt_info.is_http:
            # 使用update方法添加HTTP相关字段
            alert_info.update({
                'is_http': True,                  # 标记为HTTP流量
                'http_method': pkt_info.http_method,  # HTTP方法(GET/POST等)
                'http_uri': pkt_info.http_uri,        # 请求URI
                'http_version': pkt_info.http_version # HTTP版本
            })
            
        # 添加其他额外信息（如果提供）
        if additional_info:
            # 将额外信息合并到告警信息字典
            alert_info.update(additional_info)
            
        try:
            # 根据配置选择日志输出格式
            if self.json_format:
                # 转换为JSON字符串，便于机器处理和分析
                log_msg = json.dumps(alert_info, ensure_ascii=False)
            else:
                # 构建人类可读的标准格式
                # 基本信息部分：动作、严重级别和消息
                base_msg = f"[{alert_info['action']}] [{alert_info['severity']}] [{alert_info['message']}] "
                # 详细信息部分：规则ID、源/目标IP:端口、协议
                detail_msg = f"SID:{alert_info['sid']} {alert_info['src_ip']}:{alert_info['src_port']} -> {alert_info['dst_ip']}:{alert_info['dst_port']} Protocol:{alert_info['protocol']}"
                
                # 添加HTTP详情（如果存在）
                http_info = ""
                if pkt_info.is_http:
                    # 附加HTTP方法和URI信息
                    http_info = f" | {pkt_info.http_method} {pkt_info.http_uri}"
                    
                # 拼接完整日志消息
                log_msg = base_msg + detail_msg + http_info

            # 记录日志，使用指定的日志级别
            self.logger.log(log_level, log_msg)
        except UnicodeEncodeError as e:
            # 处理编码错误，使用ASCII进行回退
            safe_msg = f"[ENCODING ERROR] 告警记录包含不支持的字符: SID:{alert_info['sid']}"
            self.logger.log(log_level, safe_msg)
            self.logger.debug(f"编码错误详情: {str(e)}")
        
    def log_system_event(self, event_type, message, log_level=logging.INFO):
        """
        记录系统事件，如启动、停止、配置变更等
        
        :param event_type: 事件类型
        :param message: 事件消息
        :param log_level: 日志级别
        """
        try:
            if self.json_format:
                # 构建JSON格式的系统事件日志
                log_msg = json.dumps({
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # 时间戳
                    'event_type': event_type,  # 事件类型
                    'message': message         # 事件消息
                }, ensure_ascii=False)
            else:
                # 构建人类可读的系统事件日志
                log_msg = f"[SYSTEM] [{event_type}] {message}"
                
            # 使用指定级别记录日志
            self.logger.log(log_level, log_msg)
        except UnicodeEncodeError:
            # 处理编码错误
            safe_msg = f"[SYSTEM] [{event_type}] 包含不支持的字符的系统事件"
            self.logger.log(log_level, safe_msg)
    
    def log_error(self, error_message, exception=None):
        """
        记录系统错误
        
        :param error_message: 错误消息
        :param exception: 异常对象（可选）
        """
        # 如果提供了异常对象，将其信息添加到错误消息中
        if exception:
            error_message = f"{error_message}: {str(exception)}"
            
        try:
            if self.json_format:
                # 构建JSON格式的错误日志
                log_msg = json.dumps({
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # 时间戳
                    'event_type': 'ERROR',     # 事件类型固定为ERROR
                    'message': error_message   # 错误消息
                }, ensure_ascii=False)
            else:
                # 构建人类可读的错误日志
                log_msg = f"[ERROR] {error_message}"
                
            # 使用ERROR级别记录日志
            self.logger.error(log_msg)
        except UnicodeEncodeError:
            # 处理编码错误
            safe_msg = "[ERROR] 包含不支持的字符的错误消息"
            self.logger.error(safe_msg)
    
    def _get_severity(self, rule):
        """
        根据规则的classtype或优先级确定告警严重级别
        
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

    def close(self):
        """关闭日志处理器，释放资源"""
        for handler in self.logger.handlers:
            # 关闭每个处理器
            handler.close()
            # 从日志器中移除处理器
            self.logger.removeHandler(handler)