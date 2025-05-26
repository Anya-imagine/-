import threading

import scapy
from scapy.all import sniff,Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from queue import Queue


class ProtocolAnalyzer:
    def __init__(self):
        self.handlers = {
            'dns': [],
            'http': [],  # 预留HTTP解析接口
            'websocket': []  # 预留WebSocket解析接口
        }

    def register_handler(self, protocol, handler):
        """注册协议处理函数"""
        if protocol in self.handlers:
            self.handlers[protocol].append(handler)
        else:
            self.handlers[protocol] = [handler]


class PacketSniffer:
    def __init__(self, analyzer):
        self.processor = None
        self.analyzer = analyzer
        self.packet_queue = Queue(maxsize=1000)
        self._stop_event = threading.Event()

        # 协议端口映射表
        self.protocol_ports = {
            53: 'dns',
            80: 'http',
            443: 'https',
            5000: 'http',  # 新增Flask默认端口
            8080: 'http'
        }

    def _packet_callback(self, packet):
        """Scapy抓包回调函数"""
        if IP in packet:
            ip_packet = packet[IP]
            if TCP in ip_packet:
                self._process_transport(ip_packet, ip_packet[TCP], 'tcp')
            elif UDP in ip_packet:
                self._process_transport(ip_packet, ip_packet[UDP], 'udp')

    def _process_transport(self, ip_packet, transport, proto):
        """处理传输层协议"""
        src_port = transport.sport
        dst_port = transport.dport

        # 识别协议类型
        protocol = self.protocol_ports.get(dst_port) or self.protocol_ports.get(src_port)

        # 新增HTTP协议处理 ▼▼▼
        if protocol == 'http' and proto == 'tcp':
            try:
                http_data = transport.payload.load.decode('utf-8', errors='ignore')
                self.packet_queue.put(('http', http_data, {
                    'src_ip': ip_packet.src,
                    'dst_ip': ip_packet.dst,
                    'method': http_data.split(' ')[0] if http_data else ''
                }))
            except Exception as e:
                print(f"HTTP解析失败: {str(e)}")

        if protocol == 'dns' and DNS in transport:
            try:
                dns_layer = transport.getlayer(DNS)
                print(f"[抓包调试] 发现DNS数据包 QR标志位: {dns_layer.qr}")  # 新增状态输出
                raw_dns = bytes(dns_layer)
                print(f"[抓包调试] 原始DNS数据长度: {len(raw_dns)} 字节")  # 验证数据完整性
                self.packet_queue.put(('dns', raw_dns, {
                    'src_ip': ip_packet.src,
                    'src_port': src_port,
                    'dst_ip': ip_packet.dst,
                    'timestamp': ip_packet.time
                }))

            except Exception as e:
                print(f"DNS解析失败: {str(e)}")
                return

    def _processing_worker(self):
        while not self._stop_event.is_set():
            try:
                protocol, raw_data, metadata = self.packet_queue.get(timeout=1)
                print(f"[处理调试] 开始处理 {protocol} 数据包")  # 新增处理入口日志
                if protocol in self.analyzer.handlers:
                    handler_list = self.analyzer.handlers[protocol]
                    for handler_func in handler_list:
                        print(f"[处理调试] 调用 {handler_func.__name__}")  # 显示处理函数调用
                        handler_func(raw_data, metadata)
            except Exception as e:
                print(f"处理数据包时出错: {str(e)}")

    def start(self, interface=None):
        """启动抓包线程"""
        self._stop_event.clear()

        # 抓包线程
        sniff_thread = threading.Thread(
            target=scapy.all.sniff,
            kwargs={
                'prn': self._packet_callback,
                'store': 0,
                'iface': interface,
                'stop_filter': lambda p: self._stop_event.is_set()
            }
        )

        # 处理线程
        process_thread = threading.Thread(target=self._processing_worker)

        sniff_thread.start()
        process_thread.start()

    def stop(self):
        """停止抓包"""
        self._stop_event.set()




if __name__ == "__main__":
    analyzer = ProtocolAnalyzer()
    sniffer = PacketSniffer(analyzer)

    # 注册DNS处理程序（更新版）
    def dns_handler(query, metadata):  # 参数名需要与实际传递的匹配
        print(f"[DNS请求] 客户端 {metadata['src_ip']}:{metadata['src_port']}"
              f" 查询域名: {query}")

    analyzer.register_handler('dns', dns_handler)

    # 开始抓包（需要root权限）
    try:
        print("启动抓包程序...")
        sniffer.start(interface='eth33')  # 改为回环接口
        input("按回车键停止抓包...\n")
    finally:
        sniffer.stop()


