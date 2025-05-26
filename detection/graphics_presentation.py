import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import datetime
import tkinter as tk
from collections import deque
import seaborn as sns
import io
import base64
from PIL import Image, ImageTk

class Graphics:
    def __init__(self, monitor):
        """
        初始化图形呈现类
        
        :param monitor: ThroughputCounter实例，包含性能监控统计数据
        """
        self.monitor = monitor
        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'KaiTi']
        plt.rcParams['axes.unicode_minus'] = False
        # 历史数据存储
        self.time_points = deque(maxlen=60)  # 存储时间点
        self.packet_rates = deque(maxlen=60)  # 存储包速率
        self.byte_rates = deque(maxlen=60)  # 存储字节速率
        # 上次更新时间
        self.last_update = datetime.datetime.now()
        
    def update_history_data(self):
        """更新历史数据"""
        now = datetime.datetime.now()
        self.time_points.append(now)
        self.packet_rates.append(self.monitor.packet_rate())
        self.byte_rates.append(self.monitor.throughput() / 1024)  # KB/s
    
    def pie_chart_rules(self, fig=None, ax=None):
        """
        绘制规则触发统计饼图
        
        :param fig: 可选的Figure对象
        :param ax: 可选的Axes对象
        :return: fig, ax
        """
        if fig is None:
            fig, ax = plt.subplots(figsize=(8, 6))
        
        # 构造数据 - 只有ALERT一种动作
        alert_count = self.monitor.alert_count
        
        # 检查是否有非零值
        if alert_count == 0:
            ax.text(0.5, 0.5, "暂无规则触发数据", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=14, color='gray')
            ax.axis('off')
            return fig, ax
            
        # 从monitor中获取各级别告警数据
        stats = self.monitor.get_statistics()
        high_risk = stats['matches']['high_alerts']
        medium_risk = stats['matches']['medium_alerts']
        low_risk = stats['matches']['low_alerts']
        info_risk = stats['matches']['info_alerts']
        
        categories = ["高危告警", "中危告警", "低危告警", "信息告警"]
        values = [high_risk, medium_risk, low_risk, info_risk]
        
        # 检查是否所有值都为0
        if sum(values) == 0:
            # 如果没有具体数据但alert_count不为0，则使用估算值
            high_risk = int(alert_count * 0.15)
            medium_risk = int(alert_count * 0.35)
            low_risk = int(alert_count * 0.30)
            info_risk = alert_count - high_risk - medium_risk - low_risk
            values = [high_risk, medium_risk, low_risk, info_risk]
        
        # 突出显示高危告警
        explode = [0.1, 0, 0, 0]
        
        # 设置颜色 - 红色(高危)到绿色(信息)的渐变
        colors = ['#ff0000', '#ff9999', '#ffcc99', '#99ff99']
        
        # 绘制饼图
        wedges, texts, autotexts = ax.pie(
            values,
                explode=explode,
            labels=categories,
                colors=colors,
            autopct='%1.1f%%',
                shadow=True,
            startangle=90,
            wedgeprops={'edgecolor': 'black', 'linewidth': 0.5}
        )
        
        # 设置字体样式
        for text in texts:
            text.set_fontsize(12)
        for autotext in autotexts:
            autotext.set_fontsize(10)
            autotext.set_fontweight('bold')
        
        ax.set_title("告警统计 (ALERT)", fontsize=16, pad=20)
        ax.axis('equal')  # 确保饼图是圆形的
        
        # 添加图例
        ax.legend(wedges, [f"{l}: {v}" for l, v in zip(categories, values)],
                 title=f"告警统计 (共{alert_count}个)",
                 loc="center left",
                 bbox_to_anchor=(1, 0, 0.5, 1))
        
        return fig, ax
    
    def traffic_bar_chart(self, fig=None, ax=None):
        """
        绘制协议流量统计条形图
        
        :param fig: 可选的Figure对象
        :param ax: 可选的Axes对象
        :return: fig, ax
        """
        if fig is None:
            fig, ax = plt.subplots(figsize=(10, 6))
        
        # 获取顶部协议
        top_protocols = self.monitor.get_top_protocols(10)
        
        if not top_protocols:
            ax.text(0.5, 0.5, "暂无协议流量数据", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=14, color='gray')
            ax.axis('off')
            return fig, ax
            
        protocols = [p[0] for p in top_protocols]
        counts = [p[1] for p in top_protocols]
        
        # 创建水平条形图
        bars = ax.barh(protocols, counts, height=0.6, 
                      color=sns.color_palette("viridis", len(protocols)))
        
        # 添加数量标签
        for bar in bars:
            width = bar.get_width()
            label_x_pos = width * 1.01
            ax.text(label_x_pos, bar.get_y() + bar.get_height()/2, f'{int(width):,}',
                   va='center', fontsize=10)
        
        ax.set_title("协议流量统计", fontsize=16, pad=20)
        ax.set_xlabel("数据包数量", fontsize=12)
        ax.grid(axis='x', linestyle='--', alpha=0.7)
        
        # 设置Y轴标签
        ax.set_yticks(range(len(protocols)))
        ax.set_yticklabels([f"{p}" for p in protocols], fontsize=10)
        
        # 适应Y轴
        plt.tight_layout()
        
        return fig, ax
        
    def traffic_time_series(self, fig=None, ax=None):
        """
        绘制流量时间序列图
        
        :param fig: 可选的Figure对象
        :param ax: 可选的Axes对象
        :return: fig, ax
        """
        # 更新历史数据
        self.update_history_data()
        
        if fig is None:
            fig, ax = plt.subplots(figsize=(10, 5))
        
        if not self.time_points:
            ax.text(0.5, 0.5, "等待收集流量数据...", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=14, color='gray')
            ax.axis('off')
            return fig, ax
        
        # 转换为列表以便绘图
        times = list(self.time_points)
        packets = list(self.packet_rates)
        
        # 绘制时间序列
        ax.plot(times, packets, 'b-', label='数据包/秒', linewidth=2)
        
        # 设置x轴格式
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.xticks(rotation=45)
        
        # 标题和标签
        ax.set_title("实时流量监控", fontsize=16, pad=20)
        ax.set_xlabel("时间", fontsize=12)
        ax.set_ylabel("数据包/秒", fontsize=12)
        
        # 网格和图例
        ax.grid(True, linestyle='--', alpha=0.7)
        ax.legend(loc='upper left')
        
        # 增加边距，确保所有元素都能显示
        fig.subplots_adjust(bottom=0.15, top=0.9, left=0.1, right=0.95)
        
        return fig, ax
    
    def port_activity_heatmap(self, fig=None, ax=None):
        """
        端口活动热图
        
        :param fig: 可选的Figure对象
        :param ax: 可选的Axes对象
        :return: fig, ax
        """
        if fig is None:
            fig, ax = plt.subplots(figsize=(10, 8))
        
        # 获取顶部端口数据
        top_ports = self.monitor.get_top_ports(20)
        
        if not top_ports:
            ax.text(0.5, 0.5, "暂无端口流量数据", 
                   horizontalalignment='center', verticalalignment='center',
                   fontsize=14, color='gray')
            ax.axis('off')
            return fig, ax
        
        # 转换为列表
        ports = [str(p[0]) for p in top_ports]
        counts = [p[1] for p in top_ports]
        
        # 创建热图的数据矩阵
        # 将端口数据重组为5x4矩阵（或者根据端口数量调整）
        matrix_size = min(len(ports), 20)
        matrix_width = 5
        matrix_height = (matrix_size + matrix_width - 1) // matrix_width
        
        # 填充矩阵
        data_matrix = np.zeros((matrix_height, matrix_width))
        labels_matrix = np.empty((matrix_height, matrix_width), dtype=object)
        
        for i in range(matrix_size):
            row = i // matrix_width
            col = i % matrix_width
            data_matrix[row, col] = counts[i]
            labels_matrix[row, col] = ports[i]
        
        # 创建热图
        sns.heatmap(data_matrix, annot=labels_matrix, fmt='', cmap='YlOrRd',
                   linewidths=.5, ax=ax, cbar_kws={'label': '数据包数量'})
        
        # 调整显示
        ax.set_title("端口活动热图", fontsize=16, pad=20)
        ax.set_xticklabels([])
        ax.set_yticklabels([])
        
        return fig, ax
    
    def match_rate_gauge(self, fig=None, ax=None):
        """
        绘制规则匹配率仪表盘
        
        :param fig: 可选的Figure对象
        :param ax: 可选的Axes对象
        :return: fig, ax
        """
        if fig is None:
            fig, ax = plt.subplots(figsize=(6, 6), subplot_kw={'polar': True})
        
        # 获取匹配率（百分比）
        match_rate = self.monitor.match_rate() / 100  # 转换为0-1之间的值
        
        # 设置仪表盘的角度范围
        theta = np.linspace(0, 180, 100) * np.pi / 180  # 0到180度
        
        # 创建仪表盘的值范围
        r = np.ones_like(theta)
        
        # 绘制仪表盘背景
        ax.fill_between(theta, 0, r, color='lightgrey', alpha=0.5)
        
        # 计算匹配率对应的角度
        match_theta = match_rate * 180 * np.pi / 180
        
        # 绘制匹配率指示
        ax.fill_between(theta, 0, r, where=(theta <= match_theta), color='red', alpha=0.7)
        
        # 添加文本显示
        ax.text(np.pi/2, 0.5, f"{match_rate*100:.1f}%", 
               horizontalalignment='center', verticalalignment='center',
               fontsize=20, fontweight='bold')
        
        # 设置仪表盘样式
        ax.set_rticks([])  # 隐藏半径刻度
        ax.set_thetamin(0)
        ax.set_thetamax(180)
        
        # 添加刻度
        ax.set_xticks(np.array([0, 45, 90, 135, 180]) * np.pi / 180)
        ax.set_xticklabels(['0%', '25%', '50%', '75%', '100%'], fontsize=10)
        
        ax.set_title("规则匹配率", fontsize=16, pad=20)
        
        return fig, ax
    
    def create_dashboard(self, root=None):
        """
        创建可视化仪表板，集成所有图表
        
        :param root: tkinter根窗口，如果不提供则创建新窗口
        :return: tkinter窗口对象
        """
        if root is None:
            root = tk.Tk()
            root.title("网络入侵检测系统 - 性能监控仪表板")
            root.geometry("1200x800")
        
        # 创建主框架
        main_frame = tk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建上排框架
        top_frame = tk.Frame(main_frame)
        top_frame.pack(fill=tk.X, expand=False, pady=5)
        
        # 添加汇总信息标签
        stats = self.monitor.get_statistics()
        
        # 第一行显示基本性能数据
        info_text1 = f"运行时间: {stats['general']['duration_formatted']} | " \
                    f"数据包: {stats['traffic']['total_packets']:,} | " \
                    f"流量: {stats['traffic']['bytes_per_second']/1024:.2f} KB/s | " \
                    f"平均处理时间: {stats['performance']['avg_processing_time_ms']:.3f} ms"
        
        # 第二行显示告警统计数据
        info_text2 = f"告警统计: 总数={stats['matches']['alert_count']:,} | " \
                    f"高危={stats['matches']['high_alerts']:,} | " \
                    f"中危={stats['matches']['medium_alerts']:,} | " \
                    f"低危={stats['matches']['low_alerts']:,} | " \
                    f"信息={stats['matches']['info_alerts']:,} | " \
                    f"匹配率={stats['matches']['match_rate_percent']:.2f}%"
        
        info_label1 = tk.Label(top_frame, text=info_text1, font=("Arial", 10))
        info_label1.pack(fill=tk.X)
        
        info_label2 = tk.Label(top_frame, text=info_text2, font=("Arial", 10), fg="red")
        info_label2.pack(fill=tk.X)
        
        # 创建图表框架
        charts_frame = tk.Frame(main_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建2x2网格布局
        # 上左: 规则触发饼图
        pie_frame = tk.Frame(charts_frame)
        pie_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        pie_fig = Figure(figsize=(5, 4))
        pie_ax = pie_fig.add_subplot(111)
        self.pie_chart_rules(pie_fig, pie_ax)
        
        pie_canvas = FigureCanvasTkAgg(pie_fig, pie_frame)
        pie_canvas.draw()
        pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # 上右: 时间序列图
        ts_frame = tk.Frame(charts_frame)
        ts_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        ts_fig = Figure(figsize=(5, 4))
        ts_ax = ts_fig.add_subplot(111)
        self.traffic_time_series(ts_fig, ts_ax)
        
        ts_canvas = FigureCanvasTkAgg(ts_fig, ts_frame)
        ts_canvas.draw()
        ts_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # 下左: 协议条形图
        bar_frame = tk.Frame(charts_frame)
        bar_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        bar_fig = Figure(figsize=(5, 4))
        bar_ax = bar_fig.add_subplot(111)
        self.traffic_bar_chart(bar_fig, bar_ax)
        
        bar_canvas = FigureCanvasTkAgg(bar_fig, bar_frame)
        bar_canvas.draw()
        bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # 下右: 端口热图和匹配率
        heat_frame = tk.Frame(charts_frame)
        heat_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        heat_fig = Figure(figsize=(5, 4))
        heat_ax = heat_fig.add_subplot(111)
        self.port_activity_heatmap(heat_fig, heat_ax)
        
        heat_canvas = FigureCanvasTkAgg(heat_fig, heat_frame)
        heat_canvas.draw()
        heat_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # 设置网格权重
        charts_frame.grid_columnconfigure(0, weight=1)
        charts_frame.grid_columnconfigure(1, weight=1)
        charts_frame.grid_rowconfigure(0, weight=1)
        charts_frame.grid_rowconfigure(1, weight=1)
        
        # 添加更新按钮
        def update_charts():
            # 更新汇总信息
            stats = self.monitor.get_statistics()
            
            # 更新第一行性能数据
            info_text1 = f"运行时间: {stats['general']['duration_formatted']} | " \
                        f"数据包: {stats['traffic']['total_packets']:,} | " \
                        f"流量: {stats['traffic']['bytes_per_second']/1024:.2f} KB/s | " \
                        f"平均处理时间: {stats['performance']['avg_processing_time_ms']:.3f} ms"
            info_label1.config(text=info_text1)
            
            # 更新第二行告警统计数据
            info_text2 = f"告警统计: 总数={stats['matches']['alert_count']:,} | " \
                        f"高危={stats['matches']['high_alerts']:,} | " \
                        f"中危={stats['matches']['medium_alerts']:,} | " \
                        f"低危={stats['matches']['low_alerts']:,} | " \
                        f"信息={stats['matches']['info_alerts']:,} | " \
                        f"匹配率={stats['matches']['match_rate_percent']:.2f}%"
            info_label2.config(text=info_text2)
            
            # 更新所有图表
            self.pie_chart_rules(pie_fig, pie_ax)
            pie_canvas.draw()
            
            self.traffic_time_series(ts_fig, ts_ax)
            ts_canvas.draw()
            
            self.traffic_bar_chart(bar_fig, bar_ax)
            bar_canvas.draw()
            
            self.port_activity_heatmap(heat_fig, heat_ax)
            heat_canvas.draw()
            
            # 设置自动更新(每3秒)
            root.after(3000, update_charts)
        
        # 添加底部控制框架
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, expand=False, pady=5)
        
        update_btn = tk.Button(control_frame, text="手动更新", command=update_charts)
        update_btn.pack(side=tk.RIGHT, padx=5)
        
        export_btn = tk.Button(control_frame, text="导出统计数据", 
                              command=lambda: self.monitor.export_statistics())
        export_btn.pack(side=tk.RIGHT, padx=5)
        
        # 启动自动更新
        root.after(1000, update_charts)
        
        return root
    
    def save_all_charts(self, prefix="chart"):
        """
        保存所有图表为图片文件
        
        :param prefix: 文件名前缀
        :return: 保存的文件列表
        """
        saved_files = []
        
        # 保存规则触发饼图
        fig, ax = self.pie_chart_rules()
        filename = f"{prefix}_rules_pie.png"
        fig.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close(fig)
        saved_files.append(filename)
        
        # 保存流量时间序列
        fig, ax = self.traffic_time_series()
        filename = f"{prefix}_traffic_time.png"
        fig.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close(fig)
        saved_files.append(filename)
        
        # 保存协议条形图
        fig, ax = self.traffic_bar_chart()
        filename = f"{prefix}_protocol_bar.png"
        fig.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close(fig)
        saved_files.append(filename)
        
        # 保存端口热图
        fig, ax = self.port_activity_heatmap()
        filename = f"{prefix}_port_heat.png"
        fig.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close(fig)
        saved_files.append(filename)
        
        # 保存匹配率仪表盘
        fig, ax = self.match_rate_gauge()
        filename = f"{prefix}_match_gauge.png"
        fig.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close(fig)
        saved_files.append(filename)
        
        return saved_files
    
    def generate_image_base64(self, chart_method, **kwargs):
        """
        生成图表的Base64编码，用于Web展示
        
        :param chart_method: 图表方法名称
        :param kwargs: 传递给图表方法的参数
        :return: Base64编码的图像字符串
        """
        # 创建图表
        fig, ax = getattr(self, chart_method)(**kwargs)
        
        # 将图形保存到内存中
        buffer = io.BytesIO()
        fig.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
        plt.close(fig)
        
        # 获取图像数据并转换为Base64
        buffer.seek(0)
        image_png = buffer.getvalue()
        buffer.close()
        
        # 编码为Base64
        return base64.b64encode(image_png).decode('utf-8')







