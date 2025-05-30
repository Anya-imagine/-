// 创建Vue应用
const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

const app = createApp({
    setup() {
        // 状态
        const packets = ref([]);
        const isCapturing = ref(false);
        const activeTab = ref('realtime');
        const filters = ref({
            protocol: ['all']
        });

        // 图表实例
        let protocolChart = null;
        let trafficChart = null;
        let anomalyChart = null;

        // 计算属性：过滤后的数据包
        const filteredPackets = computed(() => {
            return packets.value.filter(packet => {
                // 协议过滤
                if (filters.value.protocol.length > 0 && !filters.value.protocol.includes('all')) {
                    if (!filters.value.protocol.includes(packet.protocol)) {
                        return false;
                    }
                }
                return true;
            });
        });

        // 方法
        const startCapture = () => {
            console.log('Starting capture...');
            isCapturing.value = true;
            socket.emit('start_capture');
        };

        const stopCapture = () => {
            console.log('Stopping capture...');
            isCapturing.value = false;
            socket.emit('stop_capture');
        };

        const clearPackets = () => {
            console.log('Clearing packets...');
            packets.value = [];
            updateCharts();
        };

        const getProtocolClass = (protocol) => {
            return `protocol-${protocol.toLowerCase()}`;
        };

        const getProtocolTagType = (protocol) => {
            const types = {
                'HTTP': 'primary',
                'TLS': 'success',
                'DNS': 'warning',
                'ICMP': 'danger',
                'SMB': 'info',
                'SSH': ''
            };
            return types[protocol] || 'info';
        };

        // 图表相关方法
        const initCharts = () => {
            console.log('Initializing charts...');
            // 协议分布图表
            protocolChart = echarts.init(document.getElementById('protocolChart'));
            protocolChart.setOption({
                title: {
                    text: '协议分布'
                },
                tooltip: {
                    trigger: 'item'
                },
                legend: {
                    orient: 'vertical',
                    left: 'left'
                },
                series: [{
                    type: 'pie',
                    radius: '50%',
                    data: [],
                    emphasis: {
                        itemStyle: {
                            shadowBlur: 10,
                            shadowOffsetX: 0,
                            shadowColor: 'rgba(0, 0, 0, 0.5)'
                        }
                    }
                }]
            });

            // 流量趋势图表
            trafficChart = echarts.init(document.getElementById('trafficChart'));
            trafficChart.setOption({
                title: {
                    text: '流量趋势'
                },
                tooltip: {
                    trigger: 'axis'
                },
                xAxis: {
                    type: 'time'
                },
                yAxis: {
                    type: 'value',
                    name: '数据包数量'
                },
                series: [{
                    type: 'line',
                    data: []
                }]
            });

            // 异常检测图表
            anomalyChart = echarts.init(document.getElementById('anomalyChart'));
            anomalyChart.setOption({
                title: {
                    text: '异常检测'
                },
                tooltip: {
                    trigger: 'axis'
                },
                xAxis: {
                    type: 'time'
                },
                yAxis: {
                    type: 'value',
                    name: '异常分数'
                },
                series: [{
                    type: 'line',
                    data: []
                }]
            });
        };

        const updateCharts = () => {
            // 更新协议分布
            const protocolCount = {};
            packets.value.forEach(packet => {
                protocolCount[packet.protocol] = (protocolCount[packet.protocol] || 0) + 1;
            });

            const protocolData = Object.entries(protocolCount).map(([name, value]) => ({
                name,
                value
            }));

            protocolChart.setOption({
                series: [{
                    data: protocolData
                }]
            });

            // 更新流量趋势
            const trafficData = packets.value.map((packet, index) => [
                new Date(packet.timestamp),
                index + 1
            ]);

            trafficChart.setOption({
                series: [{
                    data: trafficData
                }]
            });

            // 更新异常检测（示例数据）
            const anomalyData = packets.value.map((packet, index) => [
                new Date(packet.timestamp),
                Math.random() * 100
            ]);

            anomalyChart.setOption({
                series: [{
                    data: anomalyData
                }]
            });
        };

        // WebSocket连接
        const socket = io({
            transports: ['websocket'],
            upgrade: false
        });

        socket.on('connect', () => {
            console.log('Connected to server');
        });

        socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
        });

        socket.on('disconnect', (reason) => {
            console.log('Disconnected from server:', reason);
        });

        socket.on('new_packet', (packet) => {
            console.log('Received new packet:', packet);
            packets.value.unshift(packet);
            if (packets.value.length > 1000) {
                packets.value.pop();
            }
            updateCharts();
        });

        // 生命周期钩子
        onMounted(() => {
            console.log('Component mounted');
            initCharts();
            window.addEventListener('resize', () => {
                protocolChart.resize();
                trafficChart.resize();
                anomalyChart.resize();
            });
        });

        onUnmounted(() => {
            console.log('Component unmounted');
            socket.disconnect();
        });

        return {
            packets,
            isCapturing,
            activeTab,
            filters,
            filteredPackets,
            startCapture,
            stopCapture,
            clearPackets,
            getProtocolClass,
            getProtocolTagType
        };
    }
});

// 使用Element Plus
app.use(ElementPlus);

// 挂载应用
app.mount('#app'); 