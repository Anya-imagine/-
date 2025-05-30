// 创建Vue应用
const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

const app = createApp({
    setup() {
        // 状态
        const isCapturing = ref(false);
        const protocolStats = ref({});
        const trafficData = ref([]);
        const anomalyData = ref([]);
        const connectionStats = ref({});

        // 图表实例
        let protocolPieChart = null;
        let trafficLineChart = null;
        let anomalyChart = null;
        let connectionChart = null;

        // 计算属性：协议详情
        const protocolDetails = computed(() => {
            return Object.entries(protocolStats.value).map(([protocol, stats]) => ({
                protocol,
                count: stats.count,
                bytes: stats.bytes,
                avgSize: stats.bytes / stats.count,
                details: stats.details
            }));
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

        const clearData = () => {
            console.log('Clearing data...');
            protocolStats.value = {};
            trafficData.value = [];
            anomalyData.value = [];
            connectionStats.value = {};
            updateCharts();
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
            
            // 协议分布饼图
            protocolPieChart = echarts.init(document.getElementById('protocolPieChart'));
            protocolPieChart.setOption({
                title: {
                    text: '协议分布',
                    left: 'center'
                },
                tooltip: {
                    trigger: 'item',
                    formatter: '{a} <br/>{b}: {c} ({d}%)'
                },
                legend: {
                    orient: 'vertical',
                    left: 'left',
                    data: []
                },
                series: [{
                    name: '协议分布',
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

            // 流量趋势图
            trafficLineChart = echarts.init(document.getElementById('trafficLineChart'));
            trafficLineChart.setOption({
                title: {
                    text: '流量趋势',
                    left: 'center'
                },
                tooltip: {
                    trigger: 'axis'
                },
                xAxis: {
                    type: 'time',
                    boundaryGap: false
                },
                yAxis: {
                    type: 'value',
                    name: '数据包数量'
                },
                series: [{
                    name: '流量',
                    type: 'line',
                    smooth: true,
                    data: []
                }]
            });

            // 异常检测图
            anomalyChart = echarts.init(document.getElementById('anomalyChart'));
            anomalyChart.setOption({
                title: {
                    text: '异常检测',
                    left: 'center'
                },
                tooltip: {
                    trigger: 'axis'
                },
                xAxis: {
                    type: 'time',
                    boundaryGap: false
                },
                yAxis: {
                    type: 'value',
                    name: '异常分数'
                },
                series: [{
                    name: '异常分数',
                    type: 'line',
                    smooth: true,
                    data: []
                }]
            });

            // 连接统计图
            connectionChart = echarts.init(document.getElementById('connectionChart'));
            connectionChart.setOption({
                title: {
                    text: '连接统计',
                    left: 'center'
                },
                tooltip: {
                    trigger: 'axis'
                },
                xAxis: {
                    type: 'category',
                    data: []
                },
                yAxis: {
                    type: 'value',
                    name: '连接数'
                },
                series: [{
                    name: '连接数',
                    type: 'bar',
                    data: []
                }]
            });
        };

        const updateCharts = () => {
            // 更新协议分布饼图
            const pieData = Object.entries(protocolStats.value).map(([name, stats]) => ({
                name,
                value: stats.count
            }));

            protocolPieChart.setOption({
                legend: {
                    data: pieData.map(item => item.name)
                },
                series: [{
                    data: pieData
                }]
            });

            // 更新流量趋势图
            trafficLineChart.setOption({
                series: [{
                    data: trafficData.value
                }]
            });

            // 更新异常检测图
            anomalyChart.setOption({
                series: [{
                    data: anomalyData.value
                }]
            });

            // 更新连接统计图
            const connectionData = Object.entries(connectionStats.value).map(([name, count]) => ({
                name,
                value: count
            }));

            connectionChart.setOption({
                xAxis: {
                    data: connectionData.map(item => item.name)
                },
                series: [{
                    data: connectionData.map(item => item.value)
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
            
            // 更新协议统计
            const protocol = packet.protocol;
            if (!protocolStats.value[protocol]) {
                protocolStats.value[protocol] = {
                    count: 0,
                    bytes: 0,
                    details: {}
                };
            }
            protocolStats.value[protocol].count++;
            protocolStats.value[protocol].bytes += packet.data.payload_length;
            
            // 更新协议特定信息
            const sourceKey = `${packet.data.source}:${packet.data.sport || ''}`;
            if (!protocolStats.value[protocol].details[sourceKey]) {
                protocolStats.value[protocol].details[sourceKey] = {
                    count: 0,
                    bytes: 0,
                    lastSeen: null,
                    destinations: {}
                };
            }
            protocolStats.value[protocol].details[sourceKey].count++;
            protocolStats.value[protocol].details[sourceKey].bytes += packet.data.payload_length;
            protocolStats.value[protocol].details[sourceKey].lastSeen = packet.timestamp;

            // 更新目标地址统计
            const destKey = `${packet.data.destination}:${packet.data.dport || ''}`;
            if (!protocolStats.value[protocol].details[sourceKey].destinations[destKey]) {
                protocolStats.value[protocol].details[sourceKey].destinations[destKey] = {
                    count: 0,
                    bytes: 0,
                    lastSeen: null
                };
            }
            protocolStats.value[protocol].details[sourceKey].destinations[destKey].count++;
            protocolStats.value[protocol].details[sourceKey].destinations[destKey].bytes += packet.data.payload_length;
            protocolStats.value[protocol].details[sourceKey].destinations[destKey].lastSeen = packet.timestamp;

            // 更新流量趋势
            trafficData.value.push([
                new Date(packet.timestamp),
                protocolStats.value[protocol].count
            ]);
            if (trafficData.value.length > 100) {
                trafficData.value.shift();
            }

            // 更新异常检测（示例：基于数据包大小的异常检测）
            const avgSize = protocolStats.value[protocol].bytes / protocolStats.value[protocol].count;
            const anomalyScore = Math.abs(packet.data.payload_length - avgSize) / avgSize;
            anomalyData.value.push([
                new Date(packet.timestamp),
                anomalyScore * 100
            ]);
            if (anomalyData.value.length > 100) {
                anomalyData.value.shift();
            }

            // 更新连接统计
            const connectionKey = `${packet.data.source}:${packet.data.destination}`;
            if (!connectionStats.value[connectionKey]) {
                connectionStats.value[connectionKey] = {
                    count: 0,
                    protocol: protocol,
                    lastSeen: null
                };
            }
            connectionStats.value[connectionKey].count++;
            connectionStats.value[connectionKey].lastSeen = packet.timestamp;

            // 更新图表
            updateCharts();
        });

        // 生命周期钩子
        onMounted(() => {
            console.log('Component mounted');
            initCharts();
            window.addEventListener('resize', () => {
                protocolPieChart.resize();
                trafficLineChart.resize();
                anomalyChart.resize();
                connectionChart.resize();
            });
        });

        onUnmounted(() => {
            console.log('Component unmounted');
            socket.disconnect();
        });

        return {
            isCapturing,
            protocolDetails,
            startCapture,
            stopCapture,
            clearData,
            getProtocolTagType
        };
    }
});

// 使用Element Plus
app.use(ElementPlus);

// 挂载应用
app.mount('#app'); 