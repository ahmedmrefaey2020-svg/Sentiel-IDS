const ui = {
    inbound: document.getElementById('inboundVal'),
    outbound: document.getElementById('outboundVal'),
    latency: document.getElementById('latencyVal'),
    dropped: document.getElementById('droppedVal'),
    graph: document.getElementById('graphContainer'),
    log: document.getElementById('trafficLog')
};

const config = {
    maxGraphBars: 40,
    maxLogRows: 7
};

let graphData = Array(config.maxGraphBars).fill(10);

const badgeStyle = document.createElement('style');
badgeStyle.innerHTML = `
.monitoring-status-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-radius: 30px;
    font-size: 0.85rem;
    font-weight: 600;
    transition: all 0.3s ease;
    border: 1px solid rgba(255, 255, 255, 0.08);
}
.monitoring-status-badge .badge-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
}
.mode-scapy {
    background-color: rgba(59, 130, 246, 0.1);
    color: #60a5fa;
    border-color: rgba(59, 130, 246, 0.2);
}
.mode-scapy .badge-dot {
    background-color: #3b82f6;
    box-shadow: 0 0 8px #3b82f6;
}
.mode-agent {
    background-color: rgba(16, 185, 129, 0.1);
    color: #34d399;
    border-color: rgba(16, 185, 129, 0.2);
}
.mode-agent .badge-dot {
    background-color: #10b981;
    box-shadow: 0 0 8px #10b981;
}
.mode-fallback {
    background-color: rgba(245, 158, 11, 0.1);
    color: #fbbf24;
    border-color: rgba(245, 158, 11, 0.2);
    animation: alert-pulse 1.5s infinite;
}
.mode-fallback .badge-dot {
    background-color: #f59e0b;
    box-shadow: 0 0 8px #f59e0b;
}
@keyframes alert-pulse {
    0% { opacity: 0.8; }
    50% { opacity: 1; }
    100% { opacity: 0.8; }
}
`;
document.head.appendChild(badgeStyle);

function updateMonitoringStatusBadge(mode, isFallback, token) {
    let badge = document.getElementById('monitoring-status-badge');
    if (!badge) {
        badge = document.createElement('div');
        badge.id = 'monitoring-status-badge';
        const header = document.querySelector('header');
        if (header) {
            header.appendChild(badge);
        }
    }
    
    if (mode === 'scapy') {
        badge.className = 'monitoring-status-badge mode-scapy';
        badge.innerHTML = `<span class="badge-dot"></span> Scapy Sniffing Active`;
    } else if (mode === 'api_agent') {
        if (isFallback) {
            badge.className = 'monitoring-status-badge mode-fallback';
            badge.innerHTML = `<span class="badge-dot"></span> Agent Offline - Scapy Sniffing Active`;
        } else {
            badge.className = 'monitoring-status-badge mode-agent';
            badge.innerHTML = `<span class="badge-dot"></span> Agent Active (Key: ${token ? token.substring(0, 8) + '...' : 'None'})`;
        }
    }
}

function initGraph() {
    ui.graph.innerHTML = '';
    for (let i = 0; i < config.maxGraphBars; i++) {
        const bar = document.createElement('div');
        bar.className = 'graph-bar';
        bar.style.height = '5%';
        ui.graph.appendChild(bar);
    }
}

function updateGraph(newValue) {
    graphData.push(newValue);
    if (graphData.length > config.maxGraphBars) graphData.shift();

    const bars = ui.graph.children;
    for (let i = 0; i < bars.length; i++) {
        bars[i].style.height = `${graphData[i]}%`;
        if (graphData[i] > 85) bars[i].style.backgroundColor = 'var(--danger-color)';
        else if (graphData[i] > 65) bars[i].style.backgroundColor = '#f59e0b';
        else bars[i].style.backgroundColor = 'var(--brand-color)';
    }
}

function renderLog(data) {
    ui.log.innerHTML = '';
    data.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="color: var(--text-secondary);">${row.time}</td>
            <td>${row.src}</td>
            <td>${row.port}</td>
            <td><span class="protocol-tag">${row.proto}</span></td>
            <td>${row.status === 'anomaly' ? 'Anomaly' : 'Normal'}</td>
        `;
        ui.log.appendChild(tr);
    });
}

async function fetchNetworkData() {
    try {
        const response = await fetch('/api/dashboard-data');
        const data = await response.json();

        ui.inbound.innerHTML = `${data.packet_rate} <span class="metric-unit">pps</span>`;
        ui.latency.innerHTML = `${data.risk_score} <span class="metric-unit">% Risk</span>`;
        
        updateGraph(data.risk_score);

        if (data.recent_flows) {
            renderLog(data.recent_flows);
        }
        
        updateMonitoringStatusBadge(data.monitoring_mode, data.is_fallback_active, data.user_api_token);
        
    } catch (error) {
        console.error("Error fetching network data:", error);
    }
}

initGraph();
setInterval(fetchNetworkData, 2000);
fetchNetworkData();