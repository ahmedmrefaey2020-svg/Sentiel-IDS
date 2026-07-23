const uiElements = {
    riskScore: document.getElementById('riskScore'),
    activeConn: document.getElementById('activeConn'),
    packetRate: document.getElementById('packetRate'),
    activityTable: document.getElementById('activityTable'),
    predictionAlert: document.getElementById('predictionAlert')
};

let currentFlows = [];

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

function processDashboardData(data) {
    uiElements.activeConn.innerText = data.active_connections.toLocaleString();
    uiElements.packetRate.innerText = data.packet_rate.toLocaleString();
    
    uiElements.riskScore.innerHTML = `${data.risk_score}<span>%</span>`;
    uiElements.riskScore.className = `card-value ${data.risk_score > 70 ? 'risk-high' : 'risk-low'}`;
    uiElements.riskScore.nextElementSibling.innerText = data.risk_message;

    if (data.is_anomaly) {
        uiElements.predictionAlert.classList.add('active');
    } else {
        uiElements.predictionAlert.classList.remove('active');
    }

    currentFlows = data.network_flows;
    renderTable(currentFlows);
    
    updateMonitoringStatusBadge(data.monitoring_mode, data.is_fallback_active, data.user_api_token);
}

async function fetchDashboardData() {
    try {
        const response = await fetch('/api/dashboard-data');
        const data = await response.json();
        processDashboardData(data);
    } catch (error) {
        console.error("Error fetching dashboard data:", error);
    }
}

function renderTable(flows) {
    uiElements.activityTable.innerHTML = '';
    
    if (!flows || flows.length === 0) {
        uiElements.activityTable.innerHTML = '<tr><td colspan="5" class="text-center">No active traffic</td></tr>';
        return;
    }

    flows.forEach(flow => {
        const tr = document.createElement('tr');
        const badgeClass = flow.status === 'normal' ? 'normal' : 'anomaly';
        const badgeText = flow.status === 'normal' ? 'Normal' : 'Anomaly';

        tr.innerHTML = `
            <td>${flow.time}</td>
            <td>${flow.src}</td>
            <td>${flow.port}</td>
            <td>${flow.proto}</td>
            <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        `;
        uiElements.activityTable.appendChild(tr);
    });
}

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live-traffic`;
    const socket = new WebSocket(wsUrl);

    socket.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);
            processDashboardData(data);
        } catch (e) {
            console.error("WS message error:", e);
        }
    };

    socket.onerror = function () {
        socket.close();
    };

    socket.onclose = function () {
        setTimeout(initWebSocket, 5000);
    };
}

const btnAction = document.querySelector('.btn-action');
if (btnAction) {
    btnAction.addEventListener('click', async function () {
        if (currentFlows.length === 0) {
            alert("No traffic to block!");
            return;
        }

        const targetIp = currentFlows[0].src; 

        try {
            const response = await fetch('/api/block-ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: targetIp })
            });
            
            const result = await response.json();
            alert(result.message);

            uiElements.predictionAlert.classList.remove('active');
            fetchDashboardData(); 
            
        } catch (error) {
            console.error("Error blocking IP:", error);
            alert("Failed to block IP. Check console for details.");
        }
    });
}

setInterval(fetchDashboardData, 3000);
fetchDashboardData();
initWebSocket();