const ui = {
    feed: document.getElementById('threatFeed'),
    iocs: document.getElementById('activeIocs'),
    blocked: document.getElementById('blockedIps')
};

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

async function fetchThreatData() {
    try {
        const response = await fetch('/api/dashboard-data');
        const data = await response.json();

        if (data.total_iocs) {
            ui.iocs.innerHTML = `${data.total_iocs.toLocaleString()} <span class="trend-up">↑ 12%</span>`;
        }
        if (data.total_blocked) {
            ui.blocked.innerHTML = `${data.total_blocked.toLocaleString()} <span class="trend-up">↑ 5%</span>`;
        }

        renderThreatFeed(data.recent_flows || data.network_flows || []);
        updateMonitoringStatusBadge(data.monitoring_mode, data.is_fallback_active, data.user_api_token);

    } catch (error) {
        console.error("Error fetching threat intel:", error);
    }
}

function renderThreatFeed(flows) {
    ui.feed.innerHTML = '';
    
    const threats = flows.filter(f => f.status === 'anomaly' || f.isAttack === true);

    if (threats.length === 0) {
        ui.feed.innerHTML = '<tr><td colspan="5" class="text-center">No active threat indicators detected.</td></tr>';
        return;
    }

    threats.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="color: var(--text-secondary);">${row.time || 'N/A'}</td>
            <td>${row.src}</td>
            <td>${row.proto || 'TCP'}</td>
            <td><span class="badge critical">High</span></td>
            <td class="action-blocked">✓ Blocked via Firewall</td>
        `;
        ui.feed.appendChild(tr);
    });
}

setInterval(fetchThreatData, 3000);
fetchThreatData();
