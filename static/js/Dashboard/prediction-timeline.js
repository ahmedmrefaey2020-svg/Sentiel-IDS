const ui = {
    progress: document.getElementById('timeProgress'),
    banner: document.getElementById('forecastBanner'),
    title: document.getElementById('forecastTitle'),
    desc: document.getElementById('forecastDesc'),
    mainProb: document.getElementById('mainProbability'),
    log: document.getElementById('eventLog')
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

function getLogTime() {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function addLogEntry(message, level) {
    const li = document.createElement('li');
    li.className = `log-item ${level}`;
    li.innerHTML = `<span class="log-time">[${getLogTime()}]</span><span class="log-message">${message}</span>`;
    ui.log.prepend(li);
    if (ui.log.children.length > 5) ui.log.removeChild(ui.log.lastChild);
}

async function fetchPredictionTimeline() {
    try {
        const response = await fetch('/api/dashboard-data');
        const data = await response.json();

        updateTimelineUI(data.risk_score, data.risk_message);
        updateMonitoringStatusBadge(data.monitoring_mode, data.is_fallback_active, data.user_api_token);
        
    } catch (error) {
        console.error("Error fetching timeline data:", error);
    }
}

function updateTimelineUI(riskScore, message) {
    let width = `${riskScore}%`;
    let level = riskScore > 80 ? 'critical' : (riskScore > 50 ? 'warning' : 'normal');
    let title = riskScore > 80 ? "HIGH PROBABILITY OF ATTACK" : (riskScore > 50 ? "Elevated Risk Horizon" : "Monitoring Normal Traffic");

    ui.progress.style.width = width;
    
    ui.mainProb.innerText = `${riskScore}%`;
    ui.title.innerText = title;
    ui.desc.innerText = message;

    if (riskScore > 80) {
        ui.banner.classList.add('alert');
    } else {
        ui.banner.classList.remove('alert');
    }

    if (riskScore > 50) {
        addLogEntry(message, level);
    }
}

setInterval(fetchPredictionTimeline, 3000);
fetchPredictionTimeline();