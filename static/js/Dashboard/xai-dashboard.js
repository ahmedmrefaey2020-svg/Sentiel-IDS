const incidentInfo = document.getElementById('incidentInfo');
const shapContainer = document.getElementById('shapContainer');

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

async function fetchXAIData() {
    try {
        const response = await fetch('/api/dashboard-data');
        const data = await response.json();

        if (data.xai_explanation) {
            renderXAI(data.xai_explanation);
        }
        
        updateMonitoringStatusBadge(data.monitoring_mode, data.is_fallback_active, data.user_api_token);
        
    } catch (error) {
        console.error("Error fetching XAI data:", error);
    }
}

function renderXAI(explanation) {
    incidentInfo.innerHTML = `
        <div class="incident-title">Prediction: ${explanation.title}</div>
        <div class="incident-meta">
            <span>Confidence: <strong>${explanation.confidence}%</strong></span>
            <span>Target: ${explanation.target_ip}</span>
            <span>Model: ${explanation.model_name}</span>
        </div>
    `;

    let html = '';
    explanation.features.forEach(feat => {
        const isPositive = feat.value > 0;
        const colorClass = isPositive ? 'shap-red' : 'shap-green';
        const sign = isPositive ? '+' : '';
        
        html += `
            <div class="shap-row">
                <div class="shap-label">${feat.name}</div>
                <div class="shap-value">${sign}${feat.value}%</div>
                <div class="shap-bar-container">
                    <div class="shap-bar ${colorClass}" style="width: ${Math.abs(feat.value)}%;"></div>
                </div>
            </div>
        `;
    });

    shapContainer.innerHTML = html;
}

setInterval(fetchXAIData, 6000);
fetchXAIData();
