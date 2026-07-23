const slider = document.getElementById('confidenceSlider');
const sliderValue = document.getElementById('thresholdValue');
const btnSave = document.getElementById('btnSave');
const btnCancel = document.getElementById('btnCancel');
const toast = document.getElementById('toastBox');

let currentSettings = {};

if (slider && sliderValue) {
    slider.addEventListener('input', function () {
        sliderValue.innerText = this.value + '%';
        if (this.value < 70) {
            sliderValue.style.color = 'var(--warning-color)';
            if (this.value < 60) sliderValue.style.color = 'var(--danger-color)';
        } else {
            sliderValue.style.color = 'var(--brand-color)';
        }
    });
}

if (btnSave) {
    btnSave.addEventListener('click', function () {
        const tokenInput = document.getElementById('apiToken');
        const monitoringModeSelect = document.getElementById('monitoringMode');
        const orgNameInput = document.getElementById('orgName');
        const activeModelSelect = document.getElementById('activeModel');
        const tokenValue = tokenInput ? tokenInput.value : '';
        const monitoringModeValue = monitoringModeSelect ? monitoringModeSelect.value : 'scapy';

        const payload = {
            orgName: orgNameInput ? orgNameInput.value : '',
            activeModel: activeModelSelect ? activeModelSelect.value : 'lstm',
            confidence: parseInt(slider ? slider.value : 85),
            token: tokenValue,
            monitoringMode: monitoringModeValue
        };

        fetch('/update-settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(response => response.json())
        .then(() => {
            showToast();
            const downloadBtn = document.getElementById('downloadAgentBtn');
            if (downloadBtn) {
                if (tokenValue) {
                    downloadBtn.href = `/download-agent?token=${encodeURIComponent(tokenValue)}`;
                    downloadBtn.style.display = 'block';
                } else {
                    downloadBtn.style.display = 'none';
                }
            }
            currentSettings = payload;
        })
        .catch(error => {
            console.error('Failed to save settings:', error);
            showToast();
        });
    });
}

if (btnCancel) {
    btnCancel.addEventListener('click', function () {
        const orgNameInput = document.getElementById('orgName');
        const activeModelSelect = document.getElementById('activeModel');
        const tokenInput = document.getElementById('apiToken');
        const monitoringModeSelect = document.getElementById('monitoringMode');

        if (orgNameInput) orgNameInput.value = currentSettings.orgName || "My Network";
        if (activeModelSelect) activeModelSelect.value = currentSettings.activeModel || "lstm";
        if (slider) slider.value = currentSettings.confidence || 85;
        if (sliderValue) sliderValue.innerText = (currentSettings.confidence || 85) + '%';
        if (tokenInput) tokenInput.value = currentSettings.token || "";
        if (monitoringModeSelect) monitoringModeSelect.value = currentSettings.monitoringMode || "scapy";
    });
}

function showToast() {
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

async function loadSettings() {
    try {
        const response = await fetch('/api/get-settings');
        const data = await response.json();

        document.getElementById('orgName').value = data.orgName;
        document.getElementById('activeModel').value = data.activeModel;
        slider.value = data.confidence;
        sliderValue.innerText = data.confidence + '%';
        document.getElementById('apiToken').value = data.token || "";
        document.getElementById('monitoringMode').value = data.monitoringMode || "scapy";
        
        const downloadBtn = document.getElementById('downloadAgentBtn');
        if (data.token) {
            downloadBtn.href = `/download-agent?token=${encodeURIComponent(data.token)}`;
            downloadBtn.style.display = 'block';
        }else {
            downloadBtn.style.display = 'none';
        }

        currentSettings = data;
    } catch (error) {
        console.error("Error loading settings:", error);
    }
}

document.addEventListener('DOMContentLoaded', loadSettings);