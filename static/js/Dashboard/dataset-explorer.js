let fullDataset = [];
let filteredDataset = [];
let currentPage = 1;
const rowsPerPage = 12;

const sidePanel = document.getElementById('sidePanel');
const backdrop = document.getElementById('backdrop');
const btnClosePanel = document.getElementById('btnClosePanel');
const panelTitle = document.getElementById('panelTitle');
const jsonOutput = document.getElementById('jsonOutput');
const toastContainer = document.getElementById('toastContainer');
const dropdownMenu = document.getElementById('dropdownMenu');
const btnToggleMenu = document.getElementById('btnToggleMenu');

async function loadRealDataset() {
    try {
        const response = await fetch('/api/dataset-explorer-data');
        if (!response.ok) throw new Error("Failed to fetch data");
        
        const data = await response.json();
        
        fullDataset = data;
        filteredDataset = [...fullDataset];
        
        updateStats(filteredDataset);
        renderTable();
        showToast('Dataset loaded successfully', 'success');
    } catch (error) {
        console.error("Error loading dataset:", error);
        showToast('Failed to load real-time data.', 'error');
    }
}

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    toastContainer.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 3000);
}

function renderTable() {
    const tbody = document.getElementById('tableBody');
    tbody.innerHTML = '';

    const start = (currentPage - 1) * rowsPerPage;
    const paginatedItems = filteredDataset.slice(start, start + rowsPerPage);

    paginatedItems.forEach(row => {
        const tr = document.createElement('tr');
        tr.onclick = () => openRowDetails(row.id);
        tr.innerHTML = `
            <td class="mono">${row.id}</td>
            <td class="mono">${row.time}</td>
            <td class="mono">${row.src}</td>
            <td class="mono">${row.dest}</td>
            <td>${row.proto}</td>
            <td class="mono">${row.duration}</td>
            <td class="mono">${row.packets}</td>
            <td><span class="badge ${row.isAttack ? 'attack' : 'normal'}">${row.label}</span></td>
        `;
        tbody.appendChild(tr);
    });
    updatePagination();
}

function applyFilters() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const protoFilter = document.getElementById('filterProtocol').value;
    const labelFilter = document.getElementById('filterLabel').value;

    filteredDataset = fullDataset.filter(row => {
        const matchesSearch = row.src.includes(searchTerm) || row.dest.includes(searchTerm);
        const matchesProto = protoFilter === 'All' || row.proto === protoFilter;
        let matchesLabel = (labelFilter === 'All') || (labelFilter === 'Normal' ? !row.isAttack : row.isAttack);
        return matchesSearch && matchesProto && matchesLabel;
    });

    currentPage = 1;
    updateStats(filteredDataset);
    renderTable();
}

function updateStats(data) {
    const total = data.length;
    const attacks = data.filter(r => r.isAttack).length;
    document.getElementById('statTotal').innerText = total.toLocaleString();
    document.getElementById('statAttack').innerText = attacks.toLocaleString();
    document.getElementById('statNormal').innerText = (total - attacks).toLocaleString();
}

function openRowDetails(flowId) {
    const flowData = fullDataset.find(f => f.id === flowId);
    if (!flowData) return;

    panelTitle.innerText = `Flow Details: ${flowData.id}`;
    jsonOutput.innerHTML = syntaxHighlight(JSON.stringify(flowData, null, 4));
    sidePanel.classList.add('active');
    backdrop.classList.add('active');
}

function syntaxHighlight(json) {
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let cls = 'json-number';
        if (/^"/.test(match)) { cls = /:$/.test(match) ? 'json-key' : 'json-string'; }
        else if (/true|false/.test(match)) { cls = 'json-boolean'; }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

document.getElementById('searchInput').addEventListener('input', applyFilters);
document.getElementById('filterProtocol').addEventListener('change', applyFilters);
document.getElementById('filterLabel').addEventListener('change', applyFilters);

loadRealDataset();