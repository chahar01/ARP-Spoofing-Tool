let typeChartInstance = null;
let severityChartInstance = null;
let network = null;

function loadInterfaces() {
    const attackSel = document.getElementById('interfaceAttack');
    const monitorSel = document.getElementById('interfaceMonitor');
    attackSel.innerHTML = '<option value="">-- Select --</option>';
    monitorSel.innerHTML = '<option value="">-- Select --</option>';
    const setupContainer = document.getElementById('setupAlertContainer');
    const setupAlert = document.getElementById('setupAlert');

    function showSetupMessage(msg) {
        if (setupAlert) {
            setupAlert.innerHTML = msg;
            setupContainer.style.display = 'block';
        } else {
            alert(msg);
        }
    }

    fetch('/api/interfaces_with_ip')
        .then(res => res.json())
        .catch(err => { console.error('interfaces_with_ip error', err); return []; })
        .then(data => {
            if (!data || data.length === 0) {
                return fetch('/api/interfaces').then(r => r.json()).catch(err => { console.error('interfaces fallback error', err); return []; });
            }
            return data;
        })
        .then(data => {
            if (!data || data.length === 0) {
                // no interfaces found
                attackSel.innerHTML = '<option value="">No interfaces detected — type manually</option>';
                monitorSel.innerHTML = '<option value="">No interfaces detected — type manually</option>';
                showSetupMessage(`No network interfaces detected. On Windows install Npcap and run this app as Administrator. Alternatively type the interface name manually into the field.`);
                return;
            }
            // populate options
            setupContainer.style.display = 'none';
            data.forEach(item => {
                const label = item.ip ? `${item.name} (${item.ip})` : item.name;
                const opt1 = document.createElement('option');
                opt1.value = item.name;
                opt1.textContent = label;
                attackSel.appendChild(opt1);
                const opt2 = document.createElement('option');
                opt2.value = item.name;
                opt2.textContent = label;
                monitorSel.appendChild(opt2);
            });
        });
}

function runEnvCheck() {
    fetch('/api/env_check')
        .then(r => r.json())
        .then(info => {
            const container = document.getElementById('setupAlertContainer');
            const alert = document.getElementById('setupAlert');
            let html = `<strong>Environment check</strong><br>`;
            html += `<div>Python: ${info.python_version.split('\n')[0]}</div>`;
            html += `<div>Platform: ${info.platform}</div>`;
            html += `<div>Admin/root: ${info.is_admin}</div>`;
            html += `<div>Scapy: ${info.scapy.installed ? 'installed ' + (info.scapy.version||'') : '<b>missing</b>'}</div>`;
            html += `<div>ifaddr: ${info.ifaddr.installed ? 'installed' : 'missing'}</div>`;
            html += `<div>psutil: ${info.psutil.installed ? 'installed' : 'missing'}</div>`;
            html += `<div style="margin-top:8px;"><strong>Interfaces:</strong><br>`;
            if (info.interfaces && info.interfaces.length) {
                info.interfaces.forEach(i => { html += `${i.name} ${i.ip ? '('+i.ip+')' : ''}<br>`; });
            } else {
                html += 'None detected<br>'
            }
            html += `</div>`;
            html += `<div style="margin-top:8px;">
                <button id="copyInstall" class="btn btn-sm btn-primary">Copy pip install</button>
                <button id="openNpcap" class="btn btn-sm btn-secondary ms-2">Open Npcap page</button>
            </div>`;
            alert.innerHTML = html;
            container.style.display = 'block';
            document.getElementById('copyInstall').addEventListener('click', () => {
                navigator.clipboard.writeText('pip install -r requirements.txt');
                alert('Copied pip install command to clipboard.');
            });
            document.getElementById('openNpcap').addEventListener('click', () => {
                window.open('https://nmap.org/npcap/', '_blank');
            });
        })
        .catch(err => {
            console.error('Env check failed', err);
            alert('Environment check failed: ' + err);
        });
}

function loadStatistics() {
    fetch('/api/statistics')
        .then(res => res.json())
        .then(data => {
            document.getElementById('stat-total').textContent = data.total_events || 0;
            document.getElementById('stat-critical').textContent = data.critical_alerts || 0;
            document.getElementById('stat-warning').textContent = data.warnings || 0;
            document.getElementById('stat-info').textContent = data.info_events || 0;
            document.getElementById('stat-attacks').textContent = data.total_attacks || 0;
        });
}

function loadEvents() {
    const search = document.getElementById('searchInput').value;
    const type = document.getElementById('typeFilter').value;
    const severity = document.getElementById('severityFilter').value;
    let url = `/api/events?limit=100`;
    if (type) url += `&type=${type}`;
    if (severity) url += `&severity=${severity}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    fetch(url)
        .then(response => response.json())
        .then(data => {
            const tbody = document.getElementById('eventBody');
            tbody.innerHTML = '';
            data.forEach(event => {
                let severityBadge = '';
                if (event.severity === 'critical') severityBadge = '<span class="badge bg-danger">Critical</span>';
                else if (event.severity === 'warning') severityBadge = '<span class="badge bg-warning">Warning</span>';
                else severityBadge = '<span class="badge bg-info">Info</span>';
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(event.timestamp).toLocaleString()}</td>
                    <td>${event.event_type}</td>
                    <td>${event.source_ip || ''}</td>
                    <td>${event.target_ip || ''}</td>
                    <td>${event.source_mac || ''}</td>
                    <td>${event.target_mac || ''}</td>
                    <td>${event.details || ''}</td>
                    <td>${severityBadge}</td>
                `;
                tbody.appendChild(row);
            });
        });
}

function loadCharts() {
    fetch('/api/event_counts')
        .then(response => response.json())
        .then(data => {
            const typeCtx = document.getElementById('typeChart').getContext('2d');
            if (typeChartInstance) typeChartInstance.destroy();
            typeChartInstance = new Chart(typeCtx, {
                type: 'pie',
                data: {
                    labels: Object.keys(data.type_counts),
                    datasets: [{
                        data: Object.values(data.type_counts),
                        backgroundColor: ['#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8', '#6c757d']
                    }]
                },
                options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
            });
            const sevCtx = document.getElementById('severityChart').getContext('2d');
            if (severityChartInstance) severityChartInstance.destroy();
            severityChartInstance = new Chart(sevCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(data.severity_counts),
                    datasets: [{
                        label: 'Severity Distribution',
                        data: Object.values(data.severity_counts),
                        backgroundColor: ['#17a2b8', '#ffc107', '#dc3545']
                    }]
                },
                options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
            });
        });
}

function updateTopology(devices, attackerIp, gatewayIp) {
    const nodes = [];
    const edges = [];
    devices.forEach(dev => {
        nodes.push({ id: dev.ip, label: dev.ip + '\n' + dev.mac, shape: 'dot' });
    });
    if (attackerIp) {
        nodes.push({ id: 'attacker', label: 'Attacker\n' + attackerIp, color: '#ff0000', shape: 'box' });
    }
    if (gatewayIp) {
        nodes.push({ id: 'gateway', label: 'Gateway\n' + gatewayIp, color: '#00cc00', shape: 'star' });
    }
    const activeAttack = document.getElementById('attack-status').textContent.includes('Running');
    const targetIP = document.getElementById('targetIP').value;
    if (activeAttack && targetIP) {
        nodes.forEach(n => {
            if (n.id === targetIP) {
                edges.push({ from: n.id, to: 'attacker' });
            }
        });
        edges.push({ from: 'attacker', to: 'gateway' });
    } else {
        nodes.forEach(n => {
            if (n.id !== 'gateway' && n.id !== 'attacker') {
                edges.push({ from: n.id, to: 'gateway' });
            }
        });
    }
    const container = document.getElementById('networkGraph');
    const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
    const options = { physics: false, interaction: { dragNodes: false } };
    if (network) network.destroy();
    network = new vis.Network(container, data, options);
}

function scanNetwork() {
    const iface = document.getElementById('interfaceMonitor').value || document.getElementById('manualInterfaceMonitor').value;
    if (!iface) { alert('Select or type an interface first.'); return; }
    const ipRange = prompt('Enter IP range to scan (e.g., 192.168.1.0/24):', '192.168.1.0/24');
    if (!ipRange) return;
    fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface, ip_range: ipRange })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'error') { alert(data.message); return; }
        const div = document.getElementById('scanResults');
        div.innerHTML = '<strong>Found devices:</strong><br>';
        data.forEach(dev => {
            div.innerHTML += `${dev.ip} (${dev.mac}) <button class="btn btn-sm btn-outline-primary" onclick="document.getElementById('targetIP').value='${dev.ip}'">Use as Target</button><br>`;
        });
        const gateway = document.getElementById('gatewayIP').value;
        updateTopology(data, null, gateway);
    });
}

function refreshDashboard() {
    loadEvents();
    loadCharts();
    loadStatistics();
}

function exportCSV() {
    window.location.href = '/api/export_csv';
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    loadInterfaces();
    refreshDashboard();
    setInterval(refreshDashboard, 60000);

    // Attack
    document.getElementById('startAttackBtn').addEventListener('click', function() {
        const target = document.getElementById('targetIP').value;
        const gateway = document.getElementById('gatewayIP').value;
        const ifaceSelect = document.getElementById('interfaceAttack').value;
        const ifaceManual = document.getElementById('manualInterfaceAttack').value;
        const iface = ifaceManual || ifaceSelect;
        if (!target || !gateway || !iface) { alert('Fill all fields (interface, target, gateway).'); return; }
        fetch('/api/start_attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_ip: target, gateway_ip: gateway, interface: iface })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Attack started.');
                document.getElementById('attack-status').textContent = 'Attack: Running';
                refreshDashboard();
                scanNetwork();
            } else {
                alert('Error: ' + data.message);
            }
        });
    });

    document.getElementById('stopAttackBtn').addEventListener('click', function() {
        fetch('/api/stop_attack', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Attack stopped.');
                document.getElementById('attack-status').textContent = 'Attack: Stopped';
                refreshDashboard();
                scanNetwork();
            } else {
                alert('Error: ' + data.message);
            }
        });
    });

    // Monitor
    document.getElementById('startMonitorBtn').addEventListener('click', function() {
        const ifaceSelect = document.getElementById('interfaceMonitor').value;
        const ifaceManual = document.getElementById('manualInterfaceMonitor').value;
        const iface = ifaceManual || ifaceSelect;
        if (!iface) { alert('Select or type an interface.'); return; }
        const gwIP = document.getElementById('monitorGatewayIP').value;
        const gwMAC = document.getElementById('monitorGatewayMAC').value;
        const body = { interface: iface };
        if (gwIP) body.gateway_ip = gwIP;
        if (gwMAC) body.gateway_mac = gwMAC;
        fetch('/api/start_monitor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Monitor started.');
                document.getElementById('monitor-status').textContent = 'Monitor: Running';
                refreshDashboard();
            } else {
                alert('Error: ' + data.message);
            }
        });
    });

    document.getElementById('stopMonitorBtn').addEventListener('click', function() {
        fetch('/api/stop_monitor', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Monitor stopped.');
                document.getElementById('monitor-status').textContent = 'Monitor: Stopped';
                refreshDashboard();
            } else {
                alert('Error: ' + data.message);
            }
        });
    });

    // Scan
    document.getElementById('scanBtn').addEventListener('click', scanNetwork);

    // Test
    document.getElementById('runTestBtn').addEventListener('click', function() {
        const iface = document.getElementById('interfaceMonitor').value || document.getElementById('manualInterfaceMonitor').value;
        if (!iface) { alert('Select or type an interface for monitor.'); return; }
        fetch('/api/run_test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Test started. Check events for alerts.');
                refreshDashboard();
            } else {
                alert('Error: ' + data.message);
            }
        });
    });

    // Clear events
    document.getElementById('clearEventsBtn').addEventListener('click', function() {
        if (confirm('Clear all events?')) {
            fetch('/api/clear_events', { method: 'POST' })
            .then(res => res.json())
            .then(data => { if (data.status === 'success') refreshDashboard(); });
        }
    });

    // Export CSV
    document.getElementById('exportCSVBtn').addEventListener('click', exportCSV);

    // Refresh & filters
    document.getElementById('refreshBtn').addEventListener('click', refreshDashboard);
    document.getElementById('searchInput').addEventListener('keyup', refreshDashboard);
    document.getElementById('typeFilter').addEventListener('change', refreshDashboard);
    document.getElementById('severityFilter').addEventListener('change', refreshDashboard);
    // Env check button
    const envBtn = document.getElementById('envCheckBtn');
    if (envBtn) envBtn.addEventListener('click', runEnvCheck);
});