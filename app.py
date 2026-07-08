import threading
import csv
import subprocess
import re
from io import StringIO
from flask import Flask, render_template, request, jsonify, Response
from database import init_db, get_events, get_event_counts, clear_events
from arp_spoofer import spoofer
from arp_monitor import monitor
import importlib
import test_scenarios
import sys
import os
import platform
import ctypes

# Lazy-load scapy
try:
    _scapy = importlib.import_module('scapy.all')
    get_if_list = _scapy.get_if_list
    get_if_addr = _scapy.get_if_addr
    arping = _scapy.arping
except Exception:
    get_if_list = None
    get_if_addr = None
    arping = None

# Optional: ifaddr for reliable IP detection (pure Python)
try:
    import ifaddr
    HAS_IFADDR = True
except ImportError:
    HAS_IFADDR = False

# Optional: psutil fallback
try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False

# At startup, guide the user if Scapy isn't available
if get_if_list is None:
    print("WARNING: Scapy not detected. Some network features will be disabled.")
    print("- On Windows, install Npcap (https://nmap.org/npcap/) and run the app as Administrator.")
    print("- You can still operate the dashboard in read-only mode; to enable full features run: pip install -r requirements.txt")

app = Flask(__name__)
init_db()


@app.route('/')
def index():
    """Serve the main dashboard page."""
    try:
        return render_template('index.html')
    except Exception as e:
        # If template not found, return a helpful message
        return f"Dashboard template not found or render error: {e}", 500

# ---------- Debug endpoint ----------
@app.route('/debug/interfaces')
def debug_interfaces():
    try:
        if get_if_list:
            ifaces = get_if_list()
            out = []
            for i in ifaces:
                ip = get_if_addr(i) if get_if_addr else 'N/A'
                out.append(f"{i} -> {ip}")
            return "<br>".join(out) if out else "No interfaces found by Scapy."
        else:
            return "Scapy not available. Check installation."
    except Exception as e:
        return f"Error: {e}"

# ---------- Fallback: system tools ----------
def get_interface_ips_from_system():
    result = []
    try:
        output = subprocess.check_output("ipconfig", encoding="utf-8")
        sections = re.split(r'\n(?=[A-Za-z])', output)
        for section in sections:
            lines = section.splitlines()
            if not lines:
                continue
            first = lines[0].strip()
            name_match = re.match(r'^(.*?) adapter (.*?):$', first)
            if name_match:
                adapter_type = name_match.group(1).strip()
                adapter_name = name_match.group(2).strip()
                full_name = f"{adapter_type} {adapter_name}".strip()
            else:
                if ':' in first:
                    full_name = first.split(':', 1)[0].strip()
                else:
                    full_name = first
            ip = None
            for line in lines:
                if 'IPv4 Address' in line or 'IP Address' in line:
                    ip_match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        break
            if ip and ip != '127.0.0.1' and not ip.startswith('169.254.'):
                result.append({'name': full_name, 'ip': ip})
    except Exception as e:
        print("ipconfig fallback error:", e)

    if not result:
        try:
            output = subprocess.check_output("ifconfig", encoding="utf-8")
            for block in output.split('\n\n'):
                if not block.strip():
                    continue
                lines = block.splitlines()
                if not lines:
                    continue
                first = lines[0]
                if ':' in first and 'flags' in first:
                    iface = first.split(':', 1)[0].strip()
                else:
                    continue
                ip = None
                for line in lines:
                    if 'inet ' in line and '127.0.0.1' not in line:
                        parts = line.split()
                        ip = parts[1] if len(parts) > 1 else None
                        break
                if ip and not ip.startswith('169.254.'):
                    result.append({'name': iface, 'ip': ip})
        except Exception as e2:
            print("ifconfig fallback error:", e2)
    return result


@app.route('/api/env_check', methods=['GET'])
def env_check():
    """Return runtime environment diagnostics useful for setup troubleshooting."""
    info = {}
    info['python_version'] = sys.version
    info['platform'] = platform.platform()
    # admin/root check
    try:
        if platform.system() == 'Windows':
            info['is_admin'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            info['is_admin'] = (os.geteuid() == 0)
    except Exception:
        info['is_admin'] = False

    # packages
    def _check(pkg_name, attr='__version__'):
        try:
            m = importlib.import_module(pkg_name)
            ver = getattr(m, attr, None)
            return {'installed': True, 'version': str(ver)}
        except Exception:
            return {'installed': False, 'version': None}

    info['scapy'] = _check('scapy')
    info['ifaddr'] = _check('ifaddr')
    info['psutil'] = _check('psutil')

    # interface enumeration
    interfaces = []
    try:
        if get_if_list:
            for i in get_if_list():
                try:
                    ip = get_if_addr(i) if get_if_addr else None
                except Exception:
                    ip = None
                interfaces.append({'name': i, 'ip': ip})
    except Exception:
        pass
    if not interfaces:
        # try system fallback
        try:
            fallback = get_interface_ips_from_system()
            for item in fallback:
                interfaces.append(item)
        except Exception:
            pass
    info['interfaces'] = interfaces
    # quick guidance
    guidance = []
    if not info['scapy']['installed']:
        guidance.append('Scapy not installed: run `pip install -r requirements.txt`.')
    if platform.system() == 'Windows':
        guidance.append('On Windows install Npcap (https://nmap.org/npcap/) and run this app as Administrator.')
    else:
        guidance.append('On Unix-like systems run the app as root or with capabilities to use libpcap.')
    info['guidance'] = guidance
    return jsonify(info)

# ---------- API endpoints ----------
@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    try:
        if get_if_list:
            ifaces = get_if_list()
            if ifaces:
                return jsonify(ifaces)
    except Exception as e:
        print("Error getting interfaces via Scapy:", e)
    fallback = get_interface_ips_from_system()
    names = [x['name'] for x in fallback]
    return jsonify(names)

@app.route('/api/interfaces_with_ip', methods=['GET'])
def interfaces_with_ip():
    result = []
    # 1) Scapy
    try:
        if get_if_list:
            ifaces = get_if_list()
            for iface in ifaces:
                ip = get_if_addr(iface) if get_if_addr else None
                result.append({'name': iface, 'ip': ip if ip else None})
    except Exception as e:
        print("Scapy interface IP retrieval failed:", e)

    # 2) System fallback
    if not result:
        fallback = get_interface_ips_from_system()
        if fallback:
            for item in fallback:
                result.append({'name': item['name'], 'ip': item['ip']})

    # 3) ifaddr fallback
    if not result and HAS_IFADDR:
        try:
            adapters = ifaddr.get_adapters()
            for adapter in adapters:
                for ip in adapter.ips:
                    if ip.is_IPv4 and ip.ip != '127.0.0.1' and not ip.ip.startswith('169.254.'):
                        result.append({'name': adapter.nice_name, 'ip': ip.ip})
                        break
        except Exception as e:
            print("ifaddr fallback error:", e)

    # 4) psutil fallback
    if not result and HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            for name, infos in addrs.items():
                for a in infos:
                    if getattr(a, 'family', None):
                        fam = a.family
                        # AF_INET constant might not be available; compare by name
                        if hasattr(psutil, 'AF_INET') and fam == psutil.AF_INET:
                            ip = a.address
                        else:
                            # on Windows a.family may be socket.AddressFamily
                            try:
                                import socket
                                if fam == socket.AF_INET:
                                    ip = a.address
                                else:
                                    ip = None
                            except Exception:
                                ip = None
                        if ip and ip != '127.0.0.1' and not ip.startswith('169.254.'):
                            result.append({'name': name, 'ip': ip})
                            break
        except Exception as e:
            print('psutil fallback error:', e)

    # 4) Placeholder if nothing found
    if not result:
        result = [{'name': 'No interfaces found - check Npcap', 'ip': None}]

    return jsonify(result)

@app.route('/api/scan', methods=['POST'])
def scan_network():
    data = request.get_json()
    interface = data.get('interface')
    ip_range = data.get('ip_range', '192.168.1.0/24')
    if not interface:
        return jsonify({'status': 'error', 'message': 'Interface required'}), 400
    try:
        if arping is None:
            return jsonify({'status': 'error', 'message': 'Scapy arping not available'}), 500
        ans, _ = arping(ip_range, iface=interface, timeout=2, verbose=False)
        devices = []
        for sent, received in ans:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        return jsonify(devices)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/start_attack', methods=['POST'])
def start_attack():
    data = request.get_json()
    target_ip = data.get('target_ip')
    gateway_ip = data.get('gateway_ip')
    interface = data.get('interface')
    if not all([target_ip, gateway_ip, interface]):
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400
    result = spoofer.start_spoofing(target_ip, gateway_ip, interface)
    # start_spoofing now returns (success, message) or boolean for backwards compat
    if isinstance(result, tuple) or isinstance(result, list):
        success, message = result[0], result[1] if len(result) > 1 else None
    else:
        success, message = bool(result), None

    if success:
        if target_ip in spoofer.original_macs and gateway_ip in spoofer.original_macs:
            monitor.gateway_ip = gateway_ip
            monitor.gateway_mac = spoofer.original_macs[gateway_ip]
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': message or 'Failed to resolve MACs'}), 500

@app.route('/api/stop_attack', methods=['POST'])
def stop_attack():
    result = spoofer.stop_spoofing()
    if result:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': 'Attack not active'}), 400

@app.route('/api/start_monitor', methods=['POST'])
def start_monitor():
    data = request.get_json()
    interface = data.get('interface')
    if not interface:
        return jsonify({'status': 'error', 'message': 'Interface required'}), 400
    gateway_ip = data.get('gateway_ip')
    gateway_mac = data.get('gateway_mac')
    result = monitor.start_monitoring(interface, gateway_ip, gateway_mac)
    if result:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': 'Monitor already active'}), 400

@app.route('/api/stop_monitor', methods=['POST'])
def stop_monitor():
    result = monitor.stop_monitoring()
    if result:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': 'Monitor not active'}), 400

@app.route('/api/events', methods=['GET'])
def events():
    limit = request.args.get('limit', default=100, type=int)
    offset = request.args.get('offset', default=0, type=int)
    event_type = request.args.get('type')
    severity = request.args.get('severity')
    search = request.args.get('search')
    events_data = get_events(limit=limit, offset=offset, event_type=event_type,
                             severity=severity, search=search)
    return jsonify(events_data)

@app.route('/api/event_counts', methods=['GET'])
def event_counts():
    return jsonify(get_event_counts())

@app.route('/api/clear_events', methods=['POST'])
def clear_events_route():
    clear_events()
    return jsonify({'status': 'success'})

@app.route('/api/run_test', methods=['POST'])
def run_test():
    data = request.get_json()
    interface = data.get('interface')
    if not interface:
        return jsonify({'status': 'error', 'message': 'Interface required'}), 400
    def test_thread():
        test_scenarios.run_basic_test(interface=interface)
    t = threading.Thread(target=test_thread, daemon=True)
    t.start()
    return jsonify({'status': 'success', 'message': 'Test scenario started'})

@app.route('/api/export_csv', methods=['GET'])
def export_csv():
    events = get_events(limit=10000)
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['timestamp', 'type', 'source_ip', 'target_ip', 'source_mac', 'target_mac', 'details', 'severity'])
    for e in events:
        cw.writerow([e['timestamp'], e['event_type'], e['source_ip'], e['target_ip'],
                     e['source_mac'], e['target_mac'], e['details'], e['severity']])
    output = si.getvalue()
    return Response(output, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=arp_events.csv'})

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    counts = get_event_counts()
    total_events = sum(counts['type_counts'].values())
    critical = counts['severity_counts'].get('critical', 0)
    warning = counts['severity_counts'].get('warning', 0)
    info = counts['severity_counts'].get('info', 0)
    attacks = counts['type_counts'].get('attack_start', 0)
    return jsonify({
        'total_events': total_events,
        'critical_alerts': critical,
        'warnings': warning,
        'info_events': info,
        'total_attacks': attacks
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)