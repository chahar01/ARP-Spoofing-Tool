import time
import importlib
from database import insert_event

# Lazy-load scapy
try:
    _scapy = importlib.import_module('scapy.all')
    ARP = _scapy.ARP
    Ether = _scapy.Ether
    send = _scapy.send
    get_if_hwaddr = _scapy.get_if_hwaddr
except Exception:
    ARP = Ether = send = get_if_hwaddr = None


def run_basic_test(interface="eth0", test_ip="192.168.1.100", fake_mac="00:11:22:33:44:55"):
    insert_event("test_scenario", details=f"Test: spoofing IP {test_ip} with MAC {fake_mac} on {interface}", severity="info")
    if send is None:
        insert_event("test_scenario", details="Scapy not available; cannot run test.", severity="error")
        return
    for _ in range(3):
        send(ARP(op=2, pdst=test_ip, hwdst="ff:ff:ff:ff:ff:ff",
                 psrc=test_ip, hwsrc=fake_mac),
             iface=interface, verbose=False)
        time.sleep(1)
    insert_event("test_scenario", details="Test completed. Check for detection alerts.", severity="info")