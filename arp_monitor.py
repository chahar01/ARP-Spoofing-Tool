import threading
import time
from collections import deque
import importlib
from database import insert_event

try:
    _scapy = importlib.import_module('scapy.all')
    sniff = _scapy.sniff
    ARP = _scapy.ARP
except Exception:
    sniff = None
    ARP = None

class ARPMonitor:
    def __init__(self):
        self.interface = None
        self.active = False
        self.thread = None
        self.ip_mac_history = {}
        self.request_history = set()
        self.duplicate_threshold = 5
        self.rate_window = 10
        self.reply_counter = {}
        self.gateway_mac = None

    def _packet_handler(self, pkt):
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            ip = arp.psrc
            mac = arp.hwsrc
            now = time.time()
            if arp.op == 1:
                self.request_history.add((arp.psrc, arp.pdst))
            elif arp.op == 2:
                if (ip, arp.pdst) not in self.request_history:
                    insert_event("detection_alert", source_ip=ip, source_mac=mac,
                                 details=f"Unsolicited ARP reply from {ip} (MAC {mac})",
                                 severity="warning")

                if ip in self.ip_mac_history:
                    recent = [entry for entry in self.ip_mac_history[ip] if now - entry[0] < self.duplicate_threshold]
                    if recent and any(mac != recent[0][1] for entry in recent):
                        details = f"Duplicate IP / MAC change for {ip} within {self.duplicate_threshold}s: old {recent[0][1]}, new {mac}"
                        insert_event("detection_alert", source_ip=ip, source_mac=mac,
                                     details=details, severity="critical")
                else:
                    self.ip_mac_history[ip] = deque(maxlen=20)
                self.ip_mac_history[ip].append((now, mac))

                if ip not in self.reply_counter:
                    self.reply_counter[ip] = []
                self.reply_counter[ip].append(now)
                self.reply_counter[ip] = [t for t in self.reply_counter[ip] if now - t < self.rate_window]
                if len(self.reply_counter[ip]) > 10:
                    details = f"Excessive ARP replies from {ip} ({len(self.reply_counter[ip])} in {self.rate_window}s)"
                    insert_event("detection_alert", source_ip=ip, source_mac=mac,
                                 details=details, severity="warning")

                if self.gateway_mac and ip == self.gateway_ip and mac != self.gateway_mac:
                    details = f"Gateway MAC changed! Expected {self.gateway_mac}, got {mac}"
                    insert_event("detection_alert", source_ip=ip, source_mac=mac,
                                 details=details, severity="critical")

                if arp.pdst == arp.psrc and arp.hwdst == "ff:ff:ff:ff:ff:ff":
                    details = f"Gratuitous ARP reply from {ip} (MAC {mac})"
                    insert_event("detection_alert", source_ip=ip, target_ip=arp.pdst,
                                 source_mac=mac, target_mac=arp.hwdst,
                                 details=details, severity="warning")

    def _sniff_loop(self):
        sniff(iface=self.interface, filter="arp", prn=self._packet_handler, store=0,
              stop_filter=lambda x: not self.active)

    def start_monitoring(self, interface, gateway_ip=None, gateway_mac=None):
        if self.active:
            return False
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.active = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        insert_event("monitor_start", details=f"ARP monitoring started on {interface}", severity="info")
        return True

    def stop_monitoring(self):
        if not self.active:
            return False
        self.active = False
        if self.thread:
            self.thread.join(timeout=1)
        insert_event("monitor_stop", details="ARP monitoring stopped", severity="info")
        self.interface = None
        return True

monitor = ARPMonitor()