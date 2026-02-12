
import threading
import time
import collections
import pandas as pd

SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    pass

class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.stop_sniffing = False
        self.thread = None
        self.lock = threading.Lock()

    def start(self, duration=10):
        if not SCAPY_AVAILABLE:
            return "Scapy not installed"
        
        self.packets = []
        self.stop_sniffing = False
        
        def packet_callback(packet):
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                summary = packet.summary()
                
                info = {
                    "time": time.time(),
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "length": len(packet),
                    "summary": summary,
                    "dns_query": ""
                }
                
                # Check for DNS
                if DNS in packet and packet.haslayer(DNSQR):
                    try:
                        info["dns_query"] = packet[DNSQR].qname.decode('utf-8')
                        info["proto"] = "DNS"
                    except:
                        pass
                
                with self.lock:
                    self.packets.append(info)

        # Scapy sniff blocks, so run in a way that respects timeout or count
        # ideally we run sniff(timeout=duration)
        try:
            sniff(prn=packet_callback, timeout=duration, store=0)
        except Exception as e:
            return str(e)
            
        return None

    def get_results(self):
        with self.lock:
            return list(self.packets)

def run_sniffer_session(duration=10):
    sniffer = PacketSniffer()
    error = sniffer.start(duration=duration)
    if error:
        return {"error": error}
    return {"packets": sniffer.get_results()}
