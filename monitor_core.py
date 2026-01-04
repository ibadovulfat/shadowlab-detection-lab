
from __future__ import annotations
import time
import platform

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

# Windows event log (optional)
try:
    import win32evtlog  # type: ignore
except Exception:
    win32evtlog = None

DEFENDER_CHANNEL = r"Microsoft-Windows-Windows Defender/Operational"
SYSMON_CHANNEL   = r"Microsoft-Windows-Sysmon/Operational"



def on_windows() -> bool:
    return platform.system().lower().startswith("win")

class TelemetrySampler:
    def __init__(self):
        if psutil is None:
            raise RuntimeError("psutil not installed. pip install psutil")
        self.proc = psutil.Process()
        # Warm up CPU percent meter
        self.proc.cpu_percent(interval=None)
        self.last_net_io = psutil.net_io_counters()
        self.last_sample_time = time.time()

    def network_sampler(self) -> dict:
        current_net_io = psutil.net_io_counters()
        now = time.time()
        time_delta = now - self.last_sample_time
        if time_delta == 0:
            return {"bytes_sent_rate": 0, "bytes_recv_rate": 0}

        bytes_sent_rate = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / time_delta
        bytes_recv_rate = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / time_delta

        self.last_net_io = current_net_io
        self.last_sample_time = now

        return {
            "bytes_sent_rate": bytes_sent_rate,
            "bytes_recv_rate": bytes_recv_rate,
        }

    def sample(self) -> dict:
        try:
            cpu = self.proc.cpu_percent(interval=None)
        except Exception:
            cpu = 0.0
        try:
            mem_percent = self.proc.memory_percent()
        except Exception:
            mem_percent = 0.0
        try:
            proc_threads = self.proc.num_threads()
        except Exception:
            proc_threads = 0
        try:
            proc_handles = self.proc.num_handles() if hasattr(self.proc, "num_handles") else None
        except Exception:
            proc_handles = None
        try:
            open_files = len(self.proc.open_files())
        except Exception:
            open_files = 0
        try:
            established_conns = [c for c in psutil.net_connections(kind="tcp") if c.status == psutil.CONN_ESTABLISHED]
            tcp_conns = len(established_conns)
            remote_ips = list(set([c.raddr.ip for c in established_conns if c.raddr]))
        except Exception:
            tcp_conns = 0
            remote_ips = []

        network_sample = self.network_sampler()

        return {
            "ts": time.time(),
            "cpu": cpu,
            "mem_percent": mem_percent,
            "proc_threads": proc_threads,
            "proc_handles": proc_handles,
            "open_files": open_files,
            "tcp_conns": tcp_conns,
            "remote_ips": remote_ips,
            **network_sample,
        }

def read_windows_events(max_events: int = 1200):
    if not (on_windows() and win32evtlog):
        return [], []
    def read_channel(channel: str):
        h = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        got = []
        while True:
            recs = win32evtlog.ReadEventLog(h, flags, 0)
            if not recs:
                break
            for ev in recs:
                try:
                    got.append({
                        "TimeGenerated": ev.TimeGenerated.Format(),
                        "EventID": ev.EventID & 0xFFFF,
                        "SourceName": ev.SourceName,
                        "RecordNumber": ev.RecordNumber,
                    })
                    if len(got) >= max_events:
                        win32evtlog.CloseEventLog(h)
                        return got
                except Exception:
                    continue
        win32evtlog.CloseEventLog(h)
        return got
    return read_channel(DEFENDER_CHANNEL), read_channel(SYSMON_CHANNEL)

def summarize_events(raw, interesting: dict) -> dict:
    counts = {}
    for ev in raw:
        eid = int(ev.get("EventID", 0))
        counts[eid] = counts.get(eid, 0) + 1
    labeled = {interesting.get(k, f"Event {k}"): v for k, v in sorted(counts.items())}
    return {"total": len(raw), "by_id": labeled}

def get_all_processes() -> list[dict]:
    """
    Get a list of all running processes with their details.
    """
    if not psutil:
        return []

    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        procs.append(p.info)
    return procs

def get_network_connections() -> list[dict]:
    """
    Get a list of all network connections with their details.
    """
    if not psutil:
        return []

    connections = []
    for c in psutil.net_connections():
        connections.append({
            "fd": c.fd,
            "family": c.family,
            "type": c.type,
            "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "status": c.status,
            "pid": c.pid,
        })
    return connections
