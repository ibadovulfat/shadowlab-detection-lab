
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
        # Warm up both host and process CPU meters so the first samples are usable.
        psutil.cpu_percent(interval=None)
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
            cpu = psutil.cpu_percent(interval=None)
        except Exception:
            cpu = 0.0
        try:
            mem_percent = psutil.virtual_memory().percent
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

def read_windows_events(window_seconds: int = 600, max_events: int = 5000):
    """Read recent Defender/Sysmon events bounded by a TIME WINDOW.

    Production change: the old version blindly grabbed the last 1200
    records per channel regardless of age. On any busy host that's
    ~seconds of routine log noise, and treating that volume as "events"
    made a clean machine look like an active incident. We now walk the
    log newest-first and STOP once events fall outside `window_seconds`
    (default 10 min), so the summary reflects "what happened recently"
    rather than "the log is large". `max_events` is only a memory guard.

    `EVENTLOG_BACKWARDS_READ` yields newest-first, so the first event
    older than the cutoff means everything after it is older too — we
    can stop the whole channel immediately.
    """
    if not (on_windows() and win32evtlog):
        return [], []

    cutoff = time.time() - max(30, int(window_seconds))

    def _event_epoch(ev) -> float:
        # pywin32 PyTime supports int() -> Unix epoch. Fall back to 0.0
        # (treated as "unknown age", kept) if conversion fails so a
        # locale/format quirk never silently drops real events.
        try:
            return float(int(ev.TimeGenerated))
        except Exception:
            return 0.0

    def read_channel(channel: str):
        try:
            h = win32evtlog.OpenEventLog(None, channel)
        except Exception:
            return []
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        got = []
        try:
            while True:
                recs = win32evtlog.ReadEventLog(h, flags, 0)
                if not recs:
                    break
                for ev in recs:
                    try:
                        epoch = _event_epoch(ev)
                        if epoch and epoch < cutoff:
                            # Newest-first: this and everything after it
                            # is outside the window — stop the channel.
                            return got
                        got.append({
                            "TimeGenerated": ev.TimeGenerated.Format(),
                            "EventID": ev.EventID & 0xFFFF,
                            "SourceName": ev.SourceName,
                            "RecordNumber": ev.RecordNumber,
                        })
                        if len(got) >= max_events:
                            return got
                    except Exception:
                        continue
        finally:
            try:
                win32evtlog.CloseEventLog(h)
            except Exception:
                pass
        return got

    return read_channel(DEFENDER_CHANNEL), read_channel(SYSMON_CHANNEL)

def summarize_events(raw, interesting: dict) -> dict:
    """Summarise events counting ONLY the configured interesting IDs.

    Production change: `total` used to be `len(raw)` — every routine OS
    event inflated the count (the "2400 events" that made a benign host
    look active). It now counts only events whose ID is in the
    `interesting` map (config defender_ids/sysmon_ids), so the summary
    reflects security-relevant activity, not raw log volume. Uninteresting
    IDs are dropped entirely instead of being labelled "Event <id>".
    """
    counts: dict[int, int] = {}
    for ev in raw:
        eid = int(ev.get("EventID", 0))
        counts[eid] = counts.get(eid, 0) + 1
    interesting = interesting or {}
    labeled: dict[str, int] = {}
    interesting_total = 0
    for eid, n in sorted(counts.items()):
        if eid in interesting:
            labeled[interesting[eid]] = labeled.get(interesting[eid], 0) + n
            interesting_total += n
    return {"total": interesting_total, "by_id": labeled}

def get_all_processes() -> list[dict]:
    """
    Get a list of all running processes with their details.
    """
    if not psutil:
        return []

    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'exe', 'ppid']):
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
