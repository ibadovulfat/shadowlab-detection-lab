
import psutil
import time
import pandas as pd

class ProcessTracer:
    def __init__(self, pid):
        self.pid = pid
        self.process = None
        self.running = False
        self.events = []
        
        try:
            self.process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            pass

    def trace(self, duration=5, interval=0.5):
        """
        Polls the process for open files and connections over a duration.
        This simulates 'tracing' without kernel-level hooks.
        """
        if not self.process:
            return {"error": "Process not found"}

        self.events = []
        end_time = time.time() + duration
        
        seen_files = set()
        seen_conns = set()
        
        while time.time() < end_time:
            try:
                # 1. Open Files
                try:
                    open_files = self.process.open_files()
                    for f in open_files:
                        if f.path not in seen_files:
                            self.events.append({
                                "time": time.strftime("%H:%M:%S"),
                                "type": "FILE_OPEN",
                                "detail": f.path,
                                "mode": f.mode
                            })
                            seen_files.add(f.path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # 2. Network Connections
                try:
                    connections = self.process.connections()
                    for c in connections:
                        conn_str = f"{c.laddr} -> {c.raddr} ({c.status})"
                        if conn_str not in seen_conns and c.status == 'ESTABLISHED':
                            self.events.append({
                                "time": time.strftime("%H:%M:%S"),
                                "type": "NET_CONN",
                                "detail": conn_str,
                                "mode": c.type # TCP/UDP
                            })
                            seen_conns.add(conn_str)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                if not self.process.is_running():
                    break
                    
                time.sleep(interval)
                
            except psutil.NoSuchProcess:
                break
                
        return {"events": self.events}
