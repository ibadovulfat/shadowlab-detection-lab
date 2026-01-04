
from __future__ import annotations
import threading, time, socket, os, tempfile

class ScenarioRunner:
    """
    Safe lab-only activity generator to create benign load patterns:
      - CPU busy loop (short bursts)
      - File I/O churn in temp directory
      - Loopback TCP connect/disconnect
    No external network, no system changes beyond temp files.
    """
    def __init__(self):
        self._stop = threading.Event()
        self.threads = []
        self._running = False

    def start(self, profile: str, duration: int = 30):
        if self._running:
            return  # Don't start if already running
        self._running = True
        self._stop.clear()
        self.threads = []
        if profile in ("network-heavy","balanced"):
            self.threads.append(threading.Thread(target=self._network_loop, args=(duration,)))
        if profile in ("file-heavy","balanced"):
            self.threads.append(threading.Thread(target=self._file_loop, args=(duration,)))
        if profile in ("cpu-heavy","balanced","network-heavy","memory-heavy"):
            self.threads.append(threading.Thread(target=self._cpu_loop, args=(duration,)))
        if profile == "memory-heavy":
            self.threads.append(threading.Thread(target=self._memory_loop, args=(duration,)))

        for t in self.threads:
            t.daemon = True
            t.start()

    def stop(self):
        self._stop.set()
        for t in self.threads:
            t.join(timeout=1)
        self._running = False

    def _cpu_loop(self, duration):
        end = time.time() + duration
        while time.time() < end and not self._stop.is_set():
            # short bursts: 30ms busy, 70ms sleep
            t0 = time.time()
            while (time.time() - t0) < 0.03:
                pass
            time.sleep(0.07)

    def _file_loop(self, duration):
        end = time.time() + duration
        tmpdir = tempfile.gettempdir()
        i = 0
        while time.time() < end and not self._stop.is_set():
            p = os.path.join(tmpdir, f"shadowlab_tmp_{i}.dat")
            with open(p, "wb") as f:
                f.write(os.urandom(4096))
            try:
                os.remove(p)
            except Exception:
                pass
            i += 1
            time.sleep(0.05)

    def _network_loop(self, duration):
        # loopback only
        end = time.time() + duration
        while time.time() < end and not self._stop.is_set():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", 65535))  # will likely fail fast
            except Exception:
                pass
            finally:
                try: s.close()
                except Exception: pass
            time.sleep(0.05)
            
    def _memory_loop(self, duration):
        end = time.time() + duration
        # Allocate a moderately large object to spike memory
        big_obj = bytearray(256 * 1024 * 1024) # 256 MB
        while time.time() < end and not self._stop.is_set():
            # Touch the memory to keep it resident
            for i in range(0, len(big_obj), 4096):
                big_obj[i] = 0xFF
            time.sleep(0.5)
        del big_obj
