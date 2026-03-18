
import psutil
import pandas as pd

def get_process_handles(pid):
    """
    Returns a list of open files and connections.
    """
    try:
        p = psutil.Process(pid)
        handles = []
        
        # Open Files
        try:
            for f in p.open_files():
                handles.append({
                    "Type": "File",
                    "Path": f.path,
                    "Mode": f.mode,
                    "FD": f.fd
                })
        except Exception: pass
        
        # Connections
        try:
            for c in p.connections():
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
                handles.append({
                    "Type": "Socket",
                    "Path": f"{c.laddr.ip}:{c.laddr.port} -> {raddr} ({c.status})",
                    "Mode": str(c.type), # TCP/UDP
                    "FD": c.fd
                })
        except Exception: pass
            
        return handles
    except psutil.NoSuchProcess:
        return []

def get_process_libs(pid):
    """
    Returns a list of loaded shared libraries (DLL/dylib).
    """
    try:
        p = psutil.Process(pid)
        libs = []
        try:
            # memory_maps(grouped=False) lists all mapped regions.
            # We filter for files ending in .so, .dylib, .dll
            for m in p.memory_maps(grouped=False):
                path = m.path
                if path and (path.endswith('.dylib') or path.endswith('.so') or path.endswith('.dll')):
                    # Avoid duplicates if mapped multiple times
                    if not any(l['Path'] == path for l in libs):
                        libs.append({
                            "Path": path,
                            "Size": m.rss, # Resident Set Size
                            "Perms": m.perms
                        })
        except Exception: pass
        return libs
    except Exception:
        return []
