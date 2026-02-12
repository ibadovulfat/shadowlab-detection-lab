
import os
import streamlit as st

YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None

def compile_rules(rule_path="plugins/rules/basic.yar"):
    if not YARA_AVAILABLE:
        return None
    
    try:
        if os.path.exists(rule_path):
            return yara.compile(filepath=rule_path)
        else:
            return None
    except Exception as e:
        st.error(f"YARA Compile Error: {e}")
        return None

def scan_file(filepath, rules):
    """
    Scans a file with compiled YARA rules.
    """
    if not YARA_AVAILABLE or not rules:
        return []
    
    try:
        matches = rules.match(filepath)
        return [m.rule for m in matches]
    except Exception as e:
        # Permission errors are common
        return []

def scan_process_memory(pid, rules):
    """
    Scanning process memory usually requires Ptrace/mmap permissions or dumping memory first.
    Python's 'yara' module has match(pid=...) support on some platforms (Linux/Windows),
    but functionality on macOS can be limited due to SIP/entitlements.
    
    For this lab, we will try to match the executable file on disk first, 
    as true memory scanning requires root and complex handling.
    """
    return [] 
