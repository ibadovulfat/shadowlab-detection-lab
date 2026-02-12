
import subprocess
import os

def extract_strings(exe_path, min_length=4):
    """
    Runs the 'strings' command on the binary to find printable ASCII.
    This mimics 'Memory String' search but safely on disk.
    """
    if not os.path.exists(exe_path):
        return ["Error: Executable not found on disk."]
    
    try:
        # Run strings command
        # -n min_length
        result = subprocess.run(
            ["strings", "-n", str(min_length), exe_path],
            capture_output=True,
            text=True,
            timeout=5 # limit time
        )
        
        if result.returncode != 0:
            return [f"Error running strings: {result.stderr}"]
            
        return result.stdout.splitlines()
    except Exception as e:
        return [f"Analysis Error: {e}"]

def search_patterns(strings_list, patterns):
    """
    Filters the strings list for specific keywords.
    """
    hits = []
    for s in strings_list:
        if any(p.lower() in s.lower() for p in patterns):
            hits.append(s)
    return hits
