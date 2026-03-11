
import os
import requests
import hashlib
import logging

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
MALWAREBAZAAR_AUTH_KEY = os.environ.get("MALWAREBAZAAR_AUTH_KEY")
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
logger = logging.getLogger(__name__)

def check_ip(ip: str) -> dict | None:
    """
    Check an IP address against the AbuseIPDB API.
    """
    if not ABUSEIPDB_API_KEY:
        logger.warning("ABUSEIPDB_API_KEY not set. Skipping threat intelligence check.")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json().get("data")
    except requests.exceptions.RequestException as e:
        logger.error("Error checking IP %s: %s", ip, e)
        return None

def calculate_file_hash(filepath: str) -> str | None:
    """
    Calculate the SHA-256 hash of a file.
    """
    if not filepath:
        return None
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        # Permission denied or file not found are common for system processes
        return None

def check_file_vt(file_hash: str, api_key: str) -> dict | None:
    """
    Check a file hash against the VirusTotal API.
    """
    if not api_key:
        return {"error": "No API key provided"}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {})
        elif response.status_code == 404:
             return {"status": "not_found", "message": "Hash not found in VirusTotal"}
        elif response.status_code == 429:
             return {"error": "Rate limit exceeded"}
        else:
             return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_file_malwarebazaar(file_hash: str) -> dict | None:
    """
    Query MalwareBazaar for hash intelligence.
    """
    headers = {}
    if MALWAREBAZAAR_AUTH_KEY:
        headers["Auth-Key"] = MALWAREBAZAAR_AUTH_KEY

    payload = {
        "query": "get_info",
        "hash": file_hash,
    }

    try:
        response = requests.post(
            MALWAREBAZAAR_API_URL,
            data=payload,
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()
        result = response.json()
        if result.get("query_status") == "ok":
            data = result.get("data", [])
            if data:
                first_hit = data[0]
                return {
                    "query_status": result.get("query_status"),
                    "sha256_hash": first_hit.get("sha256_hash"),
                    "file_name": first_hit.get("file_name"),
                    "file_type": first_hit.get("file_type"),
                    "signature": first_hit.get("signature"),
                    "tags": first_hit.get("tags", []),
                    "first_seen": first_hit.get("first_seen"),
                    "reporter": first_hit.get("reporter"),
                }
            return {"query_status": "ok", "data": []}
        return {
            "query_status": result.get("query_status", "unknown"),
            "message": result.get("message"),
        }
    except Exception as exc:
        logger.error("Error querying MalwareBazaar for %s: %s", file_hash, exc)
        return {"error": str(exc)}

def scan_process(proc_info: dict, api_key: str) -> dict:
    """
    Scan a single process using VirusTotal and MalwareBazaar.
    """
    exe_path = proc_info.get("exe")
    if not exe_path:
        return {"status": "skipped", "reason": "No executable path"}
    
    file_hash = calculate_file_hash(exe_path)
    if not file_hash:
        return {"status": "skipped", "reason": "Could not hash file"}
        
    vt_result = check_file_vt(file_hash, api_key)
    malwarebazaar_result = check_file_malwarebazaar(file_hash)
    return {
        "process": proc_info.get("name"),
        "pid": proc_info.get("pid"),
        "hash": file_hash,
        "virustotal": vt_result,
        "malwarebazaar": malwarebazaar_result,
    }
