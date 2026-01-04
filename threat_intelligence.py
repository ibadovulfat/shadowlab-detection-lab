
import os
import requests
import streamlit as st

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

def check_ip(ip: str) -> dict | None:
    """
    Check an IP address against the AbuseIPDB API.
    """
    if not ABUSEIPDB_API_KEY:
        st.warning("ABUSEIPDB_API_KEY not set. Skipping threat intelligence check.")
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
        st.error(f"Error checking IP {ip}: {e}")
        return None
