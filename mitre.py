
# In a real application, this would be more comprehensive
# and likely loaded from a file (e.g., YAML, JSON).
MITRE_ATTACK_MAPPING = {
    # Sysmon Event IDs
    1: ["T1059", "T1204"],  # Process Creation
    3: ["T1048"],          # Network Connection
    8: ["T1055"],          # CreateRemoteThread
    11: ["T1003", "T1552"], # File Create
    12: ["T1136", "T1137"], # Registry Add
    13: ["T1112"],          # Registry Set
    22: ["T1071"],          # DNS Query

    # Defender Event IDs
    1006: ["T1204.002"],    # Malicious file detected
    1116: ["T1204.002"],    # Malicious file detected
}

def get_attack_technique(event_id: int) -> list[str] | None:
    """
    Get the MITRE ATT&CK technique for a given event ID.
    """
    return MITRE_ATTACK_MAPPING.get(event_id)
