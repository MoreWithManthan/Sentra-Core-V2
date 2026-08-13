"""SENTRA CORE — MITRE ATT&CK mapper."""

from typing import Dict, Optional, Tuple

TECHNIQUES: Dict[str, Dict] = {
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task / Job", "tactic": "Persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1056": {"name": "Input Capture (Keylogging)", "tactic": "Collection"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1140": {"name": "Deobfuscate / Decode Files", "tactic": "Defense Evasion"},
    "T1497": {"name": "Virtualization / Sandbox Evasion", "tactic": "Defense Evasion"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1071": {"name": "Application Layer Protocol (C2)", "tactic": "Command and Control"},
    "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion"},
}

_KW: Dict[str, str] = {
    "obfuscat": "T1027", "pack": "T1027", "encrypt": "T1027",
    "compress": "T1027", "base64": "T1140", "xor": "T1027",
    "high_entropy": "T1027",
    "masquerad": "T1036", "spoof": "T1036", "fake": "T1036",
    "inject": "T1055", "shellcode": "T1055", "dll_inject": "T1055",
    "powershell": "T1059", "cmd": "T1059", "wscript": "T1059",
    "vbscript": "T1059", "javascript": "T1059", "cscript": "T1059",
    "autorun": "T1547", "startup": "T1547", "registry_run": "T1547",
    "scheduled": "T1053", "task": "T1053",
    "credential": "T1003", "mimikatz": "T1003", "lsass": "T1003",
    "password": "T1003", "dump": "T1003",
    "keylog": "T1056", "hook": "T1056",
    "ransomware": "T1486", "ransom": "T1486", "wanna": "T1486",
    "locker": "T1486",
    "wiper": "T1485", "destruct": "T1485",
    "downloader": "T1105", "dropper": "T1105", "c2": "T1071",
    "backdoor": "T1071", "rat": "T1071", "beacon": "T1071",
    "sandbox": "T1497", "vm_detect": "T1497", "anti_debug": "T1497",
    "registry": "T1112",
    "temp": "T1204",
}


def map_finding(text: str) -> Optional[Tuple[str, str, str]]:
    lower = text.lower().replace(" ", "_").replace("-", "_")
    for keyword, tid in _KW.items():
        if keyword in lower:
            tech = TECHNIQUES.get(tid, {})
            return tid, tech.get("name", tid), tech.get("tactic", "Unknown")
    return None


def enrich_result(result: Dict) -> Dict:
    if result.get("mitre_id"):
        return result

    combined = " ".join(result.get("details", []))
    combined += " " + result.get("file", "")

    mapping = map_finding(combined)
    if mapping:
        result["mitre_id"], result["mitre_name"], result["mitre_tactic"] = mapping
    return result
