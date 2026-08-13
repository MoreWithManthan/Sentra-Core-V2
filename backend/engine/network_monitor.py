"""SENTRA CORE — Network connection monitor using psutil."""

import logging
from typing import Any, Dict, List

import psutil

logger = logging.getLogger(__name__)

_KNOWN_SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 1337, 31337, 8888, 9999,
    23, 2323,
}


def get_connections() -> List[Dict[str, Any]]:
    connections: List[Dict] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue

            proc_name, proc_pid = "Unknown", conn.pid or 0
            try:
                if conn.pid:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            remote_port = conn.raddr.port if conn.raddr else 0
            suspicious = remote_port in _KNOWN_SUSPICIOUS_PORTS

            connections.append({
                "pid":          proc_pid,
                "process":      proc_name,
                "local":        f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "remote":       f"{conn.raddr.ip}:{conn.raddr.port}",
                "remote_ip":    conn.raddr.ip,
                "remote_port":  remote_port,
                "status":       conn.status,
                "family":       "IPv6" if conn.family.name == "AF_INET6" else "IPv4",
                "suspicious":   suspicious,
            })
    except Exception as exc:
        logger.warning("Network monitor error: %s", exc)

    return sorted(connections, key=lambda c: (not c["suspicious"], c["process"].lower()))
