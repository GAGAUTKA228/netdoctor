"""Многопоточное TCP-сканирование портов с детектором перехвата сети."""

from __future__ import annotations

import concurrent.futures
import random
import socket
import time
from typing import Dict, List, Optional, Tuple

from .output import header, ok, warn, fail, info

COMMON_PORTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def parse_ports(ports_arg: str) -> List[int]:
    """Разбирает строку портов вида '22,80,443' и/или '1-1000' в отсортированный список."""
    ports = set()
    for chunk in ports_arg.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)


def check_port(ip_address: str, port: int, timeout: float) -> Tuple[int, bool]:
    """Пробует TCP-подключение к порту. Возвращает (порт, открыт_ли)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip_address, port))
        return port, result == 0
    finally:
        sock.close()


def check_network_interception(
    ip_address: str, requested_ports: List[int], timeout: float
) -> Tuple[int, bool]:
    """
    "Канарейка": проверяет случайный высокий порт, которого точно нет
    в списке запрошенных и который почти наверняка закрыт на целевом хосте.

    Если он тоже оказывается "открыт" - значит что-то в сети (корпоративный
    firewall/прокси с SSL-инспекцией, VPN-перехват, капитал-портал) отвечает
    на любое TCP-соединение независимо от порта, и результатам сканирования
    доверять нельзя.
    """
    candidates = [p for p in range(49152, 65000) if p not in requested_ports]
    canary_port = random.choice(candidates)
    _, is_open = check_port(ip_address, canary_port, timeout)
    return canary_port, is_open


def run_port_scan(
    ip_address: Optional[str],
    ports: List[int],
    timeout: float = 0.7,
    workers: int = 100,
) -> List[int]:
    """Сканирует список портов, возвращает список открытых."""
    header(f"ПОРТЫ: {ip_address} ({len(ports)} шт.)")

    if not ip_address:
        fail("Нет IP-адреса для сканирования (см. ошибку DNS выше)")
        return []

    canary_port, canary_open = check_network_interception(ip_address, ports, timeout)
    if canary_open:
        warn(
            f"ВНИМАНИЕ: заведомо случайный порт {canary_port} тоже 'открыт'. "
            "Похоже, сеть перехватывает все TCP-соединения (корпоративный "
            "firewall/прокси, VPN или капитал-портал). Результатам сканирования "
            "портов ниже доверять НЕЛЬЗЯ - реальный список открытых портов "
            "может выглядеть иначе."
        )

    open_ports: List[int] = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(check_port, ip_address, port, timeout) for port in ports
        ]
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    elapsed = time.time() - start_time

    if open_ports:
        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "?")
            ok(f"Порт {port} открыт ({service})")
    else:
        warn("Открытых портов не найдено (или всё режется firewall'ом)")

    info(f"Проверено {len(ports)} портов за {elapsed:.1f} сек.")
    return open_ports
