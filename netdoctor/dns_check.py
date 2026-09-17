"""Проверка DNS: прямой и обратный резолвинг."""

from __future__ import annotations

import socket
from typing import Optional

from .output import header, ok, warn, fail, info


def run_dns(target: str) -> Optional[str]:
    """Резолвит имя в IP (если нужно) и пытается получить обратную PTR-запись.

    Возвращает IP-адрес цели (или None, если резолвинг не удался).
    """
    header(f"DNS: {target}")

    try:
        socket.inet_aton(target)
        is_ip = True
    except OSError:
        is_ip = False

    if not is_ip:
        try:
            ip_address = socket.gethostbyname(target)
            ok(f"{target} -> {ip_address}")
        except socket.gaierror as e:
            fail(f"Не удалось разрешить имя {target}: {e}")
            return None
    else:
        ip_address = target
        info(f"{target} - это уже IP-адрес, прямой резолвинг пропущен")

    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        ok(f"Обратный DNS (PTR): {ip_address} -> {host}")
    except socket.herror:
        warn(f"PTR-запись для {ip_address} не найдена (это не всегда ошибка)")

    return ip_address
