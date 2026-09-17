"""Информация о локальных сетевых интерфейсах и ARP-таблица."""

from __future__ import annotations

import platform
import subprocess
from typing import Optional

from .output import header, ok, warn, fail, decode_console_output


def run_local_network_info() -> None:
    header("ЛОКАЛЬНАЯ СЕТЬ (эта машина)")
    system = platform.system().lower()

    cmd = ["ipconfig", "/all"] if system == "windows" else ["ip", "addr"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=False, timeout=10)
        output = decode_console_output(result.stdout)
        if not output.strip() and system != "windows":
            result = subprocess.run(["ifconfig"], capture_output=True, text=False, timeout=10)
            output = decode_console_output(result.stdout)
        print(output.strip())
        ok("Информация о сетевых интерфейсах получена")
    except FileNotFoundError:
        fail("Команда для получения сетевой информации не найдена")
    except subprocess.TimeoutExpired:
        fail("Тайм-аут при получении сетевой информации")


def run_arp_table(highlight_ip: Optional[str] = None) -> None:
    header("ARP-ТАБЛИЦА")
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=False, timeout=10)
        output = decode_console_output(result.stdout)
        print(output.strip())

        if highlight_ip:
            found = any(highlight_ip in line for line in output.splitlines())
            if found:
                ok(f"Целевой IP {highlight_ip} найден в ARP-таблице (есть L2-связность)")
            else:
                warn(
                    f"Целевой IP {highlight_ip} НЕ найден в ARP-таблице. "
                    "Если это адрес из локальной сети - хост либо выключен, "
                    "либо недоступен на канальном уровне (другой VLAN, "
                    "физическая проблема с портом/кабелем)."
                )
    except FileNotFoundError:
        fail("Команда arp не найдена в системе")
    except subprocess.TimeoutExpired:
        fail("Тайм-аут при получении ARP-таблицы")
