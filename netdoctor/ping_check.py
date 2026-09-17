"""Проверка доступности хоста через ping (кроссплатформенно)."""

from __future__ import annotations

import platform
import subprocess

from .output import header, ok, fail, decode_console_output


def run_ping(target: str, count: int = 4, timeout: int = 2) -> bool:
    """Запускает системный ping. Возвращает True, если хост отвечает."""
    header(f"PING: {target}")
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), target]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=False, timeout=count * timeout + 5
        )
        output = decode_console_output(result.stdout)
        print(output.strip())

        if result.returncode == 0:
            ok(f"{target} отвечает на ping")
            return True

        fail(f"{target} не отвечает на ping (код возврата {result.returncode})")
        return False

    except subprocess.TimeoutExpired:
        fail(f"Ping до {target} превысил тайм-аут")
        return False
    except FileNotFoundError:
        fail("Команда ping не найдена в системе")
        return False
