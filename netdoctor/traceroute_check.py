"""Трассировка маршрута до хоста (кроссплатформенно)."""

from __future__ import annotations

import platform
import subprocess

from .output import header, ok, warn, fail, decode_console_output


def run_traceroute(target: str, max_hops: int = 30) -> None:
    header(f"TRACEROUTE: {target}")
    system = platform.system().lower()

    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", "1000", target]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", "1", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=False, timeout=60)
        output = decode_console_output(result.stdout)
        if result.returncode != 0 and not output.strip():
            raise FileNotFoundError
        print(output.strip())
        ok("Трассировка завершена")

    except FileNotFoundError:
        if system != "windows":
            warn("traceroute не найден, пробую tracepath...")
            try:
                result = subprocess.run(
                    ["tracepath", target], capture_output=True, text=False, timeout=60
                )
                print(decode_console_output(result.stdout).strip())
                ok("Трассировка завершена (tracepath)")
            except FileNotFoundError:
                fail("Ни traceroute, ни tracepath не установлены в системе")
        else:
            fail("Команда tracert не найдена")
    except subprocess.TimeoutExpired:
        warn("Трассировка превысила тайм-аут (возможно, часть хопов не отвечает)")
