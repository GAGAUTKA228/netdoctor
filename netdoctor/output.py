"""
Цветной консольный вывод и декодирование вывода системных команд.

Вынесено в отдельный модуль, чтобы все проверки (dns_check, ping_check,
port_scanner...) использовали одинаковый стиль вывода без дублирования кода.
"""

from __future__ import annotations

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_OK = True
except ImportError:
    # Работаем без цвета, если colorama не установлена, а не падаем.
    COLOR_OK = False

    class _NoColor:
        def __getattr__(self, name: str) -> str:
            return ""

    Fore = _NoColor()
    Style = _NoColor()


def header(text: str) -> None:
    line = "=" * len(text)
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")


def ok(text: str) -> None:
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL}   {text}")


def warn(text: str) -> None:
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {text}")


def fail(text: str) -> None:
    print(f"{Fore.RED}[FAIL]{Style.RESET_ALL} {text}")


def info(text: str) -> None:
    print(f"{Fore.WHITE}{text}{Style.RESET_ALL}")


def decode_console_output(raw: bytes | str) -> str:
    """
    Декодирует вывод системных консольных команд (ping/tracert/ipconfig/arp).

    На русской Windows консоль по умолчанию использует кодировку CP866,
    а не UTF-8, из-за чего кириллица в выводе превращается в "кракозябры".
    Пробуем несколько вариантов кодировок по очереди.
    """
    if isinstance(raw, str):
        return raw

    for encoding in ("utf-8", "cp866", "cp1251"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    # Если совсем ничего не подошло - декодируем с заменой нечитаемых символов,
    # чтобы скрипт не упал на экзотической кодировке.
    return raw.decode("utf-8", errors="replace")
