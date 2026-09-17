"""Точка входа NetDoctor: разбор аргументов и запуск проверок по порядку."""

from __future__ import annotations

import argparse
import sys

from .output import Style, COLOR_OK, info, fail
from .network_info import run_local_network_info, run_arp_table
from .dns_check import run_dns
from .ping_check import run_ping
from .traceroute_check import run_traceroute
from .port_scanner import COMMON_PORTS, parse_ports, run_port_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NetDoctor - быстрая диагностика сети (DNS/ping/traceroute/порты/ARP)"
    )
    parser.add_argument(
        "target", nargs="?", default=None, help="Хост или IP-адрес для проверки"
    )
    parser.add_argument(
        "-p", "--ports",
        default=",".join(str(p) for p in COMMON_PORTS),
        help="Список портов через запятую или диапазон, напр. '22,80,443' или '1-1024'. "
             "По умолчанию - набор часто используемых портов."
    )
    parser.add_argument("--count", type=int, default=4, help="Количество ping-пакетов")
    parser.add_argument("--no-dns", action="store_true", help="Пропустить DNS-проверку")
    parser.add_argument("--no-ping", action="store_true", help="Пропустить ping")
    parser.add_argument("--no-trace", action="store_true", help="Пропустить traceroute")
    parser.add_argument("--no-ports", action="store_true", help="Пропустить сканирование портов")
    parser.add_argument(
        "--no-info", action="store_true",
        help="Пропустить информацию о локальной сети и ARP-таблицу"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.7,
        help="Тайм-аут на порт при сканировании, сек (по умолчанию 0.7)"
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Если запустили без аргумента (например, двойным кликом по .exe) -
    # спрашиваем адрес интерактивно, чтобы окно не закрывалось мгновенно.
    interactive_mode = args.target is None
    if interactive_mode:
        print(f"{Style.BRIGHT}NetDoctor{Style.RESET_ALL} - быстрая диагностика сети")
        info("Аргумент не указан - введите адрес для проверки вручную.\n")
        try:
            args.target = input("Хост или IP для проверки: ").strip()
        except (EOFError, KeyboardInterrupt):
            args.target = ""

        if not args.target:
            fail("Адрес не введён, завершение работы.")
            _pause_if_interactive(interactive_mode)
            return

    print(f"{Style.BRIGHT}NetDoctor{Style.RESET_ALL} -> цель: {args.target}")
    if not COLOR_OK:
        info("(подсказка: установи 'colorama' для цветного вывода: pip install colorama)")

    resolved_ip = args.target

    if not args.no_info:
        run_local_network_info()

    if not args.no_dns:
        resolved_ip = run_dns(args.target) or args.target

    if not args.no_info:
        run_arp_table(highlight_ip=resolved_ip)

    if not args.no_ping:
        run_ping(args.target, count=args.count)

    if not args.no_trace:
        run_traceroute(args.target)

    if not args.no_ports:
        ports = parse_ports(args.ports)
        run_port_scan(resolved_ip, ports, timeout=args.timeout)

    print(f"\n{Style.BRIGHT}Готово.{Style.RESET_ALL}")
    _pause_if_interactive(interactive_mode)


def _pause_if_interactive(interactive_mode: bool) -> None:
    if interactive_mode:
        try:
            input("\nНажмите Enter, чтобы закрыть окно...")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
        sys.exit(1)
