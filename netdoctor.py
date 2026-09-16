#!/usr/bin/env python3
"""
NetDoctor - быстрая диагностика сети для выездного/системного инженера.

Проверяет по одной цели (хост или IP):
    - DNS резолвинг (прямой и обратный)
    - Доступность через ping (packet loss, время отклика)
    - Маршрут (traceroute / tracert)
    - Открытые TCP-порты из заданного списка

Работает и на Windows, и на Linux/macOS без дополнительных прав администратора
(кроме traceroute на некоторых системах, где может понадобиться sudo).

Автор: <твоё имя>
Лицензия: MIT
"""

import argparse
import concurrent.futures
import platform
import random
import socket
import subprocess
import sys
import time

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_OK = True
except ImportError:
    # Если colorama не установлена - работаем без цвета, но не падаем.
    COLOR_OK = False

    class _NoColor:
        def __getattr__(self, name):
            return ""

    Fore = _NoColor()
    Style = _NoColor()


# ---------------------------------------------------------------------------
# Вспомогательные функции вывода
# ---------------------------------------------------------------------------

def header(text):
    line = "=" * len(text)
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")


def ok(text):
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL}   {text}")


def warn(text):
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {text}")


def fail(text):
    print(f"{Fore.RED}[FAIL]{Style.RESET_ALL} {text}")


def info(text):
    print(f"{Fore.WHITE}{text}{Style.RESET_ALL}")


def decode_console_output(raw_bytes):
    """
    Декодирует байты, полученные от системных консольных команд (ping/tracert).

    На русской Windows консоль (ping, tracert) по умолчанию использует
    кодировку CP866, а не UTF-8, из-за чего кириллица в выводе превращается
    в "кракозябры". Пробуем несколько вариантов по очереди.
    """
    if isinstance(raw_bytes, str):
        return raw_bytes

    for encoding in ("cp866", "cp1251", "utf-8"):
        try:
            return raw_bytes.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    # Если совсем ничего не подошло - декодируем с заменой нечитаемых символов
    return raw_bytes.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def run_dns(target):
    header(f"DNS: {target}")
    ip_address = None

    # Пробуем определить: это уже IP или доменное имя?
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

    # Обратный резолвинг (PTR)
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        ok(f"Обратный DNS (PTR): {ip_address} -> {host}")
    except socket.herror:
        warn(f"PTR-запись для {ip_address} не найдена (это не всегда ошибка)")

    return ip_address


# ---------------------------------------------------------------------------
# PING
# ---------------------------------------------------------------------------

def run_ping(target, count=4, timeout=2):
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
        else:
            fail(f"{target} не отвечает на ping (код возврата {result.returncode})")

    except subprocess.TimeoutExpired:
        fail(f"Ping до {target} превысил тайм-аут")
    except FileNotFoundError:
        fail("Команда ping не найдена в системе")


# ---------------------------------------------------------------------------
# TRACEROUTE
# ---------------------------------------------------------------------------

def run_traceroute(target, max_hops=30):
    header(f"TRACEROUTE: {target}")
    system = platform.system().lower()

    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", "1000", target]
    else:
        # traceroute есть не везде "из коробки" -> пробуем tracepath как запасной вариант
        cmd = ["traceroute", "-m", str(max_hops), "-w", "1", target]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=False, timeout=60
        )
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


# ---------------------------------------------------------------------------
# СКАНИРОВАНИЕ ПОРТОВ
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def parse_ports(ports_arg):
    """Поддерживает форматы: '22,80,443' и '1-1000' и их комбинации."""
    ports = set()
    for chunk in ports_arg.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(ports)


def check_port(ip_address, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip_address, port))
        return port, result == 0
    finally:
        sock.close()


def check_network_interception(ip_address, requested_ports, timeout):
    """
    "Канарейка": проверяет случайный высокий порт, которого точно нет
    в списке запрошенных и который почти наверняка закрыт на целевом хосте.

    Если ОН ТОЖЕ оказывается "открыт" - значит что-то в сети (корпоративный
    firewall/прокси с SSL-инспекцией, VPN-перехват, капчал-портал) отвечает
    на любое TCP-соединение независимо от порта, и результатам сканирования
    доверять нельзя.
    """
    candidates = [p for p in range(49152, 65000) if p not in requested_ports]
    canary_port = random.choice(candidates)
    _, is_open = check_port(ip_address, canary_port, timeout)
    return canary_port, is_open


def run_port_scan(ip_address, ports, timeout=0.7, workers=100):
    header(f"ПОРТЫ: {ip_address} ({len(ports)} шт.)")

    if not ip_address:
        fail("Нет IP-адреса для сканирования (см. ошибку DNS выше)")
        return

    canary_port, canary_open = check_network_interception(ip_address, ports, timeout)
    if canary_open:
        warn(
            f"ВНИМАНИЕ: заведомо случайный порт {canary_port} тоже 'открыт'. "
            "Похоже, сеть перехватывает все TCP-соединения (корпоративный "
            "firewall/прокси, VPN или капитал-портал). Результатам сканирования "
            "портов ниже доверять НЕЛЬЗЯ - реальный список открытых портов "
            "может выглядеть иначе."
        )

    open_ports = []
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


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetDoctor - быстрая диагностика сети (DNS/ping/traceroute/порты)"
    )
    parser.add_argument("target", help="Хост или IP-адрес для проверки")
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
        "--timeout", type=float, default=0.7,
        help="Тайм-аут на порт при сканировании, сек (по умолчанию 0.7)"
    )

    args = parser.parse_args()

    print(f"{Style.BRIGHT}NetDoctor{Style.RESET_ALL} -> цель: {args.target}")
    if not COLOR_OK:
        info("(подсказка: установи 'colorama' для цветного вывода: pip install colorama)")

    resolved_ip = args.target

    if not args.no_dns:
        resolved_ip = run_dns(args.target) or args.target

    if not args.no_ping:
        run_ping(args.target, count=args.count)

    if not args.no_trace:
        run_traceroute(args.target)

    if not args.no_ports:
        ports = parse_ports(args.ports)
        run_port_scan(resolved_ip, ports, timeout=args.timeout)

    print(f"\n{Style.BRIGHT}Готово.{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
        sys.exit(1)
