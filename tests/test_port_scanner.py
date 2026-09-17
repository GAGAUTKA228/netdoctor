"""
Тесты сканера портов.

Сетевые тесты используют только localhost и заведомо занятые/свободные
сокеты, чтобы не зависеть от реальной внешней сети (CI-раннеры часто
ограничивают исходящий трафик).
"""

import socket
import threading

import pytest

from netdoctor.port_scanner import (
    parse_ports,
    check_port,
    check_network_interception,
    run_port_scan,
)


# ---------------------------------------------------------------------------
# parse_ports
# ---------------------------------------------------------------------------

def test_parse_ports_comma_separated():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_ports_mixed_range_and_list():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]


def test_parse_ports_deduplicates_and_sorts():
    assert parse_ports("443,80,80,443") == [80, 443]


def test_parse_ports_ignores_empty_chunks():
    assert parse_ports("22,,80") == [22, 80]


# ---------------------------------------------------------------------------
# check_port - используем реальный локальный сокет, чтобы проверить
# и открытый, и закрытый случай без обращения к внешней сети.
# ---------------------------------------------------------------------------

@pytest.fixture
def open_local_port():
    """Поднимает временный TCP-сервер на localhost и отдаёт его порт."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))  # 0 - ОС сама выберет свободный порт
    server.listen(1)
    port = server.getsockname()[1]

    def accept_loop():
        try:
            server.accept()
        except OSError:
            pass

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()

    yield port
    server.close()


def test_check_port_open(open_local_port):
    port, is_open = check_port("127.0.0.1", open_local_port, timeout=1.0)
    assert port == open_local_port
    assert is_open is True


def test_check_port_closed():
    # Поднимаем и сразу закрываем сокет, чтобы гарантированно получить
    # свободный (закрытый) порт без гонки с другими процессами.
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    free_port = tmp.getsockname()[1]
    tmp.close()

    port, is_open = check_port("127.0.0.1", free_port, timeout=0.5)
    assert port == free_port
    assert is_open is False


# ---------------------------------------------------------------------------
# check_network_interception - тестируем через monkeypatch, без реальной сети
# ---------------------------------------------------------------------------

def test_canary_detects_interception(monkeypatch):
    monkeypatch.setattr(
        "netdoctor.port_scanner.check_port",
        lambda ip, port, timeout: (port, True),
    )
    canary_port, is_open = check_network_interception("10.0.0.1", [22, 80], 0.1)
    assert is_open is True
    assert canary_port not in [22, 80]
    assert 49152 <= canary_port < 65000


def test_canary_reports_clean_network(monkeypatch):
    monkeypatch.setattr(
        "netdoctor.port_scanner.check_port",
        lambda ip, port, timeout: (port, False),
    )
    _, is_open = check_network_interception("10.0.0.1", [22, 80], 0.1)
    assert is_open is False


# ---------------------------------------------------------------------------
# run_port_scan - без IP сразу возвращает пустой список, без обращения к сети
# ---------------------------------------------------------------------------

def test_run_port_scan_without_ip_returns_empty():
    assert run_port_scan(None, [22, 80]) == []
