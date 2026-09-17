"""Тесты DNS-модуля через monkeypatch socket, без реальных DNS-запросов."""

import socket

from netdoctor.dns_check import run_dns


def test_run_dns_resolves_hostname(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda name: "93.184.216.34")
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("example.com", [], [ip])
    )
    result = run_dns("example.com")
    assert result == "93.184.216.34"


def test_run_dns_returns_none_on_failure(monkeypatch):
    def raise_gaierror(name):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "gethostbyname", raise_gaierror)
    result = run_dns("this-host-does-not-exist.invalid")
    assert result is None


def test_run_dns_skips_forward_lookup_for_ip(monkeypatch):
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("dns.google", [], [ip])
    )
    result = run_dns("8.8.8.8")
    assert result == "8.8.8.8"
