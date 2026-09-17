"""Тесты декодирования вывода системных консольных команд."""

from netdoctor.output import decode_console_output


def test_decode_passthrough_for_str():
    assert decode_console_output("уже строка") == "уже строка"


def test_decode_cp866_russian_windows_console():
    # Так реально выглядит вывод ping/tracert на русской Windows.
    text = "Обмен пакетами с example.com"
    raw = text.encode("cp866")
    assert decode_console_output(raw) == text


def test_decode_utf8_fallback():
    text = "test énoncé"
    raw = text.encode("utf-8")
    assert decode_console_output(raw) == text


def test_decode_never_raises_on_garbage_bytes():
    garbage = b"\xff\xfe\x00\x01broken"
    # Не должно бросать исключение - в худшем случае заменяет символы
    result = decode_console_output(garbage)
    assert isinstance(result, str)
