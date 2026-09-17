#!/usr/bin/env python3
"""
NetDoctor - точка входа для прямого запуска (python netdoctor.py <host>)
и для сборки в .exe через PyInstaller.

Вся логика находится в пакете netdoctor/ (см. netdoctor/cli.py и другие
модули). Этот файл - только тонкая обёртка.
"""

from netdoctor.cli import main

if __name__ == "__main__":
    main()
