@echo off
REM Собирает NetDoctor в один портативный .exe файл (без установки Python
REM на целевой машине). Запускать один раз на своей рабочей машине.

echo Installing PyInstaller (if not already installed)...
pip install pyinstaller --quiet

echo.
echo Building netdoctor.exe ...
pyinstaller --onefile --console --name netdoctor netdoctor.py

echo.
echo Done. Find the file at: dist\netdoctor.exe
echo Copy this single file to any Windows PC - no Python installation needed there.
pause
