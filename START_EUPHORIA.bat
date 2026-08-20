@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title EUPHORIA Client Server

set "REQ=%~dp0requirements.txt"
set "APP=%~dp0main.py"

if not exist "%REQ%" (
    echo requirements.txt is missing. Creating it automatically...
    >"%REQ%" echo Flask^>=3.0,^<4.0
    >>"%REQ%" echo Werkzeug^>=3.0,^<4.0
)

if not exist "%REQ%" (
    echo.
    echo ERROR: could not create requirements.txt
    echo %REQ%
    pause
    exit /b 1
)

if not exist "%APP%" (
    echo.
    echo ERROR: main.py was not found here:
    echo %APP%
    pause
    exit /b 1
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PYTHON=py -3"
) else (
    where python >nul 2>nul
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo Python was not found. Install Python from https://www.python.org/downloads/
        echo Make sure "Add Python to PATH" is enabled.
        pause
        exit /b 1
    )
    set "PYTHON=python"
)

echo Installing required packages...
%PYTHON% -m pip install -r "%REQ%"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Package installation failed.
    echo Check your internet connection or Python/pip installation.
    pause
    exit /b 1
)

echo.
echo Starting EUPHORIA...
start "" http://127.0.0.1:5000
%PYTHON% "%APP%"

pause
