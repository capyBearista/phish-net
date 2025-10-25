@echo off
REM Run script for Phish-Net application on Windows

cd /d "%~dp0"

REM Check if virtual environment exists
if not exist ".venv" (
    echo Virtual environment not found. Please run: python -m venv .venv
    exit /b 1
)

echo Activating Python virtual environment

echo Starting Phish-Net Email Analyzer...
echo Open your browser to http://localhost:8501 once the server starts
echo.

.venv\Scripts\python.exe -m streamlit run src\app.py