#!/bin/bash
# Run script for Phish-Net application

cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Please run: python3 -m venv .venv"
    exit 1
fi

# Activate virtual environment and run the app
echo "Activating Python virtual environment"
source .venv/bin/activate

echo "Starting Phish-Net Email Analyzer..."
echo "Open your browser to http://localhost:8501 once the server starts"
echo ""


streamlit run src/app.py