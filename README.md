# Phish-Net Email Analyzer

A privacy-focused phishing email detection tool that runs locally on your machine using Ollama.

## Features

- **Local Processing**: All analysis happens on your machine - no data sent to external servers
- **AI-Powered**: Uses local LLM via Ollama for intelligent phishing detection
- **Simple Interface**: Easy-to-use web interface built with Streamlit
- **Multiple Input Methods**: Paste email text or upload .eml files
- **Risk Scoring**: Clear risk levels (Low/Medium/High) with detailed explanations

## Prerequisites

- Python 3.8 or higher
- [Ollama](https://ollama.ai/) installed and running
- A compatible LLM model (e.g., phi4-mini-reasoning)

## Installation

1. Clone or download this repository
2. Navigate to the project directory
3. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start Ollama and ensure your chosen model is available:
   ```bash
   ollama pull phi4-mini-reasoning
   ```

2. Run the application:
   ```bash
   streamlit run src/app.py
   ```

3. Open your browser to `http://localhost:8501`

4. Configure the Ollama connection settings in the sidebar

5. Paste email content or upload an .eml file and click "Analyze Email"

## Project Structure

```
phish-net/
├── src/
│   └── app.py              # Main Streamlit application
├── docs/
│   └── prd.md              # Product Requirements Document
├── examples/               # Sample emails for testing
├── tests/                  # Test files
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## License

This project is for educational purposes.