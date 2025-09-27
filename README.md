# 🎣 Phish-Net Email Analyzer

A privacy-focused phishing email detection tool that runs locally on your machine using Ollama and AI. Analyze suspicious emails without sending your data to external servers.

![Version](https://img.shields.io/badge/version-1.0.0-4695E4.svg?style=flat)
![License](https://img.shields.io/badge/license-BSD--3-787BDC.svg?style=flat)
![Local Only](https://img.shields.io/badge/privacy-secure-lightgreen.svg?style=flat)

![Python](https://img.shields.io/badge/python-yellow.svg?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/streamlit-red.svg?style=flat&logo=streamlit&logoColor=white)
![Ollama](https://img.shields.io/badge/ollama-242424.svg?style=flat&logo=ollama&logoColor=white)
![Shell](https://img.shields.io/badge/shell-3b8eea.svg?style=flat&logo=gnubash&logoColor=white)

## Features

- **Privacy First**: All analysis happens on your machine - no data sent to external servers
- **AI-Powered**: Uses local LLM via Ollama for intelligent phishing detection  
- **Simple Interface**: Clean, responsive web interface built with Streamlit
- **Multiple Input Methods**: Paste email content or upload the .eml file
- **Risk Scoring**: 1-10 risk scale with clear Low/Medium/High levels and detailed red flag explanations

## Prerequisites

Before installing Phish-Net, ensure you have:

- **Python 3.8 or higher** - [Python](https://python.org/downloads/)
- **Ollama** - [Ollama](https://ollama.com/)
- **An LLM model** (recommended: phi4-mini-reasoning)

## Installation

### Quick Setup (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/capyBearista/phish-net.git
   cd phish-net
   ```

2. **Set up Python environment**
   ```bash
   # Linux/Mac
   python3 -m venv .venv
   source .venv/bin/activate

   # Windows (Command Prompt)
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up Ollama model**
   ```bash
   # Install and start Ollama
   ollama pull phi4-mini-reasoning
   # Alternative models: phi4-mini, llama3.1, mistral, codellama
   ```

### Platform-Specific Setup

#### Windows
```batch
# Use the provided batch script (requires virtual environment setup first)
run.bat
```

#### Linux/Mac
```bash
# Use the provided shell script
chmod +x run.sh
./run.sh
```

## 🚀 Usage

### Starting the Application

1. **Ensure Ollama is running**
   ```bash
   # In a separate terminal
   ollama serve
   ```

2. **Launch Phish-Net**
   ```bash
   # From the project directory
   streamlit run src/app.py
   ```

3. **Open your browser** to `http://localhost:8501`

### Analyzing Emails

#### Method 1: Paste Email Content
1. Copy the full source of a suspicious email (including headers)
2. Paste into the text area
3. Click "Analyze Email"

#### Method 2: Upload .eml File
1. Click "Upload .eml file" 
2. Select your email file
3. Click "Analyze Email"

### Understanding Results

- **Risk Score**: 1-10 scale (1=Safe, 10=Very Dangerous)
- **Risk Level**: Color-coded assessment (Green/Yellow/Red)
- **Red Flags**: Specific phishing indicators found
- **Confidence**: AI model's confidence in the assessment

## 🔧 Configuration

### Ollama Settings
Configure in the sidebar:
- **Server URL**: Default `http://localhost:11434`
- **Model**: Choose from available models
- **Timeout**: Adjust for slower systems

### Advanced Configuration
- **trusted_domains.txt**: Add domains to trust list
- **Performance settings**: Adjust timeouts and retries

## 📁 Project Structure

```
phish-net/
├── src/                    # Source code
│   ├── app.py             # Main Streamlit application
│   ├── email_processor.py # Email parsing and processing
│   ├── llm_service.py     # Ollama API communication
│   ├── risk_assessment.py # Risk scoring logic
│   └── error_handling.py  # Error management
├── docs/                   # Documentation
│   ├── prd.md             # Product requirements
│   └── phases.md          # Development phases
├── examples/              # Sample emails for testing
├── tests/                 # Test files and utilities
│   ├── sample_emails.py   # Test data for automated testing
│   └── test_*.py          # Component and integration tests
├── examples/              # Sample .eml files for testing
├── trusted_domains.txt    # Trusted domains list
├── requirements.txt       # Python dependencies
├── run.bat               # Windows launcher
├── run.sh                # Linux/Mac launcher
└── README.md             # This file
```

## 🧪 Testing

### Quick Test
Test the installation and basic functionality:
```bash
# From project directory with virtual environment activated
python tests/test_comprehensive.py
```

### Sample Emails
Test with provided examples:
- `examples/legitimate_example_1.eml`
- `examples/phishing_example_1.eml`

## 🚨 Troubleshooting

### Common Issues

#### "Ollama connection failed"
**Solution:**
1. Ensure Ollama is installed and running: `ollama serve`
2. Check if the model is available: `ollama list`
3. Verify URL in sidebar settings

#### "Model not found"
**Solution:**
1. Pull the required model: `ollama pull phi4-mini-reasoning`
2. Check available models: `ollama list`
3. Update model name in settings (default: phi4-mini-reasoning)

#### "Analysis timeout" 
**Solution:**
1. Increase timeout in sidebar settings
2. Try a smaller/faster model
3. Check system resources

#### Python/Dependency Issues
**Solution:**
1. Ensure Python 3.8+: `python --version`
2. Activate virtual environment: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Linux/Mac)
3. Reinstall dependencies: `pip install -r requirements.txt --force-reinstall`

### Getting Help
If you encounter issues:
1. Check the error message in the sidebar system health panel
2. Review the troubleshooting guide above
3. Ensure all prerequisites are met (Python 3.8+, Ollama running, model available)
4. Try the quick test: `python tests/test_comprehensive.py`

## 📖 FAQ

**Q: Is my email data sent anywhere?**
A: No, all analysis happens locally on your machine. No data leaves your computer.

**Q: What email formats are supported?**
A: Both plain text emails (with headers) and .eml files are supported.

**Q: Can I use different AI models?**
A: Yes, any Ollama-compatible model can be used. Adjust the model name in settings.

**Q: How accurate is the phishing detection?**
A: Accuracy depends on the AI model used. Results should be used as guidance, not definitive security decisions.

**Q: Can I analyze attachments?**
A: Currently, only email text content is analyzed. Attachment analysis is not supported.

**Q: What about email authentication (SPF/DKIM)?**
A: The tool focuses on content analysis and doesn't perform technical email authentication checks.

## 🔒 Privacy & Security

- **Local Processing**: All analysis happens on your machine
- **No Data Transmission**: Email content never leaves your device
- **Open Source**: Transparent, auditable code
- **No Logging**: Sensitive data is not logged to files

## 🤝 Contributing

This is an educational project focused on local privacy-preserving phishing detection. Contributions and suggestions are welcome!

1. Fork the repository
2. Set up the development environment following the installation guide
3. Create a feature branch for your changes
4. Test your changes with the provided test suite
5. Submit a pull request with a clear description of improvements

---

**⚠️ Disclaimer**: This tool is for educational purposes and should not be the sole method for determining email safety. Always exercise caution—and common sense—with suspicious emails.