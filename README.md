# 🎣 Phish-Net Email Analyzer

A privacy-focused phishing email detection tool that runs locally on your machine using Ollama and AI. Analyze suspicious emails without sending your data to external servers.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)

## Features

- **Privacy First**: All analysis happens locally - no data sent to external servers
- **AI-Powered**: Uses local LLM via Ollama for intelligent phishing detection  
- **Simple Interface**: Clean, intuitive web interface built with Streamlit
- **Multiple Input Methods**: Paste email text or upload .eml files
- **Risk Scoring**: Clear risk levels (Low/Medium/High) with detailed explanations
- **Detailed Analysis**: Comprehensive red flag detection with explanations
- **Analysis History**: Keep track of previous analyses
- **Real-time Status**: Connection monitoring and error handling

## Prerequisites

Before installing Phish-Net, ensure you have:

- **Python 3.8 or higher** - [Download Python](https://python.org/downloads/)
- **Ollama** - [Download Ollama](https://ollama.ai/)
- **Compatible LLM model** (recommended: phi4-mini)

## Installation

### Quick Setup (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/phish-net.git
   cd phish-net
   ```

2. **Set up Python environment**
   ```bash
   # Linux/Mac
   python3 -m venv .venv
   source .venv/bin/activate

   # Windows
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up Ollama model**
   ```bash
   # Install and start Ollama (if not already done)
   ollama pull phi4-mini-reasoning
   # Alternative models: phi4-mini, llama3.1, mistral, codellama
   ```

### Platform-Specific Setup

#### Windows
```batch
# Use the provided batch script
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
├── trusted_domains.txt    # Trusted domains list
├── requirements.txt       # Python dependencies
├── run.bat               # Windows launcher
├── run.sh                # Linux/Mac launcher
└── README.md             # This file
```

## 🧪 Testing

### Quick Test
```bash
python tests/quick_test.py
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
1. Pull the required model: `ollama pull phi4-mini`
2. Check available models: `ollama list`
3. Update model name in settings

#### "Analysis timeout" 
**Solution:**
1. Increase timeout in sidebar settings
2. Try a smaller/faster model
3. Check system resources

#### Python/Dependency Issues
**Solution:**
1. Ensure Python 3.8+: `python --version`
2. Reinstall dependencies: `pip install -r requirements.txt --force-reinstall`
3. Check virtual environment is active

### Getting Help
If you encounter issues:
1. Check the error message in the sidebar
2. Review the troubleshooting guide above
3. Ensure all prerequisites are met
4. Try the quick test: `python tests/quick_test.py`

## 📖 FAQ

**Q: Is my email data sent anywhere?**
A: No, all analysis happens locally on your machine. No data is sent to external servers.

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

This is an educational project. Contributions and suggestions are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is for educational purposes.

## 🙏 Acknowledgments

- Built with [Streamlit](https://streamlit.io/) for the web interface
- Powered by [Ollama](https://ollama.ai/) for local AI processing
- Uses various open-source Python libraries

---

**⚠️ Disclaimer**: This tool is for educational purposes and should not be the sole method for determining email safety. Always exercise caution with suspicious emails and consider multiple security measures.