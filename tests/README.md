# Tests Directory

This directory contains the test suite for Phish-Net email analyzer.

## Test Files

### Core Test Files
- **`test_comprehensive.py`** - Complete test suite that validates detection accuracy, performance metrics, and edge cases
- **`test_manual.py`** - Quick manual testing utility for testing individual emails
- **`sample_emails.py`** - Test data containing legitimate and phishing email samples

## Running Tests

### Comprehensive Testing
```bash
# Run full test suite
python tests/test_comprehensive.py

# Run with specific options
python tests/test_comprehensive.py --model phi4-mini --verbose
```

### Quick Manual Testing
```bash
# Test specific email samples
python tests/test_manual.py
```

## Test Organization

Tests are organized to provide:
- **Accuracy validation** - Ensures correct classification of phishing vs legitimate emails
- **Performance metrics** - Measures response times and resource usage  
- **Edge case handling** - Tests unusual email formats and error conditions
- **End-to-end workflows** - Validates complete user experience flows

## Prerequisites

Ensure you have:
1. Ollama running locally
2. Required LLM model installed (phi4-mini recommended)
3. Python dependencies installed (`pip install -r requirements.txt`)