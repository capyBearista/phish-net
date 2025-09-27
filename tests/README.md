# Tests Directory

This directory contains the consolidated test suite for Phish-Net email analyzer.

## Test Files

### Consolidated Test Suites ✨ **(New Structure)**
- **`test_pipeline.py`** - Comprehensive pipeline testing (chunked vs legacy analysis, multi-email accuracy, statistical validation)
- **`test_domain_trust.py`** - Domain trust and weighting tests (gov/edu domains, corporate domains, .eml file processing)
- **`test_system_features.py`** - System feature tests (abort functionality, context isolation, error recovery, concurrent safety)
- **`test_manual.py`** - Quick manual testing utility for individual email testing

### Supporting Files
- **`sample_emails.py`** - Test data containing legitimate and phishing email samples

## Running Tests

## Running Tests

### Consolidated Test Suites ✨
```bash
# Run comprehensive pipeline testing (performance, accuracy, statistical validation)
python tests/test_pipeline.py

# Run domain trust and weighting tests (gov/edu domains, corporate domains)
python tests/test_domain_trust.py

# Run system feature tests (abort, context isolation, error recovery)
python tests/test_system_features.py

# Run all consolidated tests
python tests/test_pipeline.py && python tests/test_domain_trust.py && python tests/test_system_features.py
```

### Manual Testing
```bash
# Quick manual testing of individual emails
python tests/test_manual.py
```

### Test Coverage
The consolidated test suite provides comprehensive coverage:
- **Pipeline Performance**: Chunked vs legacy analysis comparison with statistical validation
- **Domain Trust**: Government, educational, and corporate domain handling with real .eml files
- **System Features**: Abort functionality, context isolation, error recovery, and concurrent safety
- **Manual Utilities**: Quick testing tools for development and debugging

## Consolidation Benefits

The new consolidated structure provides:
- **Reduced Maintenance** - 4 test files instead of 9 redundant files
- **Better Organization** - Logical grouping by functionality (pipeline, domain trust, system features)
- **Comprehensive Coverage** - All unique test cases preserved and enhanced
- **Improved Performance** - Less overhead from multiple file initialization
- **Clearer Results** - Consolidated reporting and summary statistics

### What Was Consolidated
- **Pipeline Tests**: Merged `test_comprehensive.py`, `test_multi_emails.py`, `validate_pipeline.py` → `test_pipeline.py`
- **Domain Tests**: Merged `test_gov_edu_emails.py`, `test_comprehensive_gov_edu.py`, `test_domain_weighting.py` → `test_domain_trust.py`  
- **System Tests**: Merged `test_abort_functionality.py`, `test_context_isolation.py` → `test_system_features.py`
- **Manual Testing**: Kept `test_manual.py` as-is for quick development testing

## Prerequisites

Ensure you have:
1. Ollama running locally
2. Required LLM model installed (phi4-mini recommended)
3. Python dependencies installed (`pip install -r requirements.txt`)