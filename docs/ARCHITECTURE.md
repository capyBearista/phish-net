# Phish-Net Technical Architecture

## Overview

Phish-Net is a modular, privacy-focused tool for local AI-powered phishing email detection. All analysis runs locally, with strong error handling and extensibility.

## Architecture Summary

- **Privacy First**: No external data transmission
- **Modular Services**: Dedicated layers for UI, email processing, LLM, risk assessment, and error handling
- **Error Resilience**: Centralized error management, graceful degradation
- **Extensible**: Easy to add models, analysis methods, or input formats

## Main Components

- **Application Layer (`src/app.py`)**: Streamlit UI, session state, service orchestration
- **Email Processing (`src/email_processor.py`)**: Extracts headers/body, supports text and .eml, cleans content, detects URLs
- **LLM Service (`src/llm_service.py`)**: Communicates with local Ollama (phi4-mini-reasoning), validates responses, retries on failure
- **Risk Assessment (`src/risk_assessment.py`)**: Scores risk (1-10), categorizes red flags, applies heuristics if LLM fails
- **Error Handling (`src/error_handling.py`)**: Categorizes errors, logs, provides user guidance

## Data Flow

```
User Input → Email Processor → LLM Service → Risk Assessment → UI Display
```
- Input validated and parsed
- AI analysis via Ollama
- Risk scored and categorized
- Results shown in UI, errors handled gracefully

## Import Pattern

Supports both package and standalone execution:
```python
try:
    from .module_name import ClassName
except ImportError:
    from module_name import ClassName
```

## Configuration

- Runtime: In Streamlit session state, configurable via UI
- Static: `trusted_domains.txt` (whitelist), `requirements.txt` (dependencies)

## Performance & Security

- Minimal memory use, stream processing for large emails
- Local-only, no persistent storage, sanitized error messages
- Input validation, encoding checks, URL sanitization

## Extending Phish-Net

- Add models: Update `llm_service.py` and validation logic
- New analysis: Extend `email_processor.py`, prompts, and risk rules
- New input formats: Update parser and UI

## Dependencies

- Core: Streamlit, Requests, Email
- Optional: BeautifulSoup4, Chardet

## Deployment

- Local-only, runs via `streamlit run`
- Batch scripts for Windows/Linux/Mac

## Monitoring

- Health checks for Ollama/model
- Error tracking and user guidance
- Local performance metrics

## Future Enhancements

- Plugin support, config files, advanced caching, multi-model analysis, API/batch modes
