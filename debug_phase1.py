#!/usr/bin/env python3
"""Debug script to check Phase 1 domain assessment"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.llm_service import OllamaService
from src.email_processor import EmailProcessor
from tests.sample_emails import LEGITIMATE_EMAILS

def debug_phase1_domain():
    """Debug Phase 1 domain assessment"""
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    print(f"Sender Domain: {processed['metadata'].get('sender_domain')}")
    print(f"Sender Trusted: {processed['metadata'].get('sender_trusted')}")
    
    # Check fallback logic
    sender_domain = processed['metadata'].get('sender_domain', '').lower()
    print(f"Domain (lowercase): '{sender_domain}'")
    
    if sender_domain.endswith(('.com', '.org', '.net')):
        print("✅ Should be classified as legitimate (.com domain)")
    else:
        print("❌ Domain doesn't match expected patterns")
    
    # Run actual Phase 1
    result = ollama_service._analyze_structure(processed)
    print(f"Actual result: {result.get('domain_assessment')}")
    print(f"Parsing method: {result.get('parsing_method', 'LLM')}")

if __name__ == "__main__":
    debug_phase1_domain()