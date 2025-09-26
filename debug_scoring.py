#!/usr/bin/env python3
"""Debug script to analyze chunked pipeline scoring"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.llm_service import OllamaService  
from src.email_processor import EmailProcessor
from tests.sample_emails import LEGITIMATE_EMAILS

def debug_chunked_scoring():
    """Debug why chunked analysis gives higher scores"""
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    print("🔍 DEBUGGING CHUNKED ANALYSIS SCORING")
    print("=" * 50)
    print(f"Email: Corporate newsletter from {processed['metadata'].get('sender_domain')}")
    
    # Run phases individually to see scoring
    print("\n1️⃣  PHASE 1: STRUCTURAL ANALYSIS")
    structural = ollama_service._analyze_structure(processed)
    print(f"   Structural Risk: {structural.get('structural_risk', 'N/A')}/4")
    print(f"   Domain Assessment: {structural.get('domain_assessment', 'N/A')}")
    print(f"   Format Quality: {structural.get('format_quality', 'N/A')}")
    if structural.get('header_issues'):
        print(f"   Header Issues: {structural['header_issues']}")
    
    print("\n2️⃣  PHASE 2: CONTENT ANALYSIS")  
    content = ollama_service._analyze_content(processed, structural)
    print(f"   Content Risk: {content.get('content_risk', 'N/A')}/6")
    print(f"   Request Type: {content.get('request_type', 'N/A')}")
    print(f"   URL Risk: {content.get('url_risk', 'N/A')}/4")
    if content.get('language_flags'):
        print(f"   Language Flags: {content['language_flags']}")
    
    print("\n3️⃣  PHASE 3: INTENT ASSESSMENT")
    intent = ollama_service._assess_intent(processed, structural, content)
    print(f"   Final Risk Score: {intent.get('risk_score', 'N/A')}/10")
    print(f"   Domain Trust Applied: {intent.get('domain_trust_applied', 'N/A')}")
    print(f"   Recommendation: {intent.get('recommendation', 'N/A')}")
    print(f"   Reasoning: {intent.get('reasoning', 'N/A')}")
    
    # Check trust weight calculation
    print("\n🔧 TRUST WEIGHT CALCULATION")
    sender_domain = processed['metadata'].get('sender_domain', '')
    trust_weight, trust_reason = ollama_service.risk_assessor.calculate_domain_trust_weight(sender_domain)
    print(f"   Domain: {sender_domain}")
    print(f"   Trust Weight: {trust_weight}")
    print(f"   Trust Reason: {trust_reason}")
    
    # Manual calculation check
    print("\n🧮 MANUAL CALCULATION CHECK")
    struct_risk = structural.get('structural_risk', 0)
    content_risk = content.get('content_risk', 0)
    base_score = struct_risk + content_risk
    adjusted_score = base_score + trust_weight
    
    print(f"   Structural Risk: {struct_risk}")
    print(f"   Content Risk: {content_risk}")
    print(f"   Base Score: {base_score}")
    print(f"   Trust Weight: {trust_weight}")
    print(f"   Expected Score: {max(1, min(10, adjusted_score))}")
    print(f"   Actual LLM Score: {intent.get('risk_score', 'N/A')}")
    
    # Compare with legacy
    print("\n🆚 LEGACY COMPARISON")
    legacy_result = ollama_service.analyze_email_legacy(processed)
    print(f"   Legacy Score: {legacy_result.get('risk_score', 'N/A')}/10")
    print(f"   Legacy Recommendation: {legacy_result.get('recommendation', 'N/A')}")

if __name__ == "__main__":
    debug_chunked_scoring()