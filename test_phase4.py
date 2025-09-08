#!/usr/bin/env python3
"""Test the new Risk Assessment Framework"""

import sys
sys.path.append('.')

from src.email_processor import EmailProcessor
from src.llm_service import OllamaService
import json

def test_risk_assessment():
    print("=== TESTING PHASE 4: RISK ASSESSMENT FRAMEWORK ===")
    
    # Initialize services
    processor = EmailProcessor()
    llm_service = OllamaService()
    
    # Test with the legitimate GitHub email
    with open('examples/legitimate_example_1.eml', 'r') as f:
        email_content = f.read()
    
    print("Processing legitimate GitHub email...")
    result = processor.process_email(email_content)
    
    print(f"\n=== EMAIL METADATA ===")
    metadata = result.get('metadata', {})
    print(f"Sender trusted: {metadata.get('sender_trusted')}")
    print(f"Sender domain: {metadata.get('sender_domain')}")
    print(f"Suspicious URLs: {metadata.get('suspicious_url_count')}")
    
    if llm_service.test_connection()['connected']:
        print("\n=== LLM ANALYSIS WITH RISK ASSESSMENT ===")
        analysis = llm_service.analyze_email(result)
        
        # Display enhanced risk assessment
        print(f"Risk Score: {analysis.get('risk_score')}")
        print(f"Risk Level: {analysis.get('risk_level')}")
        print(f"Risk Color: {analysis.get('risk_color')}")
        print(f"Confidence Score: {analysis.get('confidence_score')}")
        print(f"Confidence Level: {analysis.get('confidence_level')}")
        
        # Red flag analysis
        red_flags = analysis.get('red_flags', {})
        print(f"\n=== RED FLAG ANALYSIS ===")
        print(f"Total flags: {red_flags.get('total_count', 0)}")
        
        categorized = red_flags.get('categorized', {})
        for severity in ['critical', 'major', 'minor', 'unknown']:
            flags = categorized.get(severity, [])
            if flags:
                print(f"{severity.capitalize()} flags ({len(flags)}):")
                for flag in flags:
                    print(f"  - {flag.get('text')} ({flag.get('description')})")
        
        # Validation info
        validation = analysis.get('validation', {})
        print(f"\n=== VALIDATION ===")
        print(f"Score adjusted: {validation.get('score_adjusted')}")
        if validation.get('score_adjusted'):
            print(f"Original score: {validation.get('original_score')}")
            print(f"Adjustment reason: {validation.get('adjustment_reason')}")
        
        heuristic = validation.get('heuristic_validation', {})
        print(f"Heuristic score: {heuristic.get('heuristic_score')}")
        print(f"Agreement level: {heuristic.get('agreement_level')}")
        
        # Recommendation
        recommendation = analysis.get('recommendation', {})
        print(f"\n=== RECOMMENDATION ===")
        print(f"Action: {recommendation.get('action')}")
        print(f"Message: {recommendation.get('message')}")
        
        # Success check
        risk_score = analysis.get('risk_score', 10)
        if risk_score <= 3:
            print(f"\n✅ SUCCESS: Risk assessment correctly identifies legitimate email as LOW RISK")
        else:
            print(f"\n❌ ISSUE: Risk assessment still shows HIGH RISK for legitimate email")
            
    else:
        print("Ollama not available for testing")

if __name__ == "__main__":
    test_risk_assessment()