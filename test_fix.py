#!/usr/bin/env python3
"""Test the fixed phishing analysis"""

from src.email_processor import EmailProcessor
from src.llm_service import OllamaService
import json

def main():
    print("=== TESTING IMPROVED PHISHING ANALYSIS ===")
    
    # Initialize processors
    processor = EmailProcessor()
    llm_service = OllamaService()
    
    # Process the legitimate GitHub email
    with open('examples/legitimate_example_1.eml', 'r') as f:
        email_content = f.read()
    
    result = processor.process_email(email_content)
    
    # Show the new metadata
    print("\n=== NEW METADATA FIELDS ===")
    metadata = result.get('metadata', {})
    print(f"Sender trusted: {metadata.get('sender_trusted')}")
    print(f"Sender domain: {metadata.get('sender_domain')}")
    print(f"Suspicious URL count: {metadata.get('suspicious_url_count')}")
    
    # Test LLM analysis with improvements
    if llm_service.test_connection()['connected']:
        print("\n=== IMPROVED LLM ANALYSIS ===")
        analysis = llm_service.analyze_email(result)
        
        print(f"Risk Score: {analysis.get('risk_score')} (should be 1-3 for legitimate)")
        print(f"Risk Level: {analysis.get('risk_level')}")
        print(f"Confidence: {analysis.get('confidence')}")
        print(f"Red Flags: {analysis.get('red_flags')}")
        print(f"Reasoning: {analysis.get('reasoning')}")
        print(f"Recommendation: {analysis.get('recommendation')}")
        print(f"Model: {analysis.get('model_used')}")
        
        # Validation
        risk_score = analysis.get('risk_score', 10)
        if risk_score <= 3:
            print(f"\n✅ SUCCESS: Risk score {risk_score} is appropriately LOW for legitimate email")
        else:
            print(f"\n❌ ISSUE: Risk score {risk_score} is still too HIGH for legitimate email")
            
    else:
        print("\nOllama not available for LLM test")

if __name__ == "__main__":
    main()