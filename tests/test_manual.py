#!/usr/bin/env python3
"""
Manual Testing Suite - Quick testing of sample emails
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sample_emails import LEGITIMATE_EMAILS, PHISHING_EMAILS
from email_processor import EmailProcessor
from llm_service import OllamaService

def test_single_email(email_key, email_data, llm_service, email_processor):
    """Test a single email and return results"""
    print(f"\n📧 Testing: {email_data['description']}")
    print(f"Expected risk: {email_data['expected_risk']}")
    print("-" * 50)
    
    try:
        # Process email
        processed_data = email_processor.process_email(email_data["content"], is_file_content=False)
        print(f"✅ Email processed successfully")
        print(f"   Headers found: {len(processed_data.get('headers', {}))}")
        print(f"   URLs found: {len(processed_data.get('urls', []))}")
        
        # Analyze with LLM
        analysis_result = llm_service.analyze_email(processed_data)
        
        if analysis_result.get("success"):
            risk_score = analysis_result.get("risk_score", "Unknown")
            print(f"✅ LLM Analysis successful")
            print(f"   Risk Score: {risk_score}")
            
            # Show some red flags if available
            red_flags = analysis_result.get("red_flags", [])
            if red_flags:
                print(f"   Red Flags: {len(red_flags)}")
                # Ensure red_flags is a list before slicing
                if isinstance(red_flags, list):
                    for flag in red_flags[:3]:  # Show first 3
                        print(f"     • {flag}")
                else:
                    print(f"     • {red_flags}")  # Handle case where it's not a list
            
            return {
                "success": True,
                "risk_score": risk_score,
                "red_flags_count": len(red_flags)
            }
        else:
            print(f"❌ LLM Analysis failed: {analysis_result.get('error', 'Unknown error')}")
            return {"success": False, "error": analysis_result.get('error')}
            
    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        return {"success": False, "error": str(e)}

def main():
    print("🧪 Quick Manual Test Suite")
    print("=" * 50)
    
    # Initialize services
    email_processor = EmailProcessor()
    llm_service = OllamaService()
    
    # Test connection first
    print("🔧 Testing Ollama connection...")
    connection = llm_service.test_connection()
    
    if not connection.get("connected"):
        print(f"❌ Connection failed: {connection.get('error')}")
        return
    
    print("✅ Connected to Ollama")
    
    # Test a few key emails
    test_emails = [
        ("corporate_newsletter", LEGITIMATE_EMAILS["corporate_newsletter"]),
        ("banking_phish", PHISHING_EMAILS["banking_phish"]),
    ]
    
    results = []
    
    for email_key, email_data in test_emails:
        result = test_single_email(email_key, email_data, llm_service, email_processor)
        result["email_key"] = email_key
        result["expected_risk"] = email_data["expected_risk"]
        results.append(result)
    
    # Summary
    print(f"\n{'='*50}")
    print("📊 QUICK TEST SUMMARY")
    print(f"{'='*50}")
    
    for result in results:
        email_key = result["email_key"]
        if result["success"]:
            actual_risk = result["risk_score"]
            expected_risk = result["expected_risk"]
            print(f"✅ {email_key}: Risk {actual_risk} (expected ~{expected_risk})")
        else:
            print(f"❌ {email_key}: Failed - {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    main()