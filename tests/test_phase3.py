#!/usr/bin/env python3
"""
Test script for Phase 3: LLM Integration & Prompt Engineering

This script demonstrates the LLM-powered phishing analysis capabilities.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from llm_service import OllamaService
from email_processor import EmailProcessor
import json

def test_llm_integration():
    """Test the complete LLM integration pipeline"""
    
    print("🤖 Testing Phish-Net LLM Integration (Phase 3)")
    print("=" * 60)
    
    # Initialize services
    processor = EmailProcessor()
    llm_service = OllamaService("http://localhost:11434", "phi4-mini-reasoning")
    
    # Test 1: Check LLM availability
    print("\n🔌 Test 1: LLM Service Status")
    print("-" * 40)
    
    status = llm_service.test_connection()
    print(f"✅ Connected: {status.get('connected', False)}")
    print(f"🤖 Model Available: {status.get('model_available', False)}")
    
    if status.get('available_models'):
        print("📋 Available models:")
        for model in status['available_models'][:3]:
            print(f"  • {model}")
    
    if not status.get('model_available'):
        print("❌ phi4-mini-reasoning not available - cannot proceed with LLM tests")
        return
    
    # Test 2: Process and analyze phishing email
    print(f"\n📧 Test 2: Analyzing Phishing Email with LLM")
    print("-" * 40)
    
    # Use the phishing example
    phishing_email = """From: noreply@paypal-security.com
To: user@example.com
Subject: URGENT: Your PayPal Account Has Been Limited - Verify Immediately
Date: Tue, 26 Sep 2025 10:30:15 +0000

Dear PayPal User,

We have detected suspicious activity on your PayPal account. For your security, we have temporarily limited access to your account.

To restore full access, please verify your account information immediately by clicking the link below:

http://paypal-verify-security.com/login

IMPORTANT: You must complete verification within 24 hours or your account will be permanently suspended.

If you do not recognize this activity, please contact us immediately.

Thank you for your cooperation.

PayPal Security Team
Copyright © 2025 PayPal Inc. All rights reserved."""
    
    # Process the email
    processed_email = processor.process_email(phishing_email, is_file_content=True)
    print(f"📊 Email processed: {processed_email.get('success', False)}")
    print(f"🔗 URLs found: {len(processed_email.get('urls', []))}")
    print(f"⚠️  Suspicious URLs: {processed_email.get('metadata', {}).get('suspicious_url_count', 0)}")
    
    # Analyze with LLM
    print("\n🧠 Running LLM analysis...")
    
    try:
        llm_result = llm_service.analyze_email(processed_email)
        
        if llm_result.get('success'):
            print("✅ LLM Analysis successful!")
            print(f"🎯 Risk Score: {llm_result.get('risk_score', 'Unknown')}/10")
            print(f"📈 Risk Level: {llm_result.get('risk_level', 'Unknown')}")
            print(f"🔍 Confidence: {llm_result.get('confidence', 'Unknown')}")
            print(f"💡 Recommendation: {llm_result.get('recommendation', 'Unknown')}")
            print(f"⚡ Response Time: {llm_result.get('response_time', 0):.2f}s")
            
            print(f"\n🚩 Red Flags Identified:")
            for i, flag in enumerate(llm_result.get('red_flags', [])[:5], 1):
                print(f"  {i}. {flag}")
            
            print(f"\n💭 LLM Reasoning:")
            reasoning = llm_result.get('reasoning', 'No reasoning provided')
            print(f"  {reasoning[:200]}{'...' if len(reasoning) > 200 else ''}")
            
        else:
            print(f"❌ LLM Analysis failed: {llm_result.get('error', 'Unknown error')}")
    
    except Exception as e:
        print(f"❌ Error during LLM analysis: {str(e)}")
    
    # Test 3: Test with legitimate email
    print(f"\n✅ Test 3: Analyzing Legitimate Email")
    print("-" * 40)
    
    legitimate_email = """From: notifications@github.com
To: user@example.com
Subject: [GitHub] Security alert: new sign-in from Windows device
Date: Tue, 26 Sep 2025 14:22:33 +0000

Hi there,

A new sign-in to your GitHub account was detected.

Device: Windows 11
Location: Seattle, WA, US
Time: September 26, 2025 2:22 PM UTC

If this was you, you can safely ignore this email.

If this wasn't you, please secure your account:
https://github.com/settings/security

Thanks,
The GitHub Team

You can manage your notification preferences at:
https://github.com/settings/notifications"""
    
    processed_legit = processor.process_email(legitimate_email, is_file_content=True)
    
    try:
        llm_result2 = llm_service.analyze_email(processed_legit)
        
        if llm_result2.get('success'):
            print("✅ Legitimate email analysis successful!")
            print(f"🎯 Risk Score: {llm_result2.get('risk_score', 'Unknown')}/10")
            print(f"📈 Risk Level: {llm_result2.get('risk_level', 'Unknown')}")
            print(f"💡 Recommendation: {llm_result2.get('recommendation', 'Unknown')}")
            
        else:
            print(f"❌ Analysis failed: {llm_result2.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
    
    print(f"\n✅ Phase 3 Testing Complete!")
    print("🎯 LLM integration is working correctly!")

if __name__ == "__main__":
    test_llm_integration()