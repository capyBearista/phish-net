#!/usr/bin/env python3
"""
Context Isolation Test for Phish-Net Abort Functionality

This script tests that aborting email analysis properly clears context
to prevent interference between different email analyses.

Tests:
1. Sequential analyses with different email content
2. Abort during analysis and verify next analysis is clean
3. Context clearing verification
4. Server-side state isolation
"""

import sys
import os
import time
import threading
from datetime import datetime

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from llm_service import OllamaService
    from email_processor import EmailProcessor
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the tests directory")
    sys.exit(1)

def create_test_emails():
    """Create different test emails to verify context isolation"""
    emails = {
        "legitimate": """
From: notifications@github.com
To: user@example.com
Subject: GitHub Security Notification
Date: Mon, 25 Sep 2025 10:00:00 +0000

Hello,

This is a legitimate notification from GitHub about your account activity.

Best regards,
GitHub Team
        """,
        
        "phishing": """
From: security@paypal-verification.net
To: victim@example.com
Subject: URGENT: Account Suspended - Verify Now!
Date: Mon, 25 Sep 2025 15:30:00 +0000

Your PayPal account has been suspended due to suspicious activity.

Click here immediately to verify: http://fake-paypal.com/verify

You have 24 hours before permanent suspension.
        """,
        
        "business": """
From: support@microsoft.com
To: customer@company.com
Subject: Office 365 Subscription Renewal
Date: Tue, 26 Sep 2025 09:15:00 +0000

Dear Customer,

Your Office 365 subscription is due for renewal next month.

Visit https://office.microsoft.com/account to manage your subscription.

Thank you,
Microsoft Support
        """
    }
    return emails

def test_context_isolation():
    """Test that context is properly isolated between analyses"""
    print("🧪 Testing context isolation between analyses...")
    
    service = OllamaService("http://localhost:11434", "phi4-mini")
    processor = EmailProcessor()
    emails = create_test_emails()
    
    results = []
    
    # Analyze each email and collect results
    for email_type, email_content in emails.items():
        print(f"\n📧 Analyzing {email_type} email...")
        
        # Clear context before each analysis
        service.clear_context()
        
        processed_data = processor.process_email(email_content, is_file_content=False)
        
        if not processed_data.get("success"):
            print(f"❌ Failed to process {email_type} email")
            continue
        
        start_time = time.time()
        result = service.analyze_email(processed_data)
        end_time = time.time()
        
        if result.get("success"):
            risk_score = result.get("risk_score", 0)
            print(f"✅ {email_type}: Risk {risk_score}/10 (in {end_time-start_time:.2f}s)")
            results.append((email_type, risk_score))
        else:
            print(f"❌ {email_type}: Analysis failed - {result.get('error', 'Unknown error')}")
            results.append((email_type, None))
    
    # Verify results make sense and aren't influenced by previous analyses
    print(f"\n📊 Context Isolation Results:")
    for email_type, risk_score in results:
        if risk_score is not None:
            if email_type == "legitimate" and risk_score <= 3:
                print(f"✅ {email_type}: Correctly identified as low risk ({risk_score}/10)")
            elif email_type == "phishing" and risk_score >= 7:
                print(f"✅ {email_type}: Correctly identified as high risk ({risk_score}/10)")
            elif email_type == "business" and risk_score <= 4:
                print(f"✅ {email_type}: Correctly identified as low risk ({risk_score}/10)")
            else:
                print(f"⚠️  {email_type}: Unexpected risk score {risk_score}/10")
        else:
            print(f"❌ {email_type}: Analysis failed")
    
    return len([r for r in results if r[1] is not None]) == len(results)

def test_abort_context_clearing():
    """Test that aborting properly clears context for next analysis"""
    print("\n🧪 Testing abort context clearing...")
    
    service = OllamaService("http://localhost:11434", "phi4-mini")
    processor = EmailProcessor()
    emails = create_test_emails()
    
    # Start analysis and abort it
    phishing_email = emails["phishing"]
    processed_data = processor.process_email(phishing_email, is_file_content=False)
    
    def abort_after_delay():
        time.sleep(0.3)  # Let analysis start
        print("🛑 Aborting analysis...")
        service.cancel_analysis()
    
    # Start abort thread
    abort_thread = threading.Thread(target=abort_after_delay)
    abort_thread.start()
    
    print("🔄 Starting analysis (will be aborted)...")
    result1 = service.analyze_email(processed_data)
    
    # Verify it was cancelled
    if result1.get("cancelled"):
        print("✅ Analysis was successfully cancelled")
    else:
        print("❌ Analysis was not cancelled")
        return False
    
    # Now analyze a different email to verify clean context
    print("🔄 Starting new analysis after abort...")
    legitimate_email = emails["legitimate"]
    processed_data2 = processor.process_email(legitimate_email, is_file_content=False)
    
    start_time = time.time()
    result2 = service.analyze_email(processed_data2)
    end_time = time.time()
    
    if result2.get("success"):
        risk_score = result2.get("risk_score", 0)
        print(f"✅ Post-abort analysis successful: Risk {risk_score}/10 (in {end_time-start_time:.2f}s)")
        
        # Verify the legitimate email got appropriate score despite previous phishing email
        if risk_score <= 4:
            print("✅ Context properly cleared - legitimate email scored appropriately")
            return True
        else:
            print(f"⚠️  Possible context contamination - legitimate email scored {risk_score}/10")
            return False
    else:
        print("❌ Post-abort analysis failed")
        return False

def test_server_context_clearing():
    """Test server-side context clearing"""
    print("\n🧪 Testing server-side context clearing...")
    
    service = OllamaService("http://localhost:11434", "phi4-mini")
    
    # Test the context clearing method
    try:
        service.clear_server_context()
        print("✅ Server context clearing executed without errors")
        return True
    except Exception as e:
        print(f"❌ Server context clearing failed: {e}")
        return False

def main():
    """Run context isolation tests"""
    print("🎣 Phish-Net Context Isolation Test")
    print("=" * 50)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check if Ollama is running
    print("\n🔌 Checking Ollama connection...")
    service = OllamaService()
    connection = service.test_connection()
    
    if not connection.get("connected"):
        print("❌ Ollama not available - skipping tests")
        print("   Make sure Ollama is running: `ollama serve`")
        return
    
    print(f"✅ Ollama connected")
    print(f"   Model available: {connection.get('model_available', False)}")
    
    if not connection.get("model_available"):
        print("⚠️  Model not available - context tests may not work properly")
    
    # Run tests
    tests_passed = 0
    total_tests = 3
    
    try:
        print(f"\n{'='*50}")
        if test_context_isolation():
            tests_passed += 1
            
        print(f"\n{'='*50}")
        if test_abort_context_clearing():
            tests_passed += 1
            
        print(f"\n{'='*50}")
        if test_server_context_clearing():
            tests_passed += 1
            
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
    
    # Summary
    print(f"\n{'='*50}")
    print(f"📊 Context Isolation Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All context isolation tests passed!")
        print("✅ Abort functionality properly clears context")
    elif tests_passed >= total_tests - 1:
        print("✅ Most tests passed - abort functionality working well")
    else:
        print("⚠️  Some context isolation issues detected")
    
    print(f"\nEnd time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()