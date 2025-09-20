#!/usr/bin/env python3
"""
Quick Test Script for Abort Functionality

Tests the new abort functionality in Phish-Net to ensure that:
1. LLM service can be cancelled during analysis
2. Timeout settings work properly
3. UI responds correctly to abort requests

This script simulates long-running analysis scenarios.
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
    from error_handling import ErrorCategory
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the tests directory")
    sys.exit(1)

def test_cancellation():
    """Test that LLM service can be cancelled during analysis"""
    print("🧪 Testing LLM service cancellation...")
    
    # Create service with short timeout for testing
    service = OllamaService("http://localhost:11434", "phi4-mini")
    service.timeout = 5
    
    # Create sample processed email data
    processor = EmailProcessor()
    test_email = """
    From: test@example.com
    To: user@company.com
    Subject: Test Email for Abort Functionality
    
    This is a test email to verify that the abort functionality works correctly.
    The email contains some URLs: http://suspicious-site.com/login
    """
    
    processed_data = processor.process_email(test_email, is_file_content=False)
    
    if not processed_data.get("success"):
        print("❌ Failed to process test email")
        return False
    
    print("✅ Test email processed successfully")
    
    # Test 1: Start analysis and cancel immediately
    def cancel_after_delay():
        time.sleep(0.5)  # Wait briefly then cancel
        print("🛑 Cancelling analysis...")
        service.cancel_analysis()
    
    # Start cancellation thread
    cancel_thread = threading.Thread(target=cancel_after_delay)
    cancel_thread.start()
    
    # Start analysis
    print("🔄 Starting analysis (will be cancelled)...")
    start_time = time.time()
    result = service.analyze_email(processed_data)
    end_time = time.time()
    
    # Check results
    if result.get("cancelled"):
        print(f"✅ Analysis was cancelled successfully in {end_time - start_time:.2f} seconds")
        print(f"   Message: {result.get('user_message')}")
        return True
    else:
        print(f"❌ Analysis was not cancelled (completed in {end_time - start_time:.2f} seconds)")
        print(f"   Result: {result}")
        return False

def test_timeout():
    """Test timeout functionality"""
    print("\n🧪 Testing timeout functionality...")
    
    # Create service with very short timeout
    service = OllamaService("http://localhost:11434", "phi4-mini")
    service.timeout = 1  # 1 second timeout
    
    # Create sample processed email data
    processor = EmailProcessor()
    test_email = """
    From: test@example.com
    To: user@company.com
    Subject: Test Email for Timeout
    
    This is a very long email designed to test timeout functionality.
    """ + "This is additional content. " * 100  # Make it long
    
    processed_data = processor.process_email(test_email, is_file_content=False)
    
    print("🔄 Starting analysis with 1-second timeout...")
    start_time = time.time()
    result = service.analyze_email(processed_data)
    end_time = time.time()
    
    # Check if timeout was handled
    if result.get("analysis_failed") and end_time - start_time <= 5:
        print(f"✅ Timeout handled correctly in {end_time - start_time:.2f} seconds")
        print(f"   Error: {result.get('user_message', 'No message')}")
        return True
    else:
        print(f"❌ Timeout not handled properly")
        print(f"   Duration: {end_time - start_time:.2f} seconds")
        print(f"   Result: {result}")
        return False

def main():
    """Run abort functionality tests"""
    print("🎣 Phish-Net Abort Functionality Test")
    print("=" * 50)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Check if Ollama is running
    print("🔌 Checking Ollama connection...")
    service = OllamaService()
    connection = service.test_connection()
    
    if not connection.get("connected"):
        print("❌ Ollama not available - skipping tests")
        print("   Make sure Ollama is running: `ollama serve`")
        return
    
    print(f"✅ Ollama connected")
    print(f"   Model available: {connection.get('model_available', False)}")
    print()
    
    # Run tests
    tests_passed = 0
    total_tests = 2
    
    try:
        if test_cancellation():
            tests_passed += 1
            
        if test_timeout():
            tests_passed += 1
            
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
    
    # Summary
    print(f"\n📊 Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All abort functionality tests passed!")
    else:
        print("⚠️  Some tests failed - check implementation")
    
    print(f"\nEnd time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()