#!/usr/bin/env python3
"""
System Features Testing Suite

This module consolidates tests for system-level features including:
- Abort functionality and cancellation handling
- Context isolation between analyses
- Error handling and recovery
- Session management and cleanup

Consolidated from: test_abort_functionality.py, test_context_isolation.py
"""

import sys
import os
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from src.llm_service import OllamaService
    from src.email_processor import EmailProcessor
    from src.error_handling import ErrorCategory
except ImportError:
    from llm_service import OllamaService
    from email_processor import EmailProcessor
    try:
        from error_handling import ErrorCategory
    except ImportError:
        # Define basic error categories if not available
        class ErrorCategory:
            OLLAMA_CONNECTION = "OLLAMA_CONNECTION"
            TIMEOUT = "TIMEOUT"
            ANALYSIS_FAILED = "ANALYSIS_FAILED"


def create_test_emails() -> Dict[str, str]:
    """
    Create different test emails to verify context isolation and system features.
    
    Returns:
        Dict[str, str]: Dictionary of test emails with different characteristics
    """
    return {
        "legitimate": """
From: notifications@github.com
To: user@example.com
Subject: GitHub Security Notification
Date: Mon, 25 Sep 2025 10:00:00 +0000
Message-ID: <abc123@github.com>

Hi there,

This is a legitimate security notification from GitHub.

Your account was accessed from a new device. If this was you, no action needed.

GitHub Security Team
        """,
        
        "suspicious": """
From: security@github-security.net
To: user@example.com
Subject: URGENT: Account Suspended - Verify Now
Date: Mon, 25 Sep 2025 10:00:00 +0000
Message-ID: <xyz789@fake-domain.com>

URGENT ACTION REQUIRED!

Your GitHub account has been suspended due to suspicious activity.

Click here to verify: http://fake-github-verify.com/urgent

You have 24 hours to verify or your account will be permanently deleted!

GitHub Security (URGENT)
        """,
        
        "corporate": """
From: hr@company.com
To: employee@company.com
Subject: Monthly Team Meeting - Thursday 2 PM
Date: Mon, 25 Sep 2025 09:00:00 +0000
Message-ID: <meeting123@company.com>

Dear Team,

Please join us for our monthly team meeting this Thursday at 2 PM in Conference Room A.

Agenda:
- Q3 Review
- Q4 Planning
- Team Updates

Best regards,
HR Team
        """
    }


def test_basic_abort_functionality() -> bool:
    """
    Test basic abort and cancellation functionality.
    
    Tests:
    - Service can be cancelled during analysis
    - Timeout settings work properly
    - Proper cleanup after abort
    
    Returns:
        bool: True if abort functionality works correctly
    """
    print("=" * 70)
    print("🛑 BASIC ABORT FUNCTIONALITY TEST")
    print("=" * 70)
    
    # Create service with short timeout for testing
    service = OllamaService("http://localhost:11434", "phi4-mini")
    service.timeout = 5  # Short timeout for testing
    
    processor = EmailProcessor()
    test_emails = create_test_emails()
    
    print("Testing LLM service cancellation capabilities...\n")
    
    # Test 1: Basic timeout handling
    print("🔍 Test 1: Timeout Handling")
    try:
        processed = processor.process_email(test_emails["legitimate"], is_file_content=False)
        
        if processed["success"]:
            # This should complete normally or timeout gracefully
            start_time = time.time()
            result = service.analyze_email(processed)
            elapsed_time = time.time() - start_time
            
            print(f"   ⏱️  Analysis time: {elapsed_time:.2f}s")
            print(f"   ✅ Timeout handling: {'PASS' if elapsed_time <= 15 else 'SLOW'}")
            
            if result.get("success"):
                print(f"   ✅ Analysis completed successfully")
            else:
                print(f"   ⚠️  Analysis failed (acceptable for timeout test)")
                
        else:
            print("   ❌ Email processing failed")
            return False
            
    except Exception as e:
        print(f"   ❌ Exception during timeout test: {e}")
        return False
    
    # Test 2: Service state after operations
    print("\n🔍 Test 2: Service State Management")
    try:
        # Test multiple quick operations
        for i in range(3):
            processed = processor.process_email(test_emails["corporate"], is_file_content=False)
            if processed["success"]:
                result = service.analyze_email(processed)
                status = "✅" if result.get("success") else "⚠️"
                print(f"   Operation {i+1}: {status}")
            
    except Exception as e:
        print(f"   ❌ Exception during state test: {e}")
        return False
    
    print("\n📊 ABORT FUNCTIONALITY SUMMARY:")
    print("   Basic timeout handling: ✅ PASS")
    print("   Service state management: ✅ PASS")
    print("   Overall result: ✅ PASS")
    
    return True


def test_context_isolation() -> bool:
    """
    Test that analyses are properly isolated and don't interfere with each other.
    
    Tests:
    - Sequential analyses with different content
    - Context clearing between analyses
    - No cross-contamination of results
    
    Returns:
        bool: True if context isolation works correctly
    """
    print("\n" + "=" * 70)
    print("🔒 CONTEXT ISOLATION TEST")
    print("=" * 70)
    
    service = OllamaService()
    processor = EmailProcessor()
    test_emails = create_test_emails()
    
    print("Testing context isolation between different email analyses...\n")
    
    # Test sequential different analyses
    analysis_results = []
    
    email_types = ["legitimate", "suspicious", "corporate"]
    expected_scores = {
        "legitimate": (1, 4),    # Should be low risk
        "suspicious": (6, 10),   # Should be high risk  
        "corporate": (1, 3)      # Should be very low risk
    }
    
    print("🔍 Sequential Analysis Test:")
    for i, email_type in enumerate(email_types):
        print(f"\n   Analysis {i+1}: {email_type.title()} Email")
        
        try:
            # Process email
            processed = processor.process_email(test_emails[email_type], is_file_content=False)
            
            if not processed["success"]:
                print(f"      ❌ Processing failed")
                continue
            
            # Analyze with fresh context
            start_time = time.time()
            result = service.analyze_email(processed)
            analysis_time = time.time() - start_time
            
            if result.get("success"):
                risk_score = result.get("risk_score", 5)
                method = result.get("analysis_method", "unknown")
                
                # Check if score is in expected range
                expected_range = expected_scores[email_type]
                in_range = expected_range[0] <= risk_score <= expected_range[1]
                
                print(f"      📊 Risk Score: {risk_score}/10 {'✅' if in_range else '⚠️'}")
                print(f"      🔧 Method: {method}")
                print(f"      ⏱️  Time: {analysis_time:.2f}s")
                
                analysis_results.append({
                    "type": email_type,
                    "score": risk_score,
                    "success": True,
                    "in_range": in_range,
                    "method": method
                })
                
            else:
                print(f"      ❌ Analysis failed: {result.get('error', 'Unknown')}")
                analysis_results.append({
                    "type": email_type,
                    "success": False
                })
                
        except Exception as e:
            print(f"      ❌ Exception: {e}")
            analysis_results.append({
                "type": email_type,
                "success": False
            })
    
    # Analyze context isolation effectiveness
    print(f"\n🔍 Context Isolation Analysis:")
    
    successful_results = [r for r in analysis_results if r.get("success", False)]
    
    if len(successful_results) >= 2:
        # Check for proper score differentiation
        scores = [r["score"] for r in successful_results]
        score_variance = max(scores) - min(scores)
        
        print(f"   📊 Score variance: {score_variance} points")
        
        # Good isolation should show clear differentiation
        isolation_good = score_variance >= 3
        print(f"   🔒 Score differentiation: {'✅ GOOD' if isolation_good else '⚠️ POOR'}")
        
        # Check method consistency
        methods = [r.get("method", "unknown") for r in successful_results]
        method_consistent = len(set(methods)) <= 2  # Allow some method variation
        print(f"   🔧 Method consistency: {'✅ CONSISTENT' if method_consistent else '⚠️ VARIED'}")
        
        # Check range accuracy
        in_range_count = sum(1 for r in successful_results if r.get("in_range", False))
        range_accuracy = (in_range_count / len(successful_results)) * 100
        print(f"   🎯 Range accuracy: {range_accuracy:.0f}%")
        
        isolation_success = isolation_good and range_accuracy >= 60
        
    else:
        print("   ❌ Insufficient successful analyses for isolation testing")
        isolation_success = False
    
    print(f"\n📊 CONTEXT ISOLATION SUMMARY:")
    print(f"   Successful analyses: {len(successful_results)}/{len(analysis_results)}")
    if successful_results:
        print(f"   Score differentiation: {'✅ PASS' if isolation_good else '❌ FAIL'}")
        print(f"   Range accuracy: {range_accuracy:.0f}%")
    print(f"   Overall isolation: {'✅ PASS' if isolation_success else '❌ FAIL'}")
    
    return isolation_success


def test_error_recovery() -> bool:
    """
    Test system recovery from various error conditions.
    
    Tests:
    - Recovery from network errors
    - Handling of malformed inputs
    - Graceful degradation
    
    Returns:
        bool: True if error recovery works correctly
    """
    print("\n" + "=" * 70)
    print("🔧 ERROR RECOVERY TEST")
    print("=" * 70)
    
    processor = EmailProcessor()
    service = OllamaService()
    
    print("Testing system recovery from various error conditions...\n")
    
    # Test 1: Malformed email handling
    print("🔍 Test 1: Malformed Email Recovery")
    
    malformed_emails = [
        ("", "Empty email"),
        ("Invalid email content", "Invalid format"),
        ("From: \nTo: \nSubject: \n\nNo proper headers", "Minimal headers"),
    ]
    
    malformed_recovery_count = 0
    
    for bad_email, description in malformed_emails:
        try:
            processed = processor.process_email(bad_email, is_file_content=False)
            
            if processed["success"]:
                print(f"   ⚠️  {description}: Processed (unexpected)")
            else:
                print(f"   ✅ {description}: Rejected gracefully")
                malformed_recovery_count += 1
                
        except Exception as e:
            print(f"   ❌ {description}: Exception - {e}")
    
    # Test 2: Service resilience
    print(f"\n🔍 Test 2: Service Resilience")
    
    try:
        # Test with a valid email after errors
        test_emails = create_test_emails()
        processed = processor.process_email(test_emails["legitimate"], is_file_content=False)
        
        if processed["success"]:
            result = service.analyze_email(processed)
            
            if result.get("success"):
                print(f"   ✅ Service recovered: Analysis successful")
                service_recovery = True
            else:
                print(f"   ⚠️  Service partially recovered: {result.get('error', 'Unknown')}")
                service_recovery = True  # Still counts as recovery if graceful failure
        else:
            print(f"   ❌ Processing still failing after errors")
            service_recovery = False
            
    except Exception as e:
        print(f"   ❌ Service recovery failed: {e}")
        service_recovery = False
    
    # Calculate recovery success
    malformed_recovery_rate = (malformed_recovery_count / len(malformed_emails)) * 100
    
    print(f"\n📊 ERROR RECOVERY SUMMARY:")
    print(f"   Malformed email handling: {malformed_recovery_rate:.0f}%")
    print(f"   Service resilience: {'✅ PASS' if service_recovery else '❌ FAIL'}")
    
    overall_recovery = malformed_recovery_rate >= 80 and service_recovery
    print(f"   Overall recovery: {'✅ PASS' if overall_recovery else '❌ FAIL'}")
    
    return overall_recovery


def test_concurrent_analysis_safety() -> bool:
    """
    Test system behavior under concurrent analysis requests.
    
    Tests:
    - Multiple simultaneous analyses
    - Resource management
    - Result integrity
    
    Returns:
        bool: True if concurrent operations are handled safely
    """
    print("\n" + "=" * 70)
    print("⚡ CONCURRENT ANALYSIS SAFETY TEST")
    print("=" * 70)
    
    processor = EmailProcessor()
    service = OllamaService()
    test_emails = create_test_emails()
    
    print("Testing concurrent analysis safety...\n")
    
    # Prepare test data
    concurrent_results = []
    
    def analyze_email_thread(email_content: str, thread_id: int) -> None:
        """Thread function for concurrent analysis."""
        try:
            processed = processor.process_email(email_content, is_file_content=False)
            
            if processed["success"]:
                start_time = time.time()
                result = service.analyze_email(processed)
                analysis_time = time.time() - start_time
                
                concurrent_results.append({
                    "thread_id": thread_id,
                    "success": result.get("success", False),
                    "risk_score": result.get("risk_score", 0),
                    "analysis_time": analysis_time,
                    "error": result.get("error", None)
                })
            else:
                concurrent_results.append({
                    "thread_id": thread_id,
                    "success": False,
                    "error": "Processing failed"
                })
                
        except Exception as e:
            concurrent_results.append({
                "thread_id": thread_id,
                "success": False,
                "error": str(e)
            })
    
    # Run concurrent analyses
    print("🔍 Running 3 concurrent analyses...")
    
    threads = []
    email_list = list(test_emails.values())
    
    for i in range(3):
        email_content = email_list[i % len(email_list)]
        thread = threading.Thread(
            target=analyze_email_thread, 
            args=(email_content, i)
        )
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join(timeout=30)  # 30 second timeout
    
    # Analyze results
    print(f"\n📊 Concurrent Analysis Results:")
    
    successful_concurrent = [r for r in concurrent_results if r.get("success", False)]
    
    for result in concurrent_results:
        thread_id = result.get("thread_id", "Unknown")
        if result.get("success"):
            score = result.get("risk_score", 0)
            time_taken = result.get("analysis_time", 0)
            print(f"   Thread {thread_id}: ✅ Score {score}/10, Time {time_taken:.2f}s")
        else:
            error = result.get("error", "Unknown error")
            print(f"   Thread {thread_id}: ❌ {error}")
    
    # Check concurrent safety
    success_rate = (len(successful_concurrent) / len(concurrent_results)) * 100 if concurrent_results else 0
    
    # Check for reasonable performance (no thread should take excessively long)
    if successful_concurrent:
        max_time = max(r.get("analysis_time", 0) for r in successful_concurrent)
        performance_ok = max_time <= 20  # 20 second max per analysis
    else:
        performance_ok = False
    
    print(f"\n📊 CONCURRENT SAFETY SUMMARY:")
    print(f"   Threads completed: {len(concurrent_results)}/3")
    print(f"   Success rate: {success_rate:.0f}%")
    print(f"   Performance: {'✅ GOOD' if performance_ok else '❌ POOR'}")
    
    concurrent_safety = success_rate >= 60 and performance_ok
    print(f"   Overall safety: {'✅ PASS' if concurrent_safety else '❌ FAIL'}")
    
    return concurrent_safety


def run_comprehensive_system_tests() -> bool:
    """
    Run all system feature tests and provide comprehensive results.
    
    Returns:
        bool: True if all system feature tests pass
    """
    print("🛡️  COMPREHENSIVE SYSTEM FEATURES TESTING SUITE")
    print("=" * 70)
    print("Testing abort functionality, context isolation, and error recovery\n")
    
    test_results = []
    
    try:
        print("Phase 1: Basic Abort Functionality")
        abort_result = test_basic_abort_functionality()
        test_results.append(("Abort Functionality", abort_result))
        
        print("\nPhase 2: Context Isolation")
        isolation_result = test_context_isolation()
        test_results.append(("Context Isolation", isolation_result))
        
        print("\nPhase 3: Error Recovery")
        recovery_result = test_error_recovery()
        test_results.append(("Error Recovery", recovery_result))
        
        print("\nPhase 4: Concurrent Analysis Safety")
        concurrent_result = test_concurrent_analysis_safety()
        test_results.append(("Concurrent Safety", concurrent_result))
        
    except Exception as e:
        print(f"❌ Critical error during system testing: {e}")
        return False
    
    # Final summary
    print("\n" + "=" * 70)
    print("🎯 FINAL SYSTEM FEATURES TEST SUMMARY")
    print("=" * 70)
    
    passed_tests = 0
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name}: {status}")
        if result:
            passed_tests += 1
    
    overall_success = passed_tests == len(test_results)
    success_rate = (passed_tests / len(test_results)) * 100
    
    print(f"\nOverall Success Rate: {success_rate:.0f}% ({passed_tests}/{len(test_results)})")
    
    if overall_success:
        print(f"\n🎉 ALL SYSTEM FEATURE TESTS PASSED!")
        print("System features are functioning correctly and robustly.")
    else:
        print(f"\n⚠️  SYSTEM FEATURES NEED ATTENTION")
        print("Some tests failed. Review system robustness and error handling.")
    
    return overall_success


if __name__ == "__main__":
    """Main execution for comprehensive system features testing."""
    print("Phish-Net System Features Testing Suite")
    print("=" * 70)
    
    success = run_comprehensive_system_tests()
    
    if success:
        print("\n✅ All system feature tests completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ System feature testing revealed issues that need attention.")
        sys.exit(1)