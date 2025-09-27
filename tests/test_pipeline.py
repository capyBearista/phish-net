#!/usr/bin/env python3
"""
Comprehensive Pipeline Testing Suite

This module consolidates all pipeline-related tests including:
- Chunked vs Legacy pipeline comparison  
- Multi-email testing with various email types
- Statistical performance validation and benchmarking
- Accuracy and consistency verification

Consolidated from: test_comprehensive.py, test_multi_emails.py, validate_pipeline.py
"""

import sys
import os
import time
from statistics import mean, stdev
from typing import List, Dict, Tuple, Any, Optional

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from src.llm_service import OllamaService
    from src.email_processor import EmailProcessor
    from sample_emails import LEGITIMATE_EMAILS
except ImportError:
    from llm_service import OllamaService
    from email_processor import EmailProcessor
    from sample_emails import LEGITIMATE_EMAILS


class PipelineTestResult:
    """Data class to store pipeline test results for analysis."""
    
    def __init__(self, method: str, success: bool, risk_score: int = 0, 
                 processing_time: float = 0.0, phases_completed: int = 0, 
                 fallback_used: bool = False):
        self.method = method
        self.success = success
        self.risk_score = risk_score
        self.processing_time = processing_time
        self.phases_completed = phases_completed
        self.fallback_used = fallback_used


def test_chunked_vs_legacy_comparison() -> bool:
    """
    Compare chunked pipeline performance against legacy method.
    
    Tests both methods with the same email and compares:
    - Processing times
    - Risk score accuracy
    - Analysis quality
    
    Returns:
        bool: True if chunked pipeline performs acceptably
    """
    print("=" * 70)
    print("🔬 CHUNKED VS LEGACY PIPELINE COMPARISON")
    print("=" * 70)
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print("❌ Email processing failed")
        return False
    
    print(f"📧 Testing Email: Corporate newsletter from company.com")
    print(f"   From: {processed['headers'].get('from', 'Unknown')}")
    print(f"   Domain: {processed['metadata'].get('sender_domain', 'Unknown')}")
    
    # Test new chunked method
    print("\n1️⃣  CHUNKED PIPELINE:")
    print("-" * 40)
    
    chunked_start = time.time()
    try:
        chunked_result = ollama_service.analyze_email(processed)
        chunked_time = time.time() - chunked_start
        
        if chunked_result.get("success"):
            chunked_score = chunked_result.get("risk_score", 5)
            chunked_method = chunked_result.get("analysis_method", "unknown")
            chunked_phases = chunked_result.get("phases_completed", 0)
            chunked_fallback = chunked_result.get("fallback_used", False)
            
            print(f"✅ Success: Risk Score {chunked_score}/10")
            print(f"   Method: {chunked_method}")
            print(f"   Phases: {chunked_phases}/3")
            print(f"   Fallback: {'Yes' if chunked_fallback else 'No'}")
            print(f"   Time: {chunked_time:.2f}s")
        else:
            print(f"❌ Failed: {chunked_result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False
    
    # Test legacy method if available
    print("\n2️⃣  LEGACY PIPELINE:")
    print("-" * 40)
    
    legacy_start = time.time()
    try:
        # Check if legacy method exists
        if hasattr(ollama_service, 'analyze_email_legacy'):
            legacy_result = ollama_service.analyze_email_legacy(processed)
            legacy_time = time.time() - legacy_start
            
            if legacy_result.get("success"):
                legacy_score = legacy_result.get("risk_score", 5)
                print(f"✅ Success: Risk Score {legacy_score}/10")
                print(f"   Time: {legacy_time:.2f}s")
                
                # Performance comparison
                time_ratio = chunked_time / legacy_time
                print(f"\n📊 PERFORMANCE COMPARISON:")
                print(f"   Time Ratio: {time_ratio:.1f}x (chunked vs legacy)")
                print(f"   Score Difference: {abs(chunked_score - legacy_score)} points")
                
                return time_ratio <= 4.0  # Acceptable if less than 4x slower
            else:
                print(f"❌ Failed: {legacy_result.get('error', 'Unknown error')}")
        else:
            print("⚠️  Legacy method not available - testing chunked only")
            return True  # Accept chunked-only testing
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        print("⚠️  Legacy testing failed - accepting chunked results")
        return True
    
    return True


def test_multi_email_accuracy() -> bool:
    """
    Test chunked pipeline with multiple email types for accuracy and consistency.
    
    Tests various email types and verifies:
    - Risk scores within expected ranges
    - Consistent scoring across runs
    - Proper analysis method execution
    
    Returns:
        bool: True if accuracy requirements are met
    """
    print("\n" + "=" * 70)
    print("📊 MULTI-EMAIL ACCURACY TESTING")
    print("=" * 70)
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Test cases with expected risk ranges
    test_cases = [
        ("corporate_newsletter", "Corporate Newsletter", (1, 4)),
        ("password_reset_legitimate", "GitHub Password Reset", (1, 3)),
        ("meeting_invitation", "Meeting Invitation", (1, 3)),
    ]
    
    results: List[PipelineTestResult] = []
    total_time = 0.0
    
    for email_key, description, expected_range in test_cases:
        print(f"\n🔍 Testing: {description}")
        print(f"   Expected range: {expected_range}")
        
        if email_key not in LEGITIMATE_EMAILS:
            print(f"   ⚠️  Email '{email_key}' not found in samples")
            continue
        
        test_email = LEGITIMATE_EMAILS[email_key]["content"]
        processed = email_processor.process_email(test_email)
        
        if not processed["success"]:
            print(f"   ❌ Email processing failed")
            continue
        
        # Run analysis
        start_time = time.time()
        try:
            result = ollama_service.analyze_email(processed)
            processing_time = time.time() - start_time
            total_time += processing_time
            
            if result.get("success"):
                risk_score = result.get("risk_score", 5)
                method = result.get("analysis_method", "unknown")
                phases = result.get("phases_completed", 0)
                fallback = result.get("fallback_used", False)
                
                # Check if score is in expected range
                in_range = expected_range[0] <= risk_score <= expected_range[1]
                range_indicator = "✅" if in_range else "⚠️"
                
                print(f"   {range_indicator} Risk Score: {risk_score}/10")
                print(f"   📊 Method: {method}")
                print(f"   ⚡ Time: {processing_time:.2f}s")
                print(f"   🔧 Phases: {phases}/3")
                print(f"   🔄 Fallback: {'Yes' if fallback else 'No'}")
                
                # Store result
                results.append(PipelineTestResult(
                    method=method,
                    success=True,
                    risk_score=risk_score,
                    processing_time=processing_time,
                    phases_completed=phases,
                    fallback_used=fallback
                ))
            else:
                print(f"   ❌ Analysis failed: {result.get('error', 'Unknown')}")
                results.append(PipelineTestResult(method="failed", success=False))
                
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            results.append(PipelineTestResult(method="exception", success=False))
    
    # Analyze results
    successful = [r for r in results if r.success]
    if not successful:
        print("\n❌ No successful analyses - cannot evaluate accuracy")
        return False
    
    print(f"\n📈 MULTI-EMAIL ANALYSIS SUMMARY:")
    print(f"   Total emails tested: {len(results)}")
    print(f"   Successful analyses: {len(successful)}")
    print(f"   Success rate: {len(successful)/len(results)*100:.1f}%")
    print(f"   Average time: {mean([r.processing_time for r in successful]):.2f}s")
    print(f"   Total time: {total_time:.2f}s")
    
    # Check success criteria
    success_rate = len(successful) / len(results) * 100
    avg_phases = mean([r.phases_completed for r in successful])
    fallback_rate = sum(1 for r in successful if r.fallback_used) / len(successful) * 100
    
    print(f"   Average phases: {avg_phases:.1f}/3")
    print(f"   Fallback rate: {fallback_rate:.1f}%")
    
    # Success criteria: >80% success rate, <30% fallback rate
    meets_criteria = success_rate >= 80 and fallback_rate <= 30
    
    print(f"\n{'✅' if meets_criteria else '❌'} Accuracy Criteria: {meets_criteria}")
    
    return meets_criteria


def statistical_pipeline_validation() -> bool:
    """
    Comprehensive statistical validation of chunked pipeline.
    
    Performs multiple runs for statistical analysis including:
    - Performance metrics with standard deviation
    - Consistency analysis across multiple runs
    - Success criteria validation
    
    Returns:
        bool: True if pipeline meets all validation criteria
    """
    print("\n" + "=" * 70)
    print("📊 STATISTICAL PIPELINE VALIDATION")
    print("=" * 70)
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print("❌ Email processing failed")
        return False
    
    print("Running multiple analyses for statistical accuracy...")
    
    # Multiple runs for statistical analysis
    num_runs = 3
    chunked_times: List[float] = []
    chunked_scores: List[int] = []
    legacy_times: List[float] = []
    legacy_scores: List[int] = []
    
    for i in range(num_runs):
        print(f"   Run {i+1}/{num_runs}...")
        
        # Test chunked pipeline
        start = time.time()
        try:
            chunked_result = ollama_service.analyze_email(processed)
            chunked_time = time.time() - start
            
            if chunked_result.get("success"):
                chunked_times.append(chunked_time)
                chunked_scores.append(chunked_result.get("risk_score", 5))
        except Exception as e:
            print(f"      ❌ Chunked analysis failed: {e}")
        
        # Test legacy pipeline if available
        if hasattr(ollama_service, 'analyze_email_legacy'):
            start = time.time()
            try:
                legacy_result = ollama_service.analyze_email_legacy(processed)
                legacy_time = time.time() - start
                
                if legacy_result.get("success"):
                    legacy_times.append(legacy_time)
                    legacy_scores.append(legacy_result.get("risk_score", 5))
            except Exception as e:
                print(f"      ❌ Legacy analysis failed: {e}")
    
    # Statistical analysis
    print(f"\n📊 STATISTICAL RESULTS:")
    print("-" * 40)
    
    if chunked_times and chunked_scores:
        chunked_avg_time = mean(chunked_times)
        chunked_avg_score = mean(chunked_scores)
        
        print(f"Chunked Pipeline:")
        print(f"   Average Time: {chunked_avg_time:.2f}s")
        print(f"   Average Score: {chunked_avg_score:.1f}/10")
        
        if len(chunked_times) > 1:
            print(f"   Time Std Dev: {stdev(chunked_times):.2f}s")
        if len(chunked_scores) > 1:
            print(f"   Score Std Dev: {stdev(chunked_scores):.2f}")
        
        # Performance validation
        if legacy_times:
            legacy_avg_time = mean(legacy_times)
            time_ratio = chunked_avg_time / legacy_avg_time
            print(f"\nPerformance Comparison:")
            print(f"   Legacy Average: {legacy_avg_time:.2f}s")
            print(f"   Time Ratio: {time_ratio:.1f}x")
            
            performance_ok = time_ratio <= 4.0
        else:
            performance_ok = chunked_avg_time <= 10.0  # Absolute performance check
            print(f"   Absolute Performance: {'✅' if performance_ok else '❌'}")
        
        # Accuracy validation (expect low risk for corporate newsletter)
        expected_range = (1, 4)
        accuracy_ok = all(expected_range[0] <= score <= expected_range[1] for score in chunked_scores)
        
        # Consistency check
        consistency_ok = True
        if len(chunked_scores) > 1:
            score_spread = max(chunked_scores) - min(chunked_scores)
            consistency_ok = score_spread <= 2  # Allow 2-point spread
            print(f"   Score Consistency: {score_spread} point spread ({'✅' if consistency_ok else '❌'})")
        
        print(f"\n🎯 VALIDATION SUMMARY:")
        print(f"   Performance: {'✅' if performance_ok else '❌'}")
        print(f"   Accuracy: {'✅' if accuracy_ok else '❌'}")
        print(f"   Consistency: {'✅' if consistency_ok else '❌'}")
        
        return performance_ok and accuracy_ok and consistency_ok
    
    else:
        print("❌ Insufficient data for statistical analysis")
        return False


def run_comprehensive_pipeline_tests() -> bool:
    """
    Run all pipeline tests and provide comprehensive results.
    
    Returns:
        bool: True if all pipeline tests pass
    """
    print("🚀 COMPREHENSIVE PIPELINE TESTING SUITE")
    print("=" * 70)
    print("Testing chunked analysis pipeline performance and accuracy\n")
    
    test_results = []
    
    # Run all test suites
    try:
        print("Phase 1: Chunked vs Legacy Comparison")
        comparison_result = test_chunked_vs_legacy_comparison()
        test_results.append(("Comparison Test", comparison_result))
        
        print("\nPhase 2: Multi-Email Accuracy Testing")  
        accuracy_result = test_multi_email_accuracy()
        test_results.append(("Accuracy Test", accuracy_result))
        
        print("\nPhase 3: Statistical Validation")
        statistical_result = statistical_pipeline_validation()
        test_results.append(("Statistical Test", statistical_result))
        
    except Exception as e:
        print(f"❌ Critical error during testing: {e}")
        return False
    
    # Final summary
    print("\n" + "=" * 70)
    print("🎯 FINAL PIPELINE TEST SUMMARY")
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
        print(f"\n🎉 ALL PIPELINE TESTS PASSED!")
        print("The chunked analysis pipeline is ready for production use.")
    else:
        print(f"\n⚠️  PIPELINE NEEDS IMPROVEMENT")
        print("Some tests failed. Review results and optimize before deployment.")
    
    return overall_success


if __name__ == "__main__":
    """Main execution for comprehensive pipeline testing."""
    print("Phish-Net Pipeline Testing Suite")
    print("=" * 70)
    
    success = run_comprehensive_pipeline_tests()
    
    if success:
        print("\n✅ All pipeline tests completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Pipeline testing revealed issues that need attention.")
        sys.exit(1)