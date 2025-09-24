#!/usr/bin/env python3
"""
Final validation of the chunked analysis pipeline implementation
Compares performance metrics and accuracy improvements over legacy system
"""

import sys
import os
import time
from statistics import mean, stdev
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.llm_service import OllamaService
    from src.email_processor import EmailProcessor
    from tests.sample_emails import LEGITIMATE_EMAILS
except ImportError:
    from llm_service import OllamaService
    from email_processor import EmailProcessor
    sys.path.append('tests')
    from sample_emails import LEGITIMATE_EMAILS

def validate_chunked_pipeline():
    """Comprehensive validation of the chunked analysis pipeline"""
    print("🔬 CHUNKED ANALYSIS PIPELINE VALIDATION")
    print("=" * 60)
    print("Comparing new chunked pipeline vs legacy system\n")
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Test with corporate newsletter (should be consistently low risk)
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print("❌ Email processing failed")
        return False
    
    print(f"📧 Test Email: Corporate newsletter")
    print(f"   From: {processed['headers'].get('from', 'Unknown')}")
    print(f"   Domain: {processed['metadata'].get('sender_domain', 'Unknown')}")
    
    # Performance comparison
    print(f"\n⏱️  PERFORMANCE COMPARISON")
    print("-" * 30)
    
    # Multiple runs for statistical accuracy
    chunked_times = []
    legacy_times = []
    chunked_scores = []
    legacy_scores = []
    
    print("Running multiple analyses for statistical accuracy...")
    
    for i in range(3):  # 3 runs each
        print(f"   Run {i+1}/3...")
        
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
        
        # Test legacy pipeline
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
    print(f"\n📊 PERFORMANCE METRICS")
    print("-" * 30)
    
    if chunked_times and legacy_times:
        chunked_avg = mean(chunked_times)
        legacy_avg = mean(legacy_times)
        
        print(f"Chunked Pipeline:")
        print(f"   Average Time: {chunked_avg:.2f}s")
        if len(chunked_times) > 1:
            print(f"   Std Deviation: {stdev(chunked_times):.2f}s")
        
        print(f"Legacy Pipeline:")
        print(f"   Average Time: {legacy_avg:.2f}s")
        if len(legacy_times) > 1:
            print(f"   Std Deviation: {stdev(legacy_times):.2f}s")
        
        time_ratio = chunked_avg / legacy_avg
        print(f"\nTime Ratio: {time_ratio:.1f}x (chunked vs legacy)")
        
        if time_ratio < 4.0:  # Acceptable if less than 4x slower
            print("✅ Performance acceptable")
        else:
            print("⚠️  Performance concern - chunked is significantly slower")
    
    # Accuracy comparison
    print(f"\n🎯 ACCURACY ANALYSIS")
    print("-" * 30)
    
    if chunked_scores and legacy_scores:
        chunked_score_avg = mean(chunked_scores)
        legacy_score_avg = mean(legacy_scores)
        
        print(f"Risk Score Averages:")
        print(f"   Chunked: {chunked_score_avg:.1f}/10")
        print(f"   Legacy: {legacy_score_avg:.1f}/10")
        
        # For corporate newsletter, expect low risk (1-4)
        expected_range = (1, 4)
        
        chunked_in_range = all(expected_range[0] <= score <= expected_range[1] for score in chunked_scores)
        legacy_in_range = all(expected_range[0] <= score <= expected_range[1] for score in legacy_scores)
        
        print(f"Expected Range: {expected_range}")
        print(f"   Chunked in range: {'✅' if chunked_in_range else '❌'}")
        print(f"   Legacy in range: {'✅' if legacy_in_range else '❌'}")
        
        # Consistency check
        if len(chunked_scores) > 1:
            chunked_consistency = max(chunked_scores) - min(chunked_scores)
            print(f"   Chunked consistency: {chunked_consistency} point spread")
        
        if len(legacy_scores) > 1:
            legacy_consistency = max(legacy_scores) - min(legacy_scores)
            print(f"   Legacy consistency: {legacy_consistency} point spread")
    
    # Feature analysis
    print(f"\n🔧 FEATURE ANALYSIS")
    print("-" * 30)
    
    try:
        final_chunked = ollama_service.analyze_email(processed)
        
        if final_chunked.get("success"):
            method = final_chunked.get("analysis_method", "unknown")
            phases = final_chunked.get("phases_completed", 0)
            fallback = final_chunked.get("fallback_used", False)
            
            print(f"Analysis Method: {method}")
            print(f"Phases Completed: {phases}/3")
            print(f"Fallback Used: {'Yes' if fallback else 'No'}")
            
            if phases >= 3 and not fallback:
                print("✅ Full chunked analysis successful")
            elif phases > 0:
                print("⚠️  Partial chunked analysis")
            else:
                print("❌ Chunked analysis failed")
            
            # Check for chunked-specific improvements
            improvements = []
            if method == "chunked_pipeline":
                improvements.append("Three-phase analysis")
            if not fallback:
                improvements.append("No legacy fallback needed")
            if phases >= 3:
                improvements.append("Complete phase execution")
            
            if improvements:
                print(f"✅ Improvements: {', '.join(improvements)}")
    
    except Exception as e:
        print(f"❌ Feature analysis failed: {e}")
    
    # Final assessment
    print(f"\n🎯 FINAL ASSESSMENT")
    print("=" * 30)
    
    success_criteria = []
    
    # Performance criterion (not more than 4x slower)
    if chunked_times and legacy_times and mean(chunked_times) / mean(legacy_times) <= 4.0:
        success_criteria.append("Performance acceptable")
    
    # Accuracy criterion (scores in expected range)
    if chunked_scores and all(1 <= score <= 4 for score in chunked_scores):
        success_criteria.append("Accuracy maintained")
    
    # Functionality criterion (no fallbacks)
    if final_chunked.get("success") and not final_chunked.get("fallback_used") and final_chunked.get("phases_completed", 0) >= 3:
        success_criteria.append("Full functionality")
    
    print(f"Success Criteria Met: {len(success_criteria)}/3")
    for criterion in success_criteria:
        print(f"   ✅ {criterion}")
    
    if len(success_criteria) >= 2:
        print(f"\n🎉 CHUNKED PIPELINE VALIDATION SUCCESSFUL")
        print("Ready for production deployment!")
        return True
    else:
        print(f"\n⚠️  CHUNKED PIPELINE NEEDS IMPROVEMENT")
        print("Consider further optimization before deployment.")
        return False

if __name__ == "__main__":
    print("Chunked Analysis Pipeline - Final Validation")
    print("=" * 60)
    
    success = validate_chunked_pipeline()
    
    if success:
        print("\n✅ Validation completed successfully!")
        print("The chunked analysis pipeline is ready for use.")
        sys.exit(0)
    else:
        print("\n❌ Validation revealed issues.")
        print("Please review and address concerns before deployment.")
        sys.exit(1)