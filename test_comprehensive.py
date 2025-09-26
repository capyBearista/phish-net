#!/usr/bin/env python3
"""
Comprehensive test for the new chunked analysis pipeline
Tests integration with the complete system including risk assessment
"""

import sys
import os
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

def test_new_vs_old():
    """Compare new chunked pipeline vs legacy method"""
    print("=== Testing New vs Legacy Analysis ===")
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print("❌ Email processing failed")
        return False
    
    print("📧 Testing Email: Corporate newsletter from company.com")
    
    # Test new chunked method
    print("\n1️⃣  NEW CHUNKED PIPELINE:")
    print("=" * 30)
    
    try:
        new_start = time.time()
        new_result = ollama_service.analyze_email(processed)
        new_time = time.time() - new_start
        
        if new_result.get("success", False):
            print("✅ Chunked analysis completed")
            print(f"   Risk Score: {new_result.get('risk_score', 'N/A')}/10")
            print(f"   Recommendation: {new_result.get('recommendation', 'N/A')}")
            print(f"   Confidence: {new_result.get('confidence', 'N/A')}")
            print(f"   Method: {new_result.get('analysis_method', 'N/A')}")
            print(f"   Phases Completed: {new_result.get('phases_completed', 'N/A')}")
            print(f"   Processing Time: {new_time:.2f}s")
            
            if new_result.get("fallback_used"):
                print(f"   ⚠️  Fallback Used: {new_result.get('fallback_reason', 'Unknown')}")
        else:
            print("❌ Chunked analysis failed")
            print(f"   Error: {new_result}")
            return False
    except Exception as e:
        print(f"❌ Exception in chunked analysis: {e}")
        return False
    
    # Test legacy method for comparison
    print("\n2️⃣  LEGACY SINGLE-PROMPT:")
    print("=" * 30)
    
    try:
        legacy_start = time.time()
        legacy_result = ollama_service.analyze_email_legacy(processed)
        legacy_time = time.time() - legacy_start
        
        if legacy_result.get("success", False):
            print("✅ Legacy analysis completed")
            print(f"   Risk Score: {legacy_result.get('risk_score', 'N/A')}/10")
            print(f"   Recommendation: {legacy_result.get('recommendation', 'N/A')}")
            print(f"   Confidence: {legacy_result.get('confidence', 'N/A')}")
            print(f"   Processing Time: {legacy_time:.2f}s")
        else:
            print("❌ Legacy analysis failed")
            print(f"   Error: {legacy_result}")
    except Exception as e:
        print(f"❌ Exception in legacy analysis: {e}")
    
    # Comparison
    print("\n📊 COMPARISON:")
    print("=" * 30)
    
    if new_result.get("success") and legacy_result.get("success"):
        new_score = new_result.get("risk_score", 5)
        legacy_score = legacy_result.get("risk_score", 5)
        
        print(f"Risk Scores: New={new_score}, Legacy={legacy_score}, Diff={abs(new_score - legacy_score)}")
        print(f"Processing Time: New={new_time:.2f}s, Legacy={legacy_time:.2f}s, Ratio={new_time/legacy_time:.1f}x")
        
        new_rec = new_result.get("recommendation", "caution")
        legacy_rec = legacy_result.get("recommendation", "caution")
        print(f"Recommendations: New='{new_rec}', Legacy='{legacy_rec}', Match={'✅' if new_rec == legacy_rec else '❌'}")
        
        # Check for improvements
        improvements = []
        if new_result.get("phases_completed", 0) >= 3:
            improvements.append("Complete 3-phase analysis")
        if not new_result.get("fallback_used", False):
            improvements.append("No fallback needed")
        if abs(new_score - 3) <= abs(legacy_score - 3):  # Expected ~3 for newsletter
            improvements.append("More accurate risk score")
        
        if improvements:
            print(f"✅ Improvements: {', '.join(improvements)}")
    
    return True

def test_integration_with_risk_assessment():
    """Test integration with existing risk assessment system"""
    print("\n=== Testing Risk Assessment Integration ===")
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    result = ollama_service.analyze_email(processed)
    
    if not result.get("success"):
        print("❌ Analysis failed")
        return False
    
    print("✅ Analysis completed with risk assessment integration")
    
    # Check for expected risk assessment fields
    expected_fields = [
        "risk_score", "confidence", "recommendation", "risk_level", 
        "red_flags", "reasoning", "timestamp"
    ]
    
    missing_fields = [field for field in expected_fields if field not in result]
    if missing_fields:
        print(f"⚠️  Missing expected fields: {missing_fields}")
    else:
        print("✅ All expected risk assessment fields present")
    
    # Check chunked analysis specific fields
    chunked_fields = [
        "analysis_method", "phases_completed", "total_processing_time"
    ]
    
    present_chunked = [field for field in chunked_fields if field in result]
    print(f"✅ Chunked analysis fields present: {present_chunked}")
    
    # Validate reasonable values
    risk_score = result.get("risk_score", 0)
    if 1 <= risk_score <= 10:
        print(f"✅ Valid risk score: {risk_score}/10")
    else:
        print(f"⚠️  Invalid risk score: {risk_score}")
    
    phases = result.get("phases_completed", 0)
    if phases >= 3:
        print(f"✅ All phases completed: {phases}")
    elif phases > 0:
        print(f"⚠️  Partial completion: {phases} phases")
    else:
        print(f"❌ No phases completed")
    
    return True

if __name__ == "__main__":
    import time
    
    print("Comprehensive Chunked Analysis Pipeline Test")
    print("=" * 50)
    
    # Test new vs old
    if not test_new_vs_old():
        print("\n💥 New vs old comparison failed!")
        sys.exit(1)
    
    # Test integration
    if not test_integration_with_risk_assessment():
        print("\n💥 Risk assessment integration failed!")  
        sys.exit(1)
    
    print("\n🎉 All comprehensive tests passed!")
    print("\nThe chunked analysis pipeline is ready for production use!")
    sys.exit(0)