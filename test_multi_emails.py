#!/usr/bin/env python3
"""
Multi-email test for chunked analysis pipeline
Tests various email types to verify accuracy and consistency
"""

import sys
import os
import time
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

def test_multiple_emails():
    """Test chunked pipeline with various email types"""
    print("=== Multi-Email Chunked Pipeline Test ===")
    print("Testing various email types for accuracy and consistency\n")
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Test emails with expected ranges
    test_cases = [
        ("corporate_newsletter", "Corporate Newsletter", (1, 4)),
        ("password_reset_legitimate", "GitHub Password Reset", (1, 3)),
        ("meeting_invitation", "Meeting Invitation", (1, 3)),
    ]
    
    results = []
    total_time = 0
    
    for email_key, description, expected_range in test_cases:
        print(f"🔍 Testing: {description}")
        print("-" * 40)
        
        # Get test email
        if email_key not in LEGITIMATE_EMAILS:
            print(f"⚠️  Email '{email_key}' not found, skipping")
            continue
            
        test_email = LEGITIMATE_EMAILS[email_key]["content"]
        processed = email_processor.process_email(test_email)
        
        if not processed["success"]:
            print(f"❌ Email processing failed: {processed}")
            continue
        
        # Extract sender info
        sender = processed['headers'].get('from', 'Unknown')
        domain = processed['metadata'].get('sender_domain', 'Unknown')
        print(f"   From: {sender}")
        print(f"   Domain: {domain}")
        
        # Run chunked analysis
        try:
            start_time = time.time()
            result = ollama_service.analyze_email(processed)
            end_time = time.time()
            
            processing_time = end_time - start_time
            total_time += processing_time
            
            if result.get("success"):
                risk_score = result.get("risk_score", 0)
                recommendation = result.get("recommendation", {})
                method = result.get("analysis_method", "unknown")
                phases = result.get("phases_completed", 0)
                
                # Extract recommendation action if it's a dict
                if isinstance(recommendation, dict):
                    rec_action = recommendation.get("action", "unknown")
                else:
                    rec_action = str(recommendation)
                
                print(f"   ✅ Analysis completed")
                print(f"      Risk Score: {risk_score}/10")
                print(f"      Recommendation: {rec_action}")
                print(f"      Method: {method}")
                print(f"      Phases: {phases}")
                print(f"      Time: {processing_time:.2f}s")
                
                # Check if score is in expected range
                in_range = expected_range[0] <= risk_score <= expected_range[1]
                range_status = "✅" if in_range else "⚠️"
                print(f"      Expected Range: {expected_range} {range_status}")
                
                # Check for fallback usage
                if result.get("fallback_used"):
                    print(f"      ⚠️  Fallback used: {result.get('fallback_reason', 'Unknown')}")
                
                results.append({
                    "email": description,
                    "risk_score": risk_score,
                    "recommendation": rec_action,
                    "processing_time": processing_time,
                    "in_expected_range": in_range,
                    "phases_completed": phases,
                    "fallback_used": result.get("fallback_used", False)
                })
                
            else:
                print(f"   ❌ Analysis failed: {result}")
                results.append({
                    "email": description,
                    "failed": True,
                    "error": result
                })
                
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            results.append({
                "email": description,
                "failed": True,
                "exception": str(e)
            })
        
        print()  # Add spacing between tests
    
    # Summary
    print("📊 SUMMARY RESULTS")
    print("=" * 50)
    
    successful = [r for r in results if not r.get("failed", False)]
    failed = [r for r in results if r.get("failed", False)]
    
    print(f"Successful analyses: {len(successful)}/{len(results)}")
    print(f"Failed analyses: {len(failed)}")
    print(f"Total processing time: {total_time:.2f}s")
    
    if successful:
        avg_time = total_time / len(successful)
        print(f"Average time per email: {avg_time:.2f}s")
        
        # Accuracy check
        in_range_count = sum(1 for r in successful if r.get("in_expected_range", False))
        print(f"Scores in expected range: {in_range_count}/{len(successful)} ({in_range_count/len(successful)*100:.1f}%)")
        
        # Recommendation appropriateness
        ignore_count = sum(1 for r in successful if r.get("recommendation") == "ignore")
        print(f"Low-risk emails with 'ignore' recommendation: {ignore_count}/{len(successful)}")
        
        # Fallback usage
        fallback_count = sum(1 for r in successful if r.get("fallback_used", False))
        print(f"Fallback usage: {fallback_count}/{len(successful)} ({fallback_count/len(successful)*100:.1f}%)")
        
        # Phase completion
        full_phases = sum(1 for r in successful if r.get("phases_completed", 0) >= 3)
        print(f"Complete 3-phase analyses: {full_phases}/{len(successful)} ({full_phases/len(successful)*100:.1f}%)")
    
    if failed:
        print(f"\n❌ FAILED ANALYSES:")
        for fail in failed:
            print(f"   {fail['email']}: {fail.get('error', fail.get('exception', 'Unknown error'))}")
    
    # Overall assessment
    success_rate = len(successful) / len(results) * 100 if results else 0
    
    print(f"\n🎯 OVERALL ASSESSMENT")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 90 and in_range_count/len(successful) >= 0.8 and fallback_count/len(successful) <= 0.2:
        print("✅ CHUNKED PIPELINE READY FOR PRODUCTION")
        return True
    elif success_rate >= 70:
        print("⚠️  CHUNKED PIPELINE FUNCTIONAL BUT NEEDS TUNING")
        return True
    else:
        print("❌ CHUNKED PIPELINE NEEDS MORE WORK")
        return False

if __name__ == "__main__":
    print("Multi-Email Chunked Analysis Pipeline Test")
    print("=" * 50)
    
    success = test_multiple_emails()
    
    if success:
        print("\n🎉 Multi-email test completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 Multi-email test revealed issues!")
        sys.exit(1)