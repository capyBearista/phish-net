#!/usr/bin/env python3
"""
Quick test script for Phase 3: Intent Assessment and Full Pipeline
Tests the complete three-phase chunked analysis pipeline
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

def test_phase3_intent():
    """Test Phase 3 intent assessment with complete pipeline"""
    print("=== Testing Phase 3: Intent Assessment ===")
    
    # Initialize services
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Test with corporate newsletter (should be low risk overall)
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    print(f"Testing email: Corporate newsletter")
    print(f"Expected: Low risk (1-3), 'ignore' recommendation")
    
    # Process email
    print("\n1. Processing email...")
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print(f"❌ Email processing failed: {processed}")
        return False
    
    print(f"✅ Email processed successfully")
    print(f"   Sender Domain: {processed['metadata'].get('sender_domain')}")
    
    # Run Phase 1: Structural Analysis
    print("\n2. Running Phase 1: Structural Analysis...")
    structural_result = ollama_service._analyze_structure(processed)
    
    if not structural_result["success"]:
        print(f"❌ Phase 1 failed: {structural_result}")
        return False
    
    print(f"✅ Phase 1 completed - Structural Risk: {structural_result['structural_risk']}/4")
    print(f"   Domain Assessment: {structural_result['domain_assessment']}")
    
    # Run Phase 2: Content Analysis  
    print("\n3. Running Phase 2: Content Analysis...")
    content_result = ollama_service._analyze_content(processed, structural_result)
    
    if not content_result["success"]:
        print(f"❌ Phase 2 failed: {content_result}")
        return False
    
    print(f"✅ Phase 2 completed - Content Risk: {content_result['content_risk']}/6")
    print(f"   Request Type: {content_result['request_type']}")
    
    # Run Phase 3: Intent Assessment
    print("\n4. Running Phase 3: Intent Assessment...")
    try:
        intent_result = ollama_service._assess_intent(processed, structural_result, content_result)
        
        if intent_result["success"]:
            print("✅ Phase 3 completed successfully")
            print(f"   Final Risk Score: {intent_result['risk_score']}/10")
            print(f"   Recommendation: {intent_result['recommendation']}")
            print(f"   Confidence: {intent_result['confidence']}")
            print(f"   Domain Trust Applied: {intent_result['domain_trust_applied']}")
            print(f"   Processing Time: {intent_result['processing_time']}s")
            
            if intent_result.get("primary_concerns"):
                print(f"   Primary Concerns: {intent_result['primary_concerns']}")
            
            print(f"   Reasoning: {intent_result.get('reasoning', 'N/A')}")
            
            # Show phase synthesis
            synthesis = intent_result.get("phase_synthesis", {})
            if synthesis:
                print(f"\n📊 PHASE SYNTHESIS:")
                print(f"   Structural: {synthesis.get('structural_risk', 0)}/4")
                print(f"   Content: {synthesis.get('content_risk', 0)}/6") 
                print(f"   Trust Weight: {synthesis.get('trust_weight_applied', 0)}")
                print(f"   Total Time: {synthesis.get('total_processing_time', 0):.2f}s")
            
            # Verify expected results for corporate newsletter
            expected_risk_range = (1, 4)  # Should be low risk overall
            actual_risk = intent_result['risk_score']
            
            if expected_risk_range[0] <= actual_risk <= expected_risk_range[1]:
                print(f"✅ Final risk score {actual_risk} is in expected range {expected_risk_range}")
            else:
                print(f"⚠️  Final risk score {actual_risk} is outside expected range {expected_risk_range}")
            
            # Check recommendation  
            if intent_result['recommendation'] in ['ignore', 'caution']:
                print(f"✅ Recommendation '{intent_result['recommendation']}' is appropriate for newsletter")
            else:
                print(f"⚠️  Recommendation '{intent_result['recommendation']}' seems high for newsletter")
            
            return True
        else:
            print(f"❌ Phase 3 failed: {intent_result}")
            return False
            
    except Exception as e:
        print(f"❌ Phase 3 exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_complete_pipeline():
    """Test the complete three-phase pipeline integration"""
    print("=== Testing Complete Three-Phase Pipeline ===")
    
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        return False
    
    print("🔄 Running complete pipeline...")
    
    # Run all three phases in sequence  
    structural_result = ollama_service._analyze_structure(processed)
    if not structural_result["success"]:
        print(f"❌ Pipeline failed at Phase 1")
        return False
    
    content_result = ollama_service._analyze_content(processed, structural_result)
    if not content_result["success"]:
        print(f"❌ Pipeline failed at Phase 2")
        return False
    
    intent_result = ollama_service._assess_intent(processed, structural_result, content_result)
    if not intent_result["success"]:
        print(f"❌ Pipeline failed at Phase 3")
        return False
    
    # Show comprehensive results
    print("\n🎯 COMPLETE PIPELINE RESULTS:")
    print("=" * 40)
    print(f"Email Type: Corporate Newsletter")
    print(f"Sender: {processed['headers'].get('from', 'Unknown')}")
    print(f"Domain: {processed['metadata'].get('sender_domain', 'Unknown')}")
    
    print(f"\n📋 PHASE BREAKDOWN:")
    print(f"Phase 1 - Structural: {structural_result['structural_risk']}/4 ({structural_result['domain_assessment']})")
    print(f"Phase 2 - Content: {content_result['content_risk']}/6 ({content_result['request_type']})")
    print(f"Phase 3 - Intent: {intent_result['risk_score']}/10 ({intent_result['recommendation']})")
    
    synthesis = intent_result.get("phase_synthesis", {})
    total_time = synthesis.get("total_processing_time", 0)
    print(f"\n⏱️  PERFORMANCE:")
    print(f"Total Processing Time: {total_time:.2f}s")
    print(f"Average per Phase: {total_time/3:.2f}s")
    
    print(f"\n🔍 FINAL ASSESSMENT:")
    print(f"Risk Score: {intent_result['risk_score']}/10")
    print(f"Recommendation: {intent_result['recommendation'].upper()}")
    print(f"Confidence: {intent_result['confidence'].upper()}")
    if intent_result.get('primary_concerns'):
        print(f"Key Concerns: {', '.join(intent_result['primary_concerns'])}")
    
    print(f"\n💭 REASONING:")
    print(f"{intent_result.get('reasoning', 'No reasoning provided')}")
    
    return True

if __name__ == "__main__":
    print("Phase 3 Intent Assessment & Complete Pipeline Test")
    print("=" * 50)
    
    # Test Phase 3 specifically
    if not test_phase3_intent():
        print("\n💥 Phase 3 test failed!")
        sys.exit(1)
    
    print()
    
    # Test complete pipeline integration  
    if not test_complete_pipeline():
        print("\n💥 Complete pipeline test failed!")
        sys.exit(1)
    
    print("\n🎉 All tests completed successfully!")
    print("\nThe three-phase chunked analysis pipeline is working correctly!")
    sys.exit(0)