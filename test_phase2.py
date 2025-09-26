#!/usr/bin/env python3
"""
Quick test script for Phase 2: Content Analysis
Tests the new chunked analysis pipeline Phase 2 implementation
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

def test_phase2_content():
    """Test Phase 2 content analysis with a sample email"""
    print("=== Testing Phase 2: Content Analysis ===")
    
    # Initialize services
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Test with corporate newsletter (should be low content risk)
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    print(f"Testing email: Corporate newsletter")
    print(f"Content: Company updates and meeting invitation")
    
    # Process email first
    print("\n1. Processing email...")
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print(f"❌ Email processing failed: {processed}")
        return False
    
    print(f"✅ Email processed successfully")
    
    # Run Phase 1 first (required for Phase 2 context)
    print("\n2. Running Phase 1 structural analysis (for context)...")
    structural_result = ollama_service._analyze_structure(processed)
    
    if not structural_result["success"]:
        print(f"❌ Phase 1 failed: {structural_result}")
        return False
    
    print(f"✅ Phase 1 completed")
    print(f"   Domain Assessment: {structural_result['domain_assessment']}")
    print(f"   Structural Risk: {structural_result['structural_risk']}/4")
    
    # Test Phase 2 content analysis
    print("\n3. Running Phase 2 content analysis...")
    try:
        content_result = ollama_service._analyze_content(processed, structural_result)
        
        if content_result["success"]:
            print("✅ Phase 2 completed successfully")
            print(f"   Content Risk: {content_result['content_risk']}/6")
            print(f"   URL Risk: {content_result['url_risk']}/4")
            print(f"   Request Type: {content_result['request_type']}")
            print(f"   Confidence: {content_result['confidence']}")
            print(f"   Processing Time: {content_result['processing_time']}s")
            
            if content_result.get("language_flags"):
                print(f"   Language Flags: {content_result['language_flags']}")
                
            if content_result.get("urgency_indicators"):
                print(f"   Urgency Indicators: {content_result['urgency_indicators']}")
            
            # Verify expected results for corporate newsletter
            expected_content_risk_range = (1, 3)  # Should be low content risk
            actual_content_risk = content_result['content_risk']
            
            if expected_content_risk_range[0] <= actual_content_risk <= expected_content_risk_range[1]:
                print(f"✅ Content risk {actual_content_risk} is in expected range {expected_content_risk_range}")
            else:
                print(f"⚠️  Content risk {actual_content_risk} is outside expected range {expected_content_risk_range}")
            
            # Check request type (should be 'none' for newsletter)
            if content_result['request_type'] in ['none', 'information']:
                print(f"✅ Request type '{content_result['request_type']}' is appropriate for newsletter")
            else:
                print(f"⚠️  Request type '{content_result['request_type']}' seems high for newsletter")
            
            return True
        else:
            print(f"❌ Phase 2 failed: {content_result}")
            return False
            
    except Exception as e:
        print(f"❌ Phase 2 exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_phases_1_and_2():
    """Test both Phase 1 and Phase 2 working together"""
    print("=== Testing Phase 1 + Phase 2 Integration ===")
    
    # Initialize services
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Test with corporate newsletter
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print(f"❌ Email processing failed")
        return False
    
    # Run both phases
    print("Running Phase 1...")
    structural_result = ollama_service._analyze_structure(processed)
    if not structural_result["success"]:
        print(f"❌ Phase 1 failed")
        return False
        
    print("Running Phase 2...")
    content_result = ollama_service._analyze_content(processed, structural_result)
    if not content_result["success"]:
        print(f"❌ Phase 2 failed")
        return False
    
    print("\n📊 COMBINED RESULTS:")
    print(f"   Structural Risk: {structural_result['structural_risk']}/4")
    print(f"   Content Risk: {content_result['content_risk']}/6")
    print(f"   Domain Assessment: {structural_result['domain_assessment']}")
    print(f"   Request Type: {content_result['request_type']}")
    print(f"   Total Processing Time: {structural_result['processing_time'] + content_result['processing_time']:.2f}s")
    
    # Simple risk combination (preview of Phase 3)
    combined_risk = min(10, structural_result['structural_risk'] + content_result['content_risk'])
    print(f"   Combined Risk Estimate: {combined_risk}/10")
    
    return True

if __name__ == "__main__":
    print("Phase 2 Content Analysis Test")
    print("=" * 40)
    
    # Test Phase 2 standalone
    if not test_phase2_content():
        print("\n💥 Phase 2 test failed!")
        sys.exit(1)
    
    print()
    
    # Test integration
    if not test_phases_1_and_2():
        print("\n💥 Phase integration test failed!")  
        sys.exit(1)
    
    print("\n🎉 All Phase 2 tests completed successfully!")
    sys.exit(0)