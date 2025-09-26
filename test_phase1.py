#!/usr/bin/env python3
"""
Quick test script for Phase 1: Structural Analysis
Tests the new chunked analysis pipeline Phase 1 implementation
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

def test_phase1_structural():
    """Test Phase 1 structural analysis with a sample email"""
    print("=== Testing Phase 1: Structural Analysis ===")
    
    # Initialize services
    email_processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Test with corporate newsletter (should be low risk)
    test_email = LEGITIMATE_EMAILS["corporate_newsletter"]["content"]
    print(f"Testing email: Corporate newsletter")
    print(f"From: newsletters@company.com")
    
    # Process email first
    print("\n1. Processing email...")
    processed = email_processor.process_email(test_email)
    
    if not processed["success"]:
        print(f"❌ Email processing failed: {processed}")
        return False
    
    print(f"✅ Email processed successfully")
    print(f"   Format: {processed['format']}")
    print(f"   Sender Domain: {processed['metadata'].get('sender_domain', 'Unknown')}")
    
    # Test Phase 1 structural analysis
    print("\n2. Running Phase 1 structural analysis...")
    try:
        structural_result = ollama_service._analyze_structure(processed)
        
        if structural_result["success"]:
            print("✅ Phase 1 completed successfully")
            print(f"   Structural Risk: {structural_result['structural_risk']}/4")
            print(f"   Format Quality: {structural_result['format_quality']}")
            print(f"   Domain Assessment: {structural_result['domain_assessment']}")
            print(f"   Confidence: {structural_result['confidence']}")
            print(f"   Processing Time: {structural_result['processing_time']}s")
            
            if structural_result.get("header_issues"):
                print(f"   Header Issues: {structural_result['header_issues']}")
            
            # Verify expected results for corporate newsletter
            expected_risk_range = (1, 3)  # Should be low risk
            actual_risk = structural_result['structural_risk']
            
            if expected_risk_range[0] <= actual_risk <= expected_risk_range[1]:
                print(f"✅ Risk score {actual_risk} is in expected range {expected_risk_range}")
            else:
                print(f"⚠️  Risk score {actual_risk} is outside expected range {expected_risk_range}")
            
            return True
        else:
            print(f"❌ Phase 1 failed: {structural_result}")
            return False
            
    except Exception as e:
        print(f"❌ Phase 1 exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_connection():
    """Test Ollama connection before running analysis"""
    print("=== Testing Ollama Connection ===")
    
    ollama_service = OllamaService()
    
    try:
        # Simple health check
        import requests
        response = requests.get(f"{ollama_service.base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            print("✅ Ollama is running and accessible")
            
            # Check if phi4-mini model is available
            models = response.json().get("models", [])
            model_names = [model["name"] for model in models]
            
            if any("phi4-mini" in name for name in model_names):
                print("✅ phi4-mini model is available")
                return True
            else:
                print(f"⚠️  phi4-mini model not found. Available models: {model_names}")
                return False
        else:
            print(f"❌ Ollama returned HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Cannot connect to Ollama: {e}")
        print("   Make sure Ollama is running with: ollama serve")
        return False

if __name__ == "__main__":
    print("Phase 1 Structural Analysis Test")
    print("=" * 40)
    
    # Test connection first
    if not test_connection():
        print("\nSkipping Phase 1 test due to connection issues")
        sys.exit(1)
    
    print()
    
    # Run Phase 1 test
    if test_phase1_structural():
        print("\n🎉 Phase 1 test completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 Phase 1 test failed!")
        sys.exit(1)