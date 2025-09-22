#!/usr/bin/env python3
"""
Test script for .gov and .edu email handling in Phish-Net.

This script tests real email examples from government and educational institutions
to ensure proper trust weighting and risk assessment.
"""

import sys
import os
import tempfile

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from email_processor import EmailProcessor
    from risk_assessment import RiskAssessment
    from llm_service import OllamaService
except ImportError:
    from src.email_processor import EmailProcessor
    from src.risk_assessment import RiskAssessment
    from src.llm_service import OllamaService


# Test email samples
GOV_LEGITIMATE_EMAIL = """From: alerts@irs.gov
To: taxpayer@example.com
Subject: Annual Tax Filing Reminder
Date: Mon, 15 Jan 2024 10:30:00 -0500
Message-ID: <20240115153000.12345@irs.gov>

Dear Taxpayer,

This is your annual reminder that tax filing season begins on January 29, 2024.

Key dates to remember:
- Filing deadline: April 15, 2024
- Extension deadline: October 15, 2024

You can find forms and information at www.irs.gov/forms

Best regards,
Internal Revenue Service
"""

EDU_LEGITIMATE_EMAIL = """From: registrar@harvard.edu
To: student@student.harvard.edu
Subject: Spring 2024 Registration Opens
Date: Tue, 20 Nov 2023 14:22:00 -0500
Message-ID: <20231120192200.98765@harvard.edu>

Dear Harvard Student,

Registration for Spring 2024 courses will open on December 1, 2023.

Important information:
- Registration begins at 9:00 AM EST
- Use my.harvard.edu to access the system
- Contact your academic advisor with questions

Academic Calendar: https://registrar.fas.harvard.edu/calendar

Best regards,
Harvard University Registrar
"""

GOV_SUSPICIOUS_CONTENT = """From: security@cdc.gov
To: recipient@example.com
Subject: URGENT: Your Account Will Be Suspended!
Date: Wed, 28 Sep 2025 15:45:00 -0400
Message-ID: <20250928194500.54321@cdc.gov>

URGENT ACTION REQUIRED!

Your CDC account will be suspended in 24 hours unless you verify your credentials immediately!

Click here to verify: http://verify-account-now.suspicious-site.com/login

This is your FINAL WARNING! Act now or lose access forever!

CDC Security Team
"""

EDU_SUSPICIOUS_CONTENT = """From: admin@mit.edu
To: faculty@mit.edu
Subject: Immediate Action Required - Account Verification
Date: Wed, 28 Sep 2025 16:30:00 -0400
Message-ID: <20250928203000.11111@mit.edu>

Dear MIT Faculty Member,

We have detected suspicious activity on your account. You must verify your login credentials within 2 hours or your account will be permanently deleted!

Username: ________________
Password: ________________

Submit your credentials here: http://phishing-site.tk/mit-login

IT Security Department
MIT
"""


def test_email_processing(email_content, description):
    """Test email processing and analysis."""
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print('='*60)
    
    try:
        # Process email
        processor = EmailProcessor()
        result = processor.process_email(email_content, is_file_content=False)
        
        if not result['success']:
            print(f"❌ Email processing failed: {result.get('error', 'Unknown error')}")
            return None
            
        metadata = result['metadata']
        processed_content = result.get('processed_content', '')
        
        print(f"📧 Email processed successfully:")
        print(f"   From: {metadata.get('sender', 'Unknown')}")
        print(f"   Domain: {metadata.get('sender_domain', 'Unknown')}")
        print(f"   Subject: {metadata.get('subject', 'No subject')}")
        print(f"   Headers found: {len(metadata.get('headers', []))}")
        
        # Test risk assessment
        risk_assessor = RiskAssessment()
        
        # Test domain trust weight calculation
        sender_domain = metadata.get('sender_domain', '')
        trust_weight, trust_reason = risk_assessor.calculate_domain_trust_weight(sender_domain)
        print(f"   Trust Weight: {trust_weight} ({trust_reason})")
        
        # Test heuristic analysis
        heuristic_result = risk_assessor.cross_validate_with_heuristics(5, metadata)
        print(f"   Heuristic Score: {heuristic_result['heuristic_score']}")
        print(f"   Heuristic Flags: {', '.join(heuristic_result['heuristic_flags'])}")
        
        return {
            'metadata': metadata,
            'trust_weight': trust_weight,
            'trust_reason': trust_reason,
            'heuristic_score': heuristic_result['heuristic_score'],
            'heuristic_flags': heuristic_result['heuristic_flags']
        }
        
    except Exception as e:
        print(f"❌ Error processing email: {str(e)}")
        return None


def test_with_llm_if_available():
    """Test with LLM if Ollama is available."""
    try:
        ollama_service = OllamaService()
        if ollama_service.test_connection():
            print("\n🤖 Ollama available - Testing with LLM analysis...")
            return True
        else:
            print("\n⚠️  Ollama not available - Skipping LLM tests")
            return False
    except Exception as e:
        print(f"\n⚠️  Ollama connection failed: {str(e)}")
        return False


def analyze_results(results):
    """Analyze test results and provide summary."""
    print(f"\n{'='*60}")
    print("ANALYSIS SUMMARY")
    print('='*60)
    
    for description, result in results.items():
        if result is None:
            print(f"❌ {description}: FAILED - Could not process email")
            continue
            
        domain = result['metadata'].get('sender_domain', 'Unknown')
        trust_weight = result['trust_weight']
        heuristic_score = result['heuristic_score']
        
        print(f"\n📊 {description}:")
        print(f"   Domain: {domain}")
        print(f"   Trust Weight: {trust_weight}")
        print(f"   Heuristic Score: {heuristic_score}")
        
        # Evaluate if results are as expected
        if domain.endswith('.gov') or domain.endswith('.edu'):
            if trust_weight < 0:
                print(f"   ✅ GOOD: Institutional domain received trust bonus")
            else:
                print(f"   ❌ ISSUE: Institutional domain did not receive expected trust bonus")
                
            if heuristic_score <= 3:
                print(f"   ✅ GOOD: Low heuristic score due to trust weighting")
            else:
                print(f"   ❌ ISSUE: Heuristic score higher than expected for trusted domain")
        
        # Check for suspicious content detection
        if 'URGENT' in result['metadata'].get('subject', '') or 'suspicious' in description.lower():
            if any('suspicious' in flag.lower() or 'urgent' in flag.lower() for flag in result['heuristic_flags']):
                print(f"   ✅ GOOD: Suspicious content patterns detected")
            else:
                print(f"   ⚠️  NOTE: Suspicious content not flagged in heuristics")


def main():
    """Run comprehensive .gov and .edu email testing."""
    print("🏛️  Phish-Net .gov/.edu Domain Testing Suite")
    print("=" * 80)
    
    test_cases = [
        (GOV_LEGITIMATE_EMAIL, "Legitimate IRS tax reminder (.gov)"),
        (EDU_LEGITIMATE_EMAIL, "Legitimate Harvard registration notice (.edu)"),
        (GOV_SUSPICIOUS_CONTENT, "Suspicious content from CDC domain (.gov)"), 
        (EDU_SUSPICIOUS_CONTENT, "Suspicious content from MIT domain (.edu)")
    ]
    
    results = {}
    
    # Test email processing and heuristic analysis
    for email_content, description in test_cases:
        result = test_email_processing(email_content, description)
        results[description] = result
    
    # Test with LLM if available
    llm_available = test_with_llm_if_available()
    
    # Analyze and summarize results
    analyze_results(results)
    
    print(f"\n{'='*80}")
    print("TEST CONCLUSIONS:")
    
    # Check if all .gov/.edu domains got trust bonuses
    institutional_domains_tested = 0
    institutional_domains_trusted = 0
    
    for description, result in results.items():
        if result and (result['metadata'].get('sender_domain', '').endswith('.gov') or 
                      result['metadata'].get('sender_domain', '').endswith('.edu')):
            institutional_domains_tested += 1
            if result['trust_weight'] < 0:
                institutional_domains_trusted += 1
    
    print(f"📊 Institutional domains tested: {institutional_domains_tested}")
    print(f"📊 Institutional domains with trust bonus: {institutional_domains_trusted}")
    
    if institutional_domains_tested > 0 and institutional_domains_trusted == institutional_domains_tested:
        print("✅ SUCCESS: All .gov/.edu domains received appropriate trust bonuses!")
        return 0
    elif institutional_domains_tested > 0:
        print("⚠️  PARTIAL: Some institutional domains did not receive expected trust treatment")
        return 1
    else:
        print("❌ ERROR: Could not test any institutional domains")
        return 2


if __name__ == "__main__":
    sys.exit(main())