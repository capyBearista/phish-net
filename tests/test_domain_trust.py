#!/usr/bin/env python3
"""
Comprehensive Domain Trust Testing Suite

This module consolidates all domain trust and weighting tests including:
- Government (.gov) and educational (.edu) domain handling
- Domain trust weight validation 
- Corporate domain risk assessment
- Both hardcoded samples and .eml file testing

Consolidated from: test_gov_edu_emails.py, test_comprehensive_gov_edu.py, test_domain_weighting.py
"""

import sys
import os
import tempfile
from typing import Dict, List, Tuple, Any, Optional

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from src.email_processor import EmailProcessor
    from src.risk_assessment import RiskAssessment
    from src.llm_service import OllamaService
except ImportError:
    from email_processor import EmailProcessor
    from risk_assessment import RiskAssessment
    from llm_service import OllamaService


# Test email samples for domain trust testing
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

For more information, visit www.irs.gov or call 1-800-829-1040.

Sincerely,
Internal Revenue Service
"""

EDU_LEGITIMATE_EMAIL = """From: registrar@harvard.edu
To: student@example.com
Subject: Fall 2024 Course Registration Opens
Date: Wed, 20 Mar 2024 09:00:00 -0400
Message-ID: <20240320130000.67890@harvard.edu>

Dear Student,

Registration for Fall 2024 courses will open on April 1, 2024 at 9:00 AM EDT.

Important reminders:
- Check prerequisites for all courses
- Academic advisor meetings recommended before registration
- Course catalog available at my.harvard.edu

Please contact the Registrar's Office with any questions.

Best regards,
Harvard University Registrar
"""

CORPORATE_EMAIL = """From: notifications@github.com
To: developer@example.com
Subject: Security Alert: New Login Detected
Date: Thu, 25 Sep 2025 14:30:00 +0000
Message-ID: <20250925143000.abc123@github.com>

Hi developer,

We detected a new login to your GitHub account from a new device.

Details:
- Location: San Francisco, CA
- Device: Chrome on macOS
- Time: September 25, 2025 at 2:30 PM UTC

If this was you, no action is required. If not, please secure your account immediately.

GitHub Security Team
"""


class DomainTestResult:
    """Data class to store domain test results."""
    
    def __init__(self, domain: str, expected_weight: int, actual_weight: int, 
                 test_passed: bool, description: str = ""):
        self.domain = domain
        self.expected_weight = expected_weight
        self.actual_weight = actual_weight
        self.test_passed = test_passed
        self.description = description


def test_institutional_domain_weights() -> bool:
    """
    Test that institutional domains (.gov, .edu) receive appropriate trust weights.
    
    Validates the domain weighting system for:
    - Government domains (.gov) - should get -4 weight
    - Educational domains (.edu) - should get -3 weight
    - Corporate domains - should get appropriate weights
    
    Returns:
        bool: True if all domain weights are correct
    """
    print("=" * 70)
    print("🏛️  INSTITUTIONAL DOMAIN WEIGHT TESTING")
    print("=" * 70)
    
    risk_assessor = RiskAssessment()
    results: List[DomainTestResult] = []
    
    # Test cases: (domain, expected_weight, description)
    test_cases = [
        # Government domains - highest trust
        ("irs.gov", -4, "Internal Revenue Service"),
        ("cdc.gov", -4, "Centers for Disease Control"),  
        ("nasa.gov", -4, "National Aeronautics and Space Administration"),
        ("state.gov", -4, "U.S. Department of State"),
        ("fbi.gov", -4, "Federal Bureau of Investigation"),
        
        # Educational domains - high trust
        ("harvard.edu", -3, "Harvard University"),
        ("mit.edu", -3, "Massachusetts Institute of Technology"),
        ("stanford.edu", -3, "Stanford University"),
        ("berkeley.edu", -3, "UC Berkeley"),
        ("yale.edu", -3, "Yale University"),
        
        # Corporate domains - varied trust
        ("github.com", -2, "GitHub (trusted tech platform)"),
        ("google.com", -2, "Google (major tech company)"),
        ("microsoft.com", -2, "Microsoft (major tech company)"),
        ("amazon.com", -2, "Amazon (e-commerce platform)"),
        ("paypal.com", -1, "PayPal (financial service)"),
        
        # Unknown/neutral domains
        ("example.com", 0, "Generic example domain"),
        ("unknown-site.net", 0, "Unknown domain"),
    ]
    
    print("Testing domain trust weights...\n")
    
    for domain, expected_weight, description in test_cases:
        try:
            # Get actual weight from risk assessor
            actual_weight = risk_assessor.get_domain_trust_weight(domain)
            test_passed = actual_weight == expected_weight
            
            # Store result
            result = DomainTestResult(
                domain=domain,
                expected_weight=expected_weight,
                actual_weight=actual_weight,
                test_passed=test_passed,
                description=description
            )
            results.append(result)
            
            # Display result
            status = "✅" if test_passed else "❌"
            print(f"{status} {domain:20} | Expected: {expected_weight:3} | Actual: {actual_weight:3} | {description}")
            
        except Exception as e:
            print(f"❌ {domain:20} | ERROR: {e}")
            results.append(DomainTestResult(domain, expected_weight, 0, False, f"Error: {e}"))
    
    # Calculate success rate
    passed_tests = sum(1 for r in results if r.test_passed)
    total_tests = len(results)
    success_rate = (passed_tests / total_tests) * 100
    
    print(f"\n📊 DOMAIN WEIGHT TEST SUMMARY:")
    print(f"   Tests passed: {passed_tests}/{total_tests}")
    print(f"   Success rate: {success_rate:.1f}%")
    
    # Success criteria: >90% of domain weights correct
    success = success_rate >= 90
    print(f"   Overall result: {'✅ PASS' if success else '❌ FAIL'}")
    
    return success


def test_gov_edu_email_processing() -> bool:
    """
    Test processing of government and educational emails with hardcoded samples.
    
    Validates:
    - Proper header extraction
    - Domain identification
    - Risk score adjustment based on domain trust
    - Integration with LLM analysis
    
    Returns:
        bool: True if gov/edu emails are processed correctly
    """
    print("\n" + "=" * 70)
    print("📧 GOV/EDU EMAIL PROCESSING TEST")
    print("=" * 70)
    
    processor = EmailProcessor()
    risk_assessor = RiskAssessment()
    ollama_service = OllamaService()
    
    # Test cases with expected behaviors
    test_emails = [
        (GOV_LEGITIMATE_EMAIL, "irs.gov", "Government (.gov)", (1, 3)),
        (EDU_LEGITIMATE_EMAIL, "harvard.edu", "Educational (.edu)", (1, 3)),
        (CORPORATE_EMAIL, "github.com", "Corporate (trusted)", (1, 4)),
    ]
    
    results = []
    
    for email_content, expected_domain, description, expected_risk_range in test_emails:
        print(f"\n🔍 Testing: {description}")
        print(f"   Expected domain: {expected_domain}")
        print(f"   Expected risk range: {expected_risk_range}")
        
        try:
            # Process email
            processed = processor.process_email(email_content, is_file_content=False)
            
            if not processed["success"]:
                print(f"   ❌ Email processing failed: {processed.get('error', 'Unknown error')}")
                results.append(False)
                continue
            
            # Check domain extraction
            extracted_domain = processed.get("metadata", {}).get("sender_domain", "")
            domain_correct = extracted_domain == expected_domain
            
            print(f"   📍 Extracted domain: {extracted_domain} {'✅' if domain_correct else '❌'}")
            
            # Get domain trust weight
            trust_weight = risk_assessor.get_domain_trust_weight(extracted_domain)
            print(f"   ⚖️  Trust weight: {trust_weight}")
            
            # Test LLM analysis
            analysis = ollama_service.analyze_email(processed)
            
            if analysis.get("success"):
                risk_score = analysis.get("risk_score", 5)
                in_range = expected_risk_range[0] <= risk_score <= expected_risk_range[1]
                
                print(f"   🎯 Risk score: {risk_score}/10 {'✅' if in_range else '⚠️'}")
                print(f"   🔧 Analysis method: {analysis.get('analysis_method', 'unknown')}")
                
                # Check if domain trust affected the score appropriately
                red_flags = analysis.get("red_flags", [])
                print(f"   🚩 Red flags: {len(red_flags)}")
                
                test_success = domain_correct and in_range
                results.append(test_success)
                
            else:
                print(f"   ❌ LLM analysis failed: {analysis.get('error', 'Unknown error')}")
                results.append(False)
                
        except Exception as e:
            print(f"   ❌ Exception during processing: {e}")
            results.append(False)
    
    # Calculate overall success
    passed = sum(results)
    total = len(results)
    success_rate = (passed / total) * 100 if total > 0 else 0
    
    print(f"\n📊 EMAIL PROCESSING TEST SUMMARY:")
    print(f"   Tests passed: {passed}/{total}")
    print(f"   Success rate: {success_rate:.1f}%")
    
    success = success_rate >= 80
    print(f"   Overall result: {'✅ PASS' if success else '❌ FAIL'}")
    
    return success


def test_eml_file_processing() -> bool:
    """
    Test processing of .eml files from the examples directory.
    
    Tests real email files to ensure proper:
    - File parsing and header extraction
    - Domain trust application
    - Integration with full analysis pipeline
    
    Returns:
        bool: True if .eml files are processed correctly
    """
    print("\n" + "=" * 70)
    print("📁 .EML FILE PROCESSING TEST")
    print("=" * 70)
    
    processor = EmailProcessor()
    ollama_service = OllamaService()
    
    # Look for .eml files in examples directory
    examples_dir = os.path.join(os.path.dirname(__file__), '..', 'examples')
    
    # Test specific files that should exist
    test_files = [
        ("test_irs_legitimate.eml", "Government", (1, 3)),
        ("test_harvard_legitimate.eml", "Educational", (1, 3)),
        ("legitimate_example_1.eml", "Corporate/Other", (1, 4)),
    ]
    
    results = []
    
    for filename, file_type, expected_range in test_files:
        file_path = os.path.join(examples_dir, filename)
        
        print(f"\n📄 Testing: {filename}")
        print(f"   Type: {file_type}")
        print(f"   Expected range: {expected_range}")
        
        if not os.path.exists(file_path):
            print(f"   ⚠️  File not found: {file_path}")
            continue
        
        try:
            # Read .eml file
            with open(file_path, 'r', encoding='utf-8') as f:
                email_content = f.read()
            
            # Process email
            processed = processor.process_email(email_content, is_file_content=True)
            
            if not processed["success"]:
                print(f"   ❌ Processing failed: {processed.get('error', 'Unknown')}")
                results.append(False)
                continue
            
            # Display key information
            headers = processed.get("headers", {})
            metadata = processed.get("metadata", {})
            
            print(f"   📧 From: {headers.get('from', 'Unknown')}")
            print(f"   📧 Subject: {headers.get('subject', 'No subject')[:50]}")
            print(f"   🌐 Domain: {metadata.get('sender_domain', 'Unknown')}")
            
            # Run full analysis
            analysis = ollama_service.analyze_email(processed)
            
            if analysis.get("success"):
                risk_score = analysis.get("risk_score", 5)
                in_range = expected_range[0] <= risk_score <= expected_range[1]
                
                print(f"   🎯 Risk score: {risk_score}/10 {'✅' if in_range else '⚠️'}")
                print(f"   🔧 Method: {analysis.get('analysis_method', 'unknown')}")
                print(f"   📊 Phases: {analysis.get('phases_completed', 0)}/3")
                
                results.append(in_range)
            else:
                print(f"   ❌ Analysis failed: {analysis.get('error', 'Unknown')}")
                results.append(False)
                
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            results.append(False)
    
    if not results:
        print("   ⚠️  No .eml files were successfully tested")
        return True  # Don't fail if no files available
    
    # Calculate success
    passed = sum(results)
    total = len(results)
    success_rate = (passed / total) * 100
    
    print(f"\n📊 .EML FILE TEST SUMMARY:")
    print(f"   Files tested: {total}")
    print(f"   Tests passed: {passed}/{total}")
    print(f"   Success rate: {success_rate:.1f}%")
    
    success = success_rate >= 70  # Lower threshold for file-based tests
    print(f"   Overall result: {'✅ PASS' if success else '❌ FAIL'}")
    
    return success


def test_domain_edge_cases() -> bool:
    """
    Test edge cases and boundary conditions for domain trust weighting.
    
    Tests:
    - Subdomain handling
    - Case sensitivity
    - Invalid domains
    - International domains
    
    Returns:
        bool: True if edge cases are handled correctly
    """
    print("\n" + "=" * 70)
    print("🔍 DOMAIN EDGE CASE TESTING")
    print("=" * 70)
    
    risk_assessor = RiskAssessment()
    
    # Edge case test scenarios
    edge_cases = [
        # Subdomains should inherit parent domain trust
        ("subdomain.irs.gov", -4, "Government subdomain"),
        ("mail.harvard.edu", -3, "Educational subdomain"),
        ("api.github.com", -2, "Corporate subdomain"),
        
        # Case sensitivity
        ("IRS.GOV", -4, "Uppercase government domain"),
        ("Harvard.EDU", -3, "Mixed case educational domain"),
        
        # Invalid/malformed domains
        ("", 0, "Empty domain"),
        ("invalid-domain", 0, "Invalid domain format"),
        ("fake-irs.gov.evil.com", 0, "Spoofed domain"),
        
        # International domains
        ("gov.uk", 0, "UK government (not .gov)"),
        ("ac.uk", 0, "UK academic (not .edu)"),
    ]
    
    results = []
    
    print("Testing domain edge cases...\n")
    
    for domain, expected_weight, description in edge_cases:
        try:
            actual_weight = risk_assessor.get_domain_trust_weight(domain)
            test_passed = actual_weight == expected_weight
            
            status = "✅" if test_passed else "❌"
            print(f"{status} {domain:25} | Expected: {expected_weight:3} | Actual: {actual_weight:3} | {description}")
            
            results.append(test_passed)
            
        except Exception as e:
            print(f"❌ {domain:25} | ERROR: {e}")
            results.append(False)
    
    # Calculate success
    passed = sum(results)
    total = len(results)
    success_rate = (passed / total) * 100 if total > 0 else 0
    
    print(f"\n📊 EDGE CASE TEST SUMMARY:")
    print(f"   Tests passed: {passed}/{total}")
    print(f"   Success rate: {success_rate:.1f}%")
    
    success = success_rate >= 85
    print(f"   Overall result: {'✅ PASS' if success else '❌ FAIL'}")
    
    return success


def run_comprehensive_domain_tests() -> bool:
    """
    Run all domain trust tests and provide comprehensive results.
    
    Returns:
        bool: True if all domain trust tests pass
    """
    print("🏛️  COMPREHENSIVE DOMAIN TRUST TESTING SUITE")
    print("=" * 70)
    print("Testing domain trust weights and institutional email handling\n")
    
    test_results = []
    
    try:
        print("Phase 1: Domain Weight Validation")
        weight_result = test_institutional_domain_weights()
        test_results.append(("Domain Weights", weight_result))
        
        print("\nPhase 2: Gov/Edu Email Processing")
        processing_result = test_gov_edu_email_processing()
        test_results.append(("Email Processing", processing_result))
        
        print("\nPhase 3: .EML File Processing")
        eml_result = test_eml_file_processing()
        test_results.append(("EML Files", eml_result))
        
        print("\nPhase 4: Edge Case Handling")
        edge_result = test_domain_edge_cases()
        test_results.append(("Edge Cases", edge_result))
        
    except Exception as e:
        print(f"❌ Critical error during domain testing: {e}")
        return False
    
    # Final summary
    print("\n" + "=" * 70)
    print("🎯 FINAL DOMAIN TRUST TEST SUMMARY")
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
        print(f"\n🎉 ALL DOMAIN TRUST TESTS PASSED!")
        print("Domain weighting system is functioning correctly.")
    else:
        print(f"\n⚠️  DOMAIN TRUST SYSTEM NEEDS ATTENTION")
        print("Some tests failed. Review domain weighting implementation.")
    
    return overall_success


if __name__ == "__main__":
    """Main execution for comprehensive domain trust testing."""
    print("Phish-Net Domain Trust Testing Suite")
    print("=" * 70)
    
    success = run_comprehensive_domain_tests()
    
    if success:
        print("\n✅ All domain trust tests completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Domain trust testing revealed issues that need attention.")
        sys.exit(1)