#!/usr/bin/env python3
"""
Test script for domain weighting functionality in Phish-Net risk assessment.

This script validates that the new domain trust weights are working correctly
for .gov, .edu, and corporate domains.
"""

import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from risk_assessment import RiskAssessment
except ImportError:
    from src.risk_assessment import RiskAssessment


def test_institutional_domains():
    """Test that institutional domains receive appropriate trust weights."""
    risk_assessor = RiskAssessment()
    
    print("Testing Institutional Domain Weights...")
    print("=" * 50)
    
    # Test government domains
    test_cases = [
        ("irs.gov", -4, "Government domain"),
        ("cdc.gov", -4, "Government domain"),  
        ("nasa.gov", -4, "Government domain"),
        ("state.gov", -4, "Government domain"),
        
        # Test educational domains
        ("harvard.edu", -3, "Educational institution"),
        ("mit.edu", -3, "Educational institution"),
        ("stanford.edu", -3, "Educational institution"),
        ("berkeley.edu", -3, "Educational institution"),
        
        # Test military domains
        ("army.mil", -4, "Military domain"),
        ("navy.mil", -4, "Military domain"),
        
        # Test corporate domains
        ("microsoft.com", -2, "Known trusted corporate domain"),
        ("google.com", -2, "Known trusted corporate domain"),
        ("github.com", -2, "Known trusted corporate domain"),
        
        # Test unknown domains (should get 0 weight)
        ("unknown-company.com", 0, "Domain not in trusted categories"),
        ("suspicious-domain.tk", 0, "Domain not in trusted categories"),
        
        # Test suspicious patterns (should be rejected even with trusted TLD)
        ("phishing.gov", 0, "Domain contains suspicious patterns"),
        ("scam-alert.edu", 0, "Domain contains suspicious patterns")
    ]
    
    all_passed = True
    
    for domain, expected_weight, expected_reason_part in test_cases:
        weight, reason = risk_assessor.calculate_domain_trust_weight(domain)
        
        if weight == expected_weight and expected_reason_part in reason:
            print(f"✓ PASS: {domain:<20} -> weight: {weight:2d}, reason: {reason}")
        else:
            print(f"✗ FAIL: {domain:<20} -> expected: {expected_weight:2d}, got: {weight:2d}")
            print(f"       Expected reason containing: '{expected_reason_part}'")
            print(f"       Got: '{reason}'")
            all_passed = False
    
    return all_passed


def test_heuristic_integration():
    """Test that domain weights are properly integrated into heuristic scoring."""
    risk_assessor = RiskAssessment()
    
    print("\nTesting Heuristic Integration...")
    print("=" * 50)
    
    # Test metadata for government domain
    gov_metadata = {
        "sender_domain": "irs.gov",
        "sender_trusted": False,
        "suspicious_url_count": 0,
        "url_count": 0
    }
    
    # Test metadata for suspicious domain
    suspicious_metadata = {
        "sender_domain": "suspicious-site.tk",
        "sender_trusted": False,
        "suspicious_url_count": 0,
        "url_count": 0
    }
    
    # Test metadata for corporate domain
    corporate_metadata = {
        "sender_domain": "microsoft.com", 
        "sender_trusted": False,
        "suspicious_url_count": 0,
        "url_count": 0
    }
    
    test_cases = [
        (gov_metadata, "Government domain should get trust bonus"),
        (corporate_metadata, "Corporate domain should get trust bonus"), 
        (suspicious_metadata, "Suspicious domain should get penalty")
    ]
    
    all_passed = True
    
    for metadata, description in test_cases:
        result = risk_assessor.cross_validate_with_heuristics(5, metadata)
        heuristic_score = result['heuristic_score']
        flags = result['heuristic_flags']
        
        print(f"\nTest: {description}")
        print(f"Domain: {metadata['sender_domain']}")
        print(f"Heuristic Score: {heuristic_score}")
        print(f"Flags: {', '.join(flags)}")
        
        # Government and corporate domains should have lower heuristic scores
        if metadata['sender_domain'] in ['irs.gov', 'microsoft.com']:
            if heuristic_score <= 3 and any('Trust bonus' in flag or 'Legitimate corporate' in flag for flag in flags):
                print("✓ PASS: Domain received appropriate trust treatment")
            else:
                print("✗ FAIL: Domain did not receive expected trust treatment")
                all_passed = False
        # Suspicious domains should have higher scores
        elif 'suspicious' in metadata['sender_domain']:
            if heuristic_score >= 4:
                print("✓ PASS: Suspicious domain penalized appropriately")  
            else:
                print("✗ FAIL: Suspicious domain not penalized enough")
                all_passed = False
    
    return all_passed


def main():
    """Run all domain weighting tests."""
    print("Phish-Net Domain Weighting Test Suite")
    print("=" * 60)
    
    test1_passed = test_institutional_domains()
    test2_passed = test_heuristic_integration()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY:")
    print(f"Institutional Domain Tests: {'PASSED' if test1_passed else 'FAILED'}")
    print(f"Heuristic Integration Tests: {'PASSED' if test2_passed else 'FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 ALL TESTS PASSED! Domain weighting is working correctly.")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED. Please check the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())