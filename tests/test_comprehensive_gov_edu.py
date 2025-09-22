#!/usr/bin/env python3
"""
Comprehensive test for .gov and .edu email handling with proper .eml files.

This tests the full pipeline including header extraction and domain weighting.
"""

import sys
import os

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


def test_eml_file(file_path, description):
    """Test processing of .eml file."""
    print(f"\n{'='*70}")
    print(f"Testing: {description}")
    print(f"File: {file_path}")
    print('='*70)
    
    try:
        # Read the .eml file
        with open(file_path, 'r', encoding='utf-8') as f:
            email_content = f.read()
        
        # Process email
        processor = EmailProcessor()
        result = processor.process_email(email_content, is_file_content=True)
        
        if not result['success']:
            print(f"❌ Email processing failed: {result.get('error', 'Unknown error')}")
            return None
            
        metadata = result['metadata']
        headers = result['headers']
        body = result['body']
        urls = result['urls']
        
        print(f"📧 Email processed successfully:")
        print(f"   Format: {result.get('format', 'Unknown')}")
        print(f"   From: {headers.get('From', 'Unknown')}")
        print(f"   Domain: {metadata.get('sender_domain', 'Unknown')}")
        print(f"   Subject: {headers.get('Subject', 'No subject')}")
        print(f"   Headers found: {len(headers)}")
        print(f"   URLs found: {len(urls)}")
        if urls:
            # Handle both string and dict URL formats
            url_list = []
            for url in urls:
                if isinstance(url, dict):
                    url_list.append(url.get('url', str(url)))
                else:
                    url_list.append(str(url))
            print(f"   URLs: {', '.join(url_list)}")
        
        # Test risk assessment
        risk_assessor = RiskAssessment()
        
        # Test domain trust weight calculation
        sender_domain = metadata.get('sender_domain', '')
        trust_weight, trust_reason = risk_assessor.calculate_domain_trust_weight(sender_domain)
        print(f"   🏛️  Trust Weight: {trust_weight} ({trust_reason})")
        
        # Test heuristic analysis
        heuristic_result = risk_assessor.cross_validate_with_heuristics(5, metadata)
        print(f"   📊 Heuristic Score: {heuristic_result['heuristic_score']}")
        print(f"   🚩 Heuristic Flags: {', '.join(heuristic_result['heuristic_flags'])}")
        
        # Check for suspicious content indicators
        subject = headers.get('Subject', '')
        body_text = body.get('text', '')
        
        suspicious_indicators = []
        if any(word in subject.upper() for word in ['URGENT', 'SUSPENDED', 'FINAL WARNING']):
            suspicious_indicators.append("Urgent language in subject")
        if any(word in body_text.upper() for word in ['VERIFY YOUR CREDENTIALS', 'CLICK HERE', 'ACT NOW']):
            suspicious_indicators.append("Suspicious language in body")
        # Check URLs for suspicious patterns
        url_strings = []
        for url in urls:
            if isinstance(url, dict):
                url_strings.append(url.get('url', ''))
            else:
                url_strings.append(str(url))
                
        if any('suspicious' in url or '.tk' in url for url in url_strings):
            suspicious_indicators.append("Suspicious URLs detected")
            
        if suspicious_indicators:
            print(f"   ⚠️  Content Analysis: {', '.join(suspicious_indicators)}")
        else:
            print(f"   ✅ Content Analysis: No obvious suspicious indicators")
        
        return {
            'metadata': metadata,
            'headers': headers,
            'trust_weight': trust_weight,
            'trust_reason': trust_reason,
            'heuristic_score': heuristic_result['heuristic_score'],
            'heuristic_flags': heuristic_result['heuristic_flags'],
            'suspicious_indicators': suspicious_indicators,
            'urls': urls
        }
        
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return None
    except Exception as e:
        print(f"❌ Error processing email: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def test_with_llm(file_path, description):
    """Test with full LLM analysis if available."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            email_content = f.read()
            
        ollama_service = OllamaService()
        if not ollama_service.test_connection():
            print("   ⚠️  Ollama not available - skipping LLM analysis")
            return None
            
        print(f"   🤖 Running LLM analysis...")
        
        # Process with LLM
        processor = EmailProcessor() 
        email_result = processor.process_email(email_content, is_file_content=True)
        
        if email_result['success']:
            llm_result = ollama_service.analyze_email(email_result['processed_content'])
            if llm_result['success']:
                analysis = llm_result['analysis']
                print(f"   📊 LLM Risk Score: {analysis.get('risk_score', 'Unknown')}")
                print(f"   🚩 LLM Red Flags: {len(analysis.get('red_flags', []))} detected")
                print(f"   💭 LLM Confidence: {analysis.get('confidence', 'Unknown')}")
                return analysis
            else:
                print(f"   ❌ LLM analysis failed: {llm_result.get('error', 'Unknown')}")
        
    except Exception as e:
        print(f"   ❌ LLM test error: {str(e)}")
    
    return None


def main():
    """Run comprehensive .gov and .edu email testing."""
    print("🏛️  Comprehensive .gov/.edu Domain Testing Suite")
    print("=" * 90)
    
    # Test files
    test_files = [
        ("examples/test_irs_legitimate.eml", "Legitimate IRS tax reminder (.gov)"),
        ("examples/test_harvard_legitimate.eml", "Legitimate Harvard registration notice (.edu)"),
        ("examples/test_cdc_suspicious.eml", "Suspicious content from spoofed CDC (.gov)")
    ]
    
    results = {}
    
    # Test each email file
    for file_path, description in test_files:
        result = test_eml_file(file_path, description)
        results[description] = result
        
        # Test with LLM if available
        if result:
            llm_result = test_with_llm(file_path, description)
            if llm_result:
                result['llm_analysis'] = llm_result
    
    # Analysis summary
    print(f"\n{'='*90}")
    print("🔍 COMPREHENSIVE ANALYSIS SUMMARY")
    print('='*90)
    
    institutional_tested = 0
    institutional_trusted = 0
    suspicious_detected = 0
    
    for description, result in results.items():
        if result is None:
            print(f"\n❌ {description}: FAILED - Could not process")
            continue
            
        domain = result['metadata'].get('sender_domain', 'Unknown')
        trust_weight = result['trust_weight']
        heuristic_score = result['heuristic_score']
        suspicious_count = len(result['suspicious_indicators'])
        
        print(f"\n📋 {description}:")
        print(f"   🌐 Domain: {domain}")
        print(f"   🏛️  Trust Weight: {trust_weight}")
        print(f"   📊 Heuristic Score: {heuristic_score}")
        print(f"   ⚠️  Suspicious Indicators: {suspicious_count}")
        
        # Check institutional domain handling
        if domain.endswith('.gov') or domain.endswith('.edu'):
            institutional_tested += 1
            if trust_weight < 0:
                institutional_trusted += 1
                print(f"   ✅ EXCELLENT: Institutional domain received appropriate trust bonus")
            else:
                print(f"   ❌ PROBLEM: Institutional domain missing trust bonus")
                
            # Even suspicious content from .gov/.edu should get trust weight, 
            # but other indicators should still flag it
            if heuristic_score <= 3:
                print(f"   ✅ GOOD: Low risk score due to domain trust")
            else:
                print(f"   ⚠️  NOTE: Higher risk score despite domain trust")
        
        # Check suspicious content detection
        if 'suspicious' in description.lower() and suspicious_count > 0:
            suspicious_detected += 1
            print(f"   ✅ GOOD: Suspicious content patterns detected in analysis")
        elif 'suspicious' in description.lower():
            print(f"   ⚠️  NOTE: Suspicious content not detected in basic analysis")
            
        # Check LLM analysis if available
        if 'llm_analysis' in result:
            llm_score = result['llm_analysis'].get('risk_score', 'Unknown')
            print(f"   🤖 LLM Risk Score: {llm_score}")
    
    # Final summary
    print(f"\n{'='*90}")
    print("🎯 FINAL TEST RESULTS:")
    print(f"📊 Institutional domains tested: {institutional_tested}")
    print(f"🏛️  Institutional domains with trust bonus: {institutional_trusted}")
    
    success_rate = (institutional_trusted / institutional_tested * 100) if institutional_tested > 0 else 0
    
    if success_rate == 100:
        print("✅ SUCCESS: All .gov/.edu domains received appropriate trust treatment!")
        print("🎉 Domain weighting system is working correctly!")
        return 0
    elif success_rate >= 50:
        print("⚠️  PARTIAL SUCCESS: Some institutional domains handled correctly")
        return 1
    else:
        print("❌ FAILURE: Institutional domain trust system not working properly")
        return 2


if __name__ == "__main__":
    sys.exit(main())