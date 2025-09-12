#!/usr/bin/env python3
"""
Deep LLM Analysis Debugger - Detailed investigation of model performance issues

This tool provides detailed insight into:
1. Raw LLM responses 
2. JSON parsing results
3. Risk assessment modifications
4. Score validation changes
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sample_emails import LEGITIMATE_EMAILS, PHISHING_EMAILS
from email_processor import EmailProcessor
from llm_service import OllamaService
import json

def debug_llm_pipeline_detailed(email_key, email_data, model_name="phi4-mini"):
    """Deep debug of the entire LLM pipeline"""
    
    print(f"\n{'='*80}")
    print(f"🔬 DEEP DEBUGGING: {email_key}")
    print(f"Model: {model_name}")
    print(f"Expected Risk: {email_data['expected_risk']}")
    print(f"Description: {email_data['description']}")
    print(f"{'='*80}")
    
    # Initialize services
    email_processor = EmailProcessor()
    llm_service = OllamaService(model=model_name)
    
    # Step 1: Process Email
    print(f"\n📧 STEP 1: Email Processing")
    print("-" * 40)
    processed_data = email_processor.process_email(email_data["content"], is_file_content=False)
    
    print(f"✅ Processing Success: {processed_data.get('success')}")
    print(f"📄 Headers Found: {list(processed_data.get('headers', {}).keys())}")
    print(f"🔗 URLs Found: {len(processed_data.get('urls', []))}")
    print(f"📧 Email Addresses: {len(processed_data.get('email_addresses', []))}")
    
    if processed_data.get('urls'):
        for url in processed_data['urls'][:3]:  # Show first 3 URLs
            print(f"   URL: {url.get('url', 'N/A')} (suspicious: {url.get('is_suspicious', False)})")
    
    # Step 2: Create LLM Prompt
    print(f"\n🤖 STEP 2: LLM Prompt Generation")
    print("-" * 40)
    
    # Access the private method to see the prompt
    prompt = llm_service._create_phishing_analysis_prompt(processed_data)
    print(f"📏 Prompt Length: {len(prompt)} characters")
    print(f"📝 Prompt Preview (first 500 chars):")
    print(f"┌{'─'*78}┐")
    for line in prompt[:500].split('\n')[:10]:
        print(f"│ {line[:76]:<76} │")
    print(f"└{'─'*78}┘")
    
    # Step 3: Raw LLM Request and Response
    print(f"\n🚀 STEP 3: LLM API Call")
    print("-" * 40)
    
    import requests
    import time
    
    request_data = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "top_p": 0.9,
            "max_tokens": 2000,
            "stop": ["</analysis>", "Human:", "Assistant:"]
        }
    }
    
    print(f"🔧 Request Config:")
    print(f"   Temperature: {request_data['options']['temperature']}")
    print(f"   Max Tokens: {request_data['options']['max_tokens']}")
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{llm_service.base_url}/api/generate",
            json=request_data,
            timeout=llm_service.timeout
        )
        response_time = time.time() - start_time
        
        print(f"⏱️  Response Time: {response_time:.2f}s")
        print(f"📊 HTTP Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            raw_response = result.get("response", "")
            
            print(f"📏 Raw Response Length: {len(raw_response)} characters")
            print(f"📝 Raw Response:")
            print(f"┌{'─'*78}┐")
            for line in raw_response.split('\n')[:20]:  # Show first 20 lines
                print(f"│ {line[:76]:<76} │")
            if len(raw_response.split('\n')) > 20:
                print(f"│ ... ({len(raw_response.split('\n')) - 20} more lines)") 
            print(f"└{'─'*78}┘")
            
            # Step 4: JSON Extraction
            print(f"\n🔍 STEP 4: JSON Extraction")
            print("-" * 40)
            
            json_match = llm_service._extract_json_from_response(raw_response)
            if json_match:
                print(f"✅ JSON Found: {len(json_match)} characters")
                print(f"📝 Extracted JSON:")
                try:
                    parsed_json = json.loads(json_match)
                    print(json.dumps(parsed_json, indent=2)[:1000] + ("..." if len(str(parsed_json)) > 1000 else ""))
                except:
                    print(f"❌ JSON Parse Error: {json_match[:500]}...")
            else:
                print(f"❌ No JSON found in response")
                
            # Step 5: Full Analysis Pipeline
            print(f"\n⚙️ STEP 5: Full Analysis Pipeline")
            print("-" * 40)
            
            analysis_result = llm_service.analyze_email(processed_data)
            
            print(f"✅ Analysis Success: {analysis_result.get('success')}")
            print(f"🎯 Final Risk Score: {analysis_result.get('risk_score')}")
            print(f"📊 Risk Level: {analysis_result.get('risk_level')}")
            print(f"🔍 Confidence: {analysis_result.get('confidence_score')}")
            
            # Show red flags
            red_flags = analysis_result.get('red_flags', {})
            if isinstance(red_flags, dict) and 'categorized' in red_flags:
                total_flags = red_flags.get('total_count', 0)
                print(f"🚩 Red Flags: {total_flags} total")
                categorized = red_flags.get('categorized', {})
                for severity in ['critical', 'major', 'minor']:
                    count = len(categorized.get(severity, []))
                    if count > 0:
                        print(f"   {severity.title()}: {count}")
                        for flag in categorized.get(severity, [])[:2]:  # Show first 2
                            print(f"     • {flag.get('text', 'N/A')}")
            
            # Step 6: Risk Assessment Validation
            print(f"\n🎲 STEP 6: Risk Assessment Analysis")
            print("-" * 40)
            
            validation = analysis_result.get('validation', {})
            if validation:
                print(f"🔧 Score Adjusted: {validation.get('score_adjusted', False)}")
                print(f"📈 Original Score: {validation.get('original_score', 'N/A')}")
                print(f"📝 Adjustment Reason: {validation.get('adjustment_reason', 'N/A')}")
            
            # Step 7: Performance Analysis
            print(f"\n📈 STEP 7: Performance Analysis")
            print("-" * 40)
            
            expected_range = (email_data['expected_risk'] - 1, email_data['expected_risk'] + 1)
            actual_score = analysis_result.get('risk_score', 0)
            
            print(f"🎯 Expected Score: {email_data['expected_risk']} (range: {expected_range})")
            print(f"🎯 Actual Score: {actual_score}")
            print(f"✅ Within Range: {'YES' if expected_range[0] <= actual_score <= expected_range[1] else 'NO'}")
            print(f"📊 Score Deviation: {abs(actual_score - email_data['expected_risk'])}")
            
            return {
                "email_key": email_key,
                "expected_score": email_data['expected_risk'],
                "actual_score": actual_score,
                "within_range": expected_range[0] <= actual_score <= expected_range[1],
                "deviation": abs(actual_score - email_data['expected_risk']),
                "raw_response_length": len(raw_response),
                "json_found": json_match is not None,
                "analysis_success": analysis_result.get('success', False)
            }
            
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        return {"error": str(e)}

def main():
    """Run detailed debugging on key test emails"""
    
    print("🔬 DEEP LLM ANALYSIS DEBUGGER")
    print("=" * 80)
    
    # Test key emails that should be very different
    test_cases = [
        ("corporate_newsletter", LEGITIMATE_EMAILS["corporate_newsletter"]),  # Should be ~1
        ("banking_phish", PHISHING_EMAILS["banking_phish"]),  # Should be ~9
        ("meeting_invitation", LEGITIMATE_EMAILS["meeting_invitation"]),  # Should be ~1
        ("paypal_scam", PHISHING_EMAILS["paypal_scam"])  # Should be ~10
    ]
    
    results = []
    
    for email_key, email_data in test_cases:
        result = debug_llm_pipeline_detailed(email_key, email_data)
        if "error" not in result:
            results.append(result)
    
    # Summary
    print(f"\n{'='*80}")
    print("📊 DEBUGGING SUMMARY")
    print(f"{'='*80}")
    
    for result in results:
        status = "✅ PASS" if result["within_range"] else "❌ FAIL"
        print(f"{status} {result['email_key']}: {result['actual_score']} (expected ~{result['expected_score']}) [deviation: {result['deviation']}]")
    
    if results:
        accuracy = len([r for r in results if r["within_range"]]) / len(results) * 100
        avg_deviation = sum(r["deviation"] for r in results) / len(results)
        print(f"\n📈 Overall Accuracy: {accuracy:.1f}%")
        print(f"📊 Average Deviation: {avg_deviation:.1f}")
        
        # Analysis of issues
        json_failures = len([r for r in results if not r["json_found"]])
        analysis_failures = len([r for r in results if not r["analysis_success"]])
        
        if json_failures > 0:
            print(f"⚠️  JSON Extraction Issues: {json_failures}/{len(results)}")
        if analysis_failures > 0:
            print(f"⚠️  Analysis Pipeline Issues: {analysis_failures}/{len(results)}")

if __name__ == "__main__":
    main()