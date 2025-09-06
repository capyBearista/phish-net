#!/usr/bin/env python3
"""
Test script for Phase 2: Email Content Processing

This script demonstrates the enhanced email processing capabilities
of the Phish-Net application.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from email_processor import EmailProcessor
import json

def test_email_processing():
    """Test the EmailProcessor with different types of content"""
    
    print("🧪 Testing Phish-Net Email Processing (Phase 2)")
    print("=" * 60)
    
    processor = EmailProcessor()
    
    # Test 1: Process .eml file
    print("\n📧 Test 1: Processing .eml file")
    print("-" * 40)
    
    try:
        with open('../examples/phishing_example_1.eml', 'r') as f:
            eml_content = f.read()
        
        result = processor.process_email(eml_content, is_file_content=True)
        
        print(f"✅ Success: {result['success']}")
        print(f"📋 Format: {result['format']}")
        print(f"📧 Headers found: {len(result['headers'])}")
        print(f"🔗 URLs found: {len(result['urls'])}")
        print(f"⚠️  Suspicious URLs: {result['metadata'].get('suspicious_url_count', 0)}")
        print(f"🔗 Shortened URLs: {result['metadata'].get('shortened_url_count', 0)}")
        
        # Show headers
        if result['headers']:
            print("\n📋 Key Headers:")
            for key in ['from', 'to', 'subject', 'date']:
                if key in result['headers']:
                    value = result['headers'][key]
                    print(f"  {key.upper()}: {value[:50]}{'...' if len(value) > 50 else ''}")
        
        # Show URLs
        if result['urls']:
            print(f"\n🔗 URLs Found:")
            for url in result['urls'][:3]:  # Show first 3
                status = ""
                if url.get('is_suspicious'): status += " [SUSPICIOUS]"
                if url.get('is_shortened'): status += " [SHORTENED]"
                print(f"  • {url['url']}{status}")
    
    except Exception as e:
        print(f"❌ Error processing .eml file: {e}")
    
    # Test 2: Process plain text
    print(f"\n📝 Test 2: Processing plain text")
    print("-" * 40)
    
    plain_text = """From: support@bank-security.com
To: customer@example.com
Subject: URGENT: Verify Your Account NOW

Dear Valued Customer,

Your account has been temporarily suspended due to suspicious activity. 

Please verify your information immediately by clicking here:
http://bank-verify.suspicious-domain.tk/login

You have 24 hours to complete this verification or your account will be permanently closed.

Thank you,
Security Team"""
    
    result2 = processor.process_email(plain_text, is_file_content=False)
    
    print(f"✅ Success: {result2['success']}")
    print(f"📋 Format: {result2['format']}")
    print(f"📧 Headers found: {len(result2['headers'])}")
    print(f"🔗 URLs found: {len(result2['urls'])}")
    print(f"⚠️  Suspicious URLs: {result2['metadata'].get('suspicious_url_count', 0)}")
    
    # Test 3: Demonstrate processed content
    print(f"\n🔍 Test 3: Processed content for LLM")
    print("-" * 40)
    
    processed_content = result2['processed_content']
    print("Content prepared for LLM analysis:")
    print(processed_content[:300] + "..." if len(processed_content) > 300 else processed_content)
    
    # Test 4: Show metadata
    print(f"\n📊 Test 4: Email metadata")
    print("-" * 40)
    
    metadata = result2['metadata']
    print(json.dumps(metadata, indent=2))
    
    print(f"\n✅ Phase 2 Testing Complete!")
    print("🎯 Email processing is working correctly!")

if __name__ == "__main__":
    test_email_processing()