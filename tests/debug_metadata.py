#!/usr/bin/env python3
"""
Debug Metadata and Trust Analysis
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sample_emails import LEGITIMATE_EMAILS
from email_processor import EmailProcessor

def debug_metadata():
    email_data = LEGITIMATE_EMAILS["meeting_invitation"]
    
    processor = EmailProcessor()
    processed_data = processor.process_email(email_data["content"], is_file_content=False)
    
    print("📊 METADATA ANALYSIS")
    print("=" * 50)
    print(f"✅ Success: {processed_data.get('success')}")
    
    headers = processed_data.get("headers", {})
    print(f"\n📧 Headers:")
    for key, value in headers.items():
        print(f"   {key}: {value}")
    
    metadata = processed_data.get("metadata", {})
    print(f"\n🔍 Metadata:")
    for key, value in metadata.items():
        print(f"   {key}: {value}")
    
    print(f"\n🔐 Trust Analysis:")
    print(f"   sender_trusted: {metadata.get('sender_trusted', 'NOT SET')}")
    print(f"   sender_domain: {metadata.get('sender_domain', 'NOT SET')}")
    print(f"   suspicious_url_count: {metadata.get('suspicious_url_count', 'NOT SET')}")
    print(f"   url_count: {metadata.get('url_count', 'NOT SET')}")

if __name__ == "__main__":
    debug_metadata()