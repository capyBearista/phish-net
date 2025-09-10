#!/usr/bin/env python3
"""
Debug LLM Service - Check what's happening with the analysis
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sample_emails import LEGITIMATE_EMAILS
from email_processor import EmailProcessor
from llm_service import OllamaService
import json

def debug_llm_analysis():
    print("🔧 Debugging LLM Analysis")
    print("=" * 40)
    
    # Test both models available
    models_to_test = ["phi4-mini", "phi4-mini-reasoning"]
    
    for model_name in models_to_test:
        print(f"\n📋 Testing model: {model_name}")
        
        # Initialize services  
        email_processor = EmailProcessor()
        llm_service = OllamaService(model=model_name)
        
        # Test connection
        connection = llm_service.test_connection()
        print(f"Connection: {connection}")
        
        if connection.get("connected") and connection.get("model_available"):
            # Try analysis
            email_data = LEGITIMATE_EMAILS["corporate_newsletter"]
            processed_data = email_processor.process_email(email_data["content"], is_file_content=False)
            
            print(f"Processed data keys: {list(processed_data.keys())}")
            
            try:
                analysis_result = llm_service.analyze_email(processed_data)
                print(f"Analysis success: {analysis_result.get('success')}")
                print(f"Analysis keys: {list(analysis_result.keys())}")
                
                if not analysis_result.get('success'):
                    print(f"Error: {analysis_result.get('error')}")
                else:
                    print(f"Risk score: {analysis_result.get('risk_score')}")
                    
            except Exception as e:
                print(f"Exception during analysis: {e}")
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    debug_llm_analysis()