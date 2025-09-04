import streamlit as st
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import requests
from typing import Dict, List, Optional
import os

# Page configuration
st.set_page_config(
    page_title="Phish-Net Email Analyzer",
    page_icon="🎣",
    layout="wide"
)

def main():
    """Main application function"""
    st.title("🎣 Phish-Net Email Analyzer")
    st.markdown("**Analyze emails for phishing indicators using local AI**")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        ollama_url = st.text_input(
            "Ollama URL", 
            value="http://localhost:11434",
            help="URL of your local Ollama instance"
        )
        model_name = st.text_input(
            "Model Name", 
            value="phi4-mini-reasoning",
            help="Name of the Ollama model to use"
        )
        
        # Test connection button
        if st.button("Test Ollama Connection"):
            if test_ollama_connection(ollama_url):
                st.success("✅ Connected to Ollama!")
            else:
                st.error("❌ Cannot connect to Ollama")
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("📧 Email Input")
        
        # Input method selection
        input_method = st.radio(
            "Choose input method:",
            ["Paste Email Text", "Upload .eml File"],
            horizontal=True
        )
        
        email_content = ""
        
        if input_method == "Paste Email Text":
            email_content = st.text_area(
                "Paste the email content here:",
                height=300,
                placeholder="Paste the full email content including headers if available..."
            )
        else:
            uploaded_file = st.file_uploader(
                "Upload .eml file",
                type=['eml'],
                help="Upload an email file (.eml format)"
            )
            if uploaded_file is not None:
                email_content = uploaded_file.read().decode('utf-8')
                st.text_area(
                    "Email content preview:",
                    value=email_content[:1000] + "..." if len(email_content) > 1000 else email_content,
                    height=200,
                    disabled=True
                )
        
        # Analyze button
        if st.button("🔍 Analyze Email", type="primary", disabled=not email_content.strip()):
            if email_content.strip():
                analyze_email(email_content, ollama_url, model_name)
    
    with col2:
        st.header("📊 Analysis Results")
        # Placeholder for results - will be populated by analyze_email function
        if 'analysis_results' not in st.session_state:
            st.info("Enter an email and click 'Analyze Email' to see results")


def test_ollama_connection(ollama_url: str) -> bool:
    """Test connection to Ollama instance"""
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def analyze_email(email_content: str, ollama_url: str, model_name: str):
    """Analyze email content for phishing indicators"""
    with st.spinner("Analyzing email..."):
        try:
            # For now, we'll create a placeholder analysis
            # This will be replaced with actual LLM integration
            
            # Simulate processing time
            import time
            time.sleep(2)
            
            # Placeholder results
            results = {
                "risk_score": 7,
                "risk_level": "High Risk",
                "red_flags": [
                    "Urgent language requesting immediate action",
                    "Generic greeting without personalization",
                    "Suspicious domain in sender address"
                ],
                "reasoning": "This email exhibits multiple characteristics commonly found in phishing attempts."
            }
            
            # Store results in session state
            st.session_state.analysis_results = results
            
            # Display results
            display_results(results)
            
        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")


def display_results(results: Dict):
    """Display analysis results"""
    # Risk score with color coding
    risk_score = results.get("risk_score", 0)
    risk_level = get_risk_level(risk_score)
    
    if risk_score >= 7:
        st.error(f"🚨 **{risk_level}** (Score: {risk_score}/10)")
    elif risk_score >= 4:
        st.warning(f"⚠️ **{risk_level}** (Score: {risk_score}/10)")
    else:
        st.success(f"✅ **{risk_level}** (Score: {risk_score}/10)")
    
    # Red flags
    st.subheader("🚩 Identified Red Flags")
    red_flags = results.get("red_flags", [])
    if red_flags:
        for flag in red_flags:
            st.markdown(f"• {flag}")
    else:
        st.info("No significant red flags detected")
    
    # Reasoning
    reasoning = results.get("reasoning", "")
    if reasoning:
        st.subheader("💭 Analysis Summary")
        st.markdown(reasoning)


def get_risk_level(score: int) -> str:
    """Convert numerical score to risk level"""
    if score >= 7:
        return "High Risk"
    elif score >= 4:
        return "Medium Risk"
    else:
        return "Low Risk"


if __name__ == "__main__":
    main()