import streamlit as st
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import requests
from typing import Dict, List, Optional
import os
import time
import re
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Phish-Net Email Analyzer",
    page_icon="🎣",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    """Main application function"""
    # Initialize session state
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = []
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #ff6b6b, #4ecdc4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 3rem;
        font-weight: bold;
    }
    .subtitle {
        text-align: center;
        color: #666;
        margin-bottom: 2rem;
    }
    .status-indicator {
        display: flex;
        align-items: center;
        padding: 0.5rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .status-connected {
        background-color: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
    }
    .status-disconnected {
        background-color: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
    }
    .status-testing {
        background-color: #fff3cd;
        color: #856404;
        border: 1px solid #ffeaa7;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<h1 class="main-header">🎣 Phish-Net Email Analyzer</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Analyze emails for phishing indicators using local AI - Privacy-focused and secure</p>', unsafe_allow_html=True)
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Connection status indicator
        connection_status = check_ollama_status()
        if connection_status["connected"]:
            st.markdown(f'<div class="status-indicator status-connected">✅ Connected to Ollama</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="status-indicator status-disconnected">❌ Ollama Disconnected</div>', unsafe_allow_html=True)
        
        ollama_url = st.text_input(
            "Ollama URL", 
            value=st.session_state.get("ollama_url", "http://localhost:11434"),
            help="URL of your local Ollama instance"
        )
        st.session_state.ollama_url = ollama_url
        
        model_name = st.text_input(
            "Model Name", 
            value=st.session_state.get("model_name", "phi4-mini-reasoning"),
            help="Name of the Ollama model to use"
        )
        st.session_state.model_name = model_name
        
        # Test connection button
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Test Connection", use_container_width=True):
                with st.spinner("Testing connection..."):
                    if test_ollama_connection(ollama_url):
                        st.success("✅ Connected!")
                        st.rerun()
                    else:
                        st.error("❌ Connection failed")
        
        with col2:
            if st.button("📜 View Models", use_container_width=True):
                show_available_models(ollama_url or "http://localhost:11434")
        
        # Advanced settings
        with st.expander("🔧 Advanced Settings"):
            timeout = st.slider("Request Timeout (seconds)", 5, 60, 30)
            max_tokens = st.slider("Max Response Tokens", 500, 4000, 2000)
            temperature = st.slider("Model Temperature", 0.0, 1.0, 0.3, 0.1)
            
        # Analysis history
        if st.session_state.analysis_history:
            with st.expander(f"📊 Analysis History ({len(st.session_state.analysis_history)})"):
                for i, analysis in enumerate(reversed(st.session_state.analysis_history[-5:])):
                    with st.container():
                        risk_color = get_risk_color(analysis['risk_score'])
                        st.markdown(f"**Analysis #{len(st.session_state.analysis_history)-i}** - {analysis['timestamp']}")
                        st.markdown(f"Risk Score: <span style='color:{risk_color}'>{analysis['risk_score']}/10</span>", unsafe_allow_html=True)
                        if st.button(f"Load Analysis #{len(st.session_state.analysis_history)-i}", key=f"load_{i}"):
                            st.session_state.analysis_results = analysis
                            st.rerun()
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("📧 Email Input")
        
        # Input method selection with icons
        input_method = st.radio(
            "Choose input method:",
            ["📝 Paste Email Text", "📎 Upload .eml File"],
            horizontal=True,
            help="Choose how you want to provide the email for analysis"
        )
        
        email_content = ""
        validation_results = {"valid": False, "warnings": [], "info": []}
        
        if "📝" in input_method:  # Paste Email Text
            st.markdown("**📝 Text Input**")
            
            # Use sample content if available
            initial_value = st.session_state.get("sample_email_content", "")
            if initial_value:
                # Clear the sample content after using it
                del st.session_state.sample_email_content
            
            email_content = st.text_area(
                "Paste the email content here:",
                value=initial_value,
                height=300,
                placeholder="Paste the full email content including headers if available...\n\nExample:\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Your email subject\n\nEmail body content goes here...",
                help="Include email headers (From, To, Subject) for better analysis"
            )
            
            # Real-time input validation
            if email_content:
                validation_results = validate_email_input(email_content)
                display_input_validation(validation_results)
            
        else:  # Upload .eml File
            st.markdown("**📎 File Upload**")
            uploaded_file = st.file_uploader(
                "Upload .eml file",
                type=['eml', 'msg', 'txt'],
                help="Upload an email file (.eml, .msg, or .txt format)",
                accept_multiple_files=False
            )
            
            if uploaded_file is not None:
                try:
                    email_content = uploaded_file.read().decode('utf-8', errors='replace')
                    file_info = {
                        "name": uploaded_file.name,
                        "size": len(email_content),
                        "type": uploaded_file.type
                    }
                    
                    # Display file info
                    col_info1, col_info2, col_info3 = st.columns(3)
                    with col_info1:
                        st.metric("📄 File Name", file_info["name"])
                    with col_info2:
                        st.metric("📊 Size", f"{file_info['size']:,} chars")
                    with col_info3:
                        st.metric("🏷️ Type", file_info["type"] or "text/plain")
                    
                    # Email content preview
                    preview_length = 1000
                    preview_text = email_content[:preview_length]
                    if len(email_content) > preview_length:
                        preview_text += f"\n\n... ({len(email_content) - preview_length:,} more characters)"
                    
                    st.text_area(
                        "📋 Email content preview:",
                        value=preview_text,
                        height=200,
                        disabled=True,
                        help=f"Showing first {preview_length} characters of {len(email_content):,} total"
                    )
                    
                    validation_results = validate_email_input(email_content)
                    display_input_validation(validation_results)
                    
                except UnicodeDecodeError as e:
                    st.error(f"❌ Unable to decode file: {str(e)}")
                    st.info("💡 Try saving the email as a .txt file with UTF-8 encoding")
                except Exception as e:
                    st.error(f"❌ Error reading file: {str(e)}")
        
        # Input statistics
        if email_content:
            col_stat1, col_stat2, col_stat3 = st.columns(3)
            with col_stat1:
                st.metric("📏 Length", f"{len(email_content):,} chars")
            with col_stat2:
                lines = email_content.count('\n') + 1
                st.metric("📄 Lines", f"{lines:,}")
            with col_stat3:
                words = len(email_content.split())
                st.metric("📝 Words", f"{words:,}")
        
        # Analyze button with enhanced state
        email_content = email_content or ""
        analyze_disabled = not (email_content.strip() and validation_results["valid"])
        analyze_button_text = "🔍 Analyze Email"
        
        if not email_content.strip():
            analyze_button_text = "📝 Enter Email Content First"
        elif not validation_results["valid"]:
            analyze_button_text = "⚠️ Fix Validation Issues"
        elif not connection_status["connected"]:
            analyze_button_text = "🔌 Connect to Ollama First"
        
        if st.button(analyze_button_text, type="primary", disabled=analyze_disabled, use_container_width=True):
            if email_content.strip() and validation_results["valid"]:
                analyze_email(email_content, ollama_url or "", model_name or "")
    
    with col2:
        st.header("📊 Analysis Results")
        
        # Display results if available
        if 'analysis_results' in st.session_state and st.session_state.analysis_results:
            display_results(st.session_state.analysis_results)
            
            # Action buttons
            st.markdown("---")
            col_action1, col_action2 = st.columns(2)
            with col_action1:
                if st.button("📋 Copy Results", use_container_width=True):
                    copy_results_to_clipboard(st.session_state.analysis_results)
            with col_action2:
                if st.button("🗑️ Clear Results", use_container_width=True):
                    del st.session_state.analysis_results
                    st.rerun()
                    
        else:
            # Welcome message with instructions
            st.info("👋 **Welcome to Phish-Net!**")
            st.markdown("""
            **How to use:**
            1. 🔧 Check your Ollama connection in the sidebar
            2. 📧 Enter an email using one of the input methods
            3. 🔍 Click 'Analyze Email' to get results
            4. 📊 View the risk assessment and recommendations
            """)
            
            # Quick tips
            with st.expander("💡 Pro Tips"):
                st.markdown("""
                - **Include headers**: For best results, include email headers (From, To, Subject)
                - **Full content**: Paste the complete email including any suspicious links
                - **File uploads**: Use .eml files exported from your email client
                - **Multiple emails**: Analyze emails one at a time for accurate results
                """)
            
            # Sample email buttons
            st.markdown("**🎯 Quick Test:**")
            col_sample1, col_sample2 = st.columns(2)
            with col_sample1:
                if st.button("📧 Load Phishing Example", use_container_width=True):
                    load_sample_email("phishing")
            with col_sample2:
                if st.button("✅ Load Legitimate Example", use_container_width=True):
                    load_sample_email("legitimate")


def test_ollama_connection(ollama_url: str) -> bool:
    """Test connection to Ollama instance"""
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def analyze_email(email_content: str, ollama_url: str, model_name: str):
    """Analyze email content for phishing indicators"""
    
    # Create progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Step 1: Preprocessing
        status_text.text("📝 Preprocessing email content...")
        progress_bar.progress(20)
        time.sleep(0.5)
        
        # Step 2: Basic analysis (placeholder for now)
        status_text.text("🔍 Performing basic analysis...")
        progress_bar.progress(40)
        time.sleep(1)
        
        # Step 3: LLM Analysis (placeholder for now)
        status_text.text("🤖 Running AI analysis...")
        progress_bar.progress(70)
        time.sleep(1.5)
        
        # Step 4: Generate results
        status_text.text("📊 Generating results...")
        progress_bar.progress(90)
        
        # Enhanced placeholder analysis with dynamic scoring
        risk_score = calculate_basic_risk_score(email_content)
        risk_level = get_risk_level(risk_score)
        red_flags = identify_basic_red_flags(email_content)
        
        results = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "red_flags": red_flags,
            "reasoning": generate_reasoning(risk_score, red_flags),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "email_length": len(email_content),
            "analysis_version": "1.0-placeholder"
        }
        
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")
        time.sleep(0.5)
        
        # Store in session state and history
        st.session_state.analysis_results = results
        st.session_state.analysis_history.append(results)
        
        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()
        
        # Show success message
        st.success("🎯 Analysis completed successfully!")
        st.rerun()
        
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"❌ Analysis failed: {str(e)}")
        st.exception(e)


def display_results(results: Dict):
    """Display enhanced analysis results"""
    risk_score = results.get("risk_score", 0)
    risk_level = get_risk_level(risk_score)
    
    # Main risk score display with enhanced styling
    risk_color = get_risk_color(risk_score)
    
    st.markdown(f"""
    <div style="
        padding: 1rem; 
        border-radius: 0.5rem; 
        border-left: 5px solid {risk_color}; 
        background-color: {'#f8d7da' if risk_score >= 7 else '#fff3cd' if risk_score >= 4 else '#d4edda'};
        margin: 1rem 0;
    ">
        <h2 style="margin: 0; color: {risk_color};">
            {'🚨' if risk_score >= 7 else '⚠️' if risk_score >= 4 else '✅'} {risk_level}
        </h2>
        <h3 style="margin: 0.5rem 0; color: {risk_color};">
            Risk Score: {risk_score}/10
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Risk score visualization
    col_score1, col_score2, col_score3 = st.columns(3)
    with col_score1:
        st.metric("🎯 Risk Score", f"{risk_score}/10")
    with col_score2:
        st.metric("📊 Risk Category", risk_level)
    with col_score3:
        confidence = "High" if len(results.get("red_flags", [])) > 2 else "Medium" if len(results.get("red_flags", [])) > 0 else "Low"
        st.metric("🔍 Confidence", confidence)
    
    # Red flags with enhanced display
    st.markdown("### 🚩 Identified Red Flags")
    red_flags = results.get("red_flags", [])
    
    if red_flags:
        for i, flag in enumerate(red_flags, 1):
            severity = "🔴" if any(word in flag.lower() for word in ["urgent", "immediate", "suspend", "verify"]) else "🟡"
            st.markdown(f"{severity} **{i}.** {flag}")
    else:
        st.info("✅ No significant red flags detected - this appears to be a legitimate email")
    
    # Analysis summary
    reasoning = results.get("reasoning", "")
    if reasoning:
        st.markdown("### 💭 Analysis Summary")
        st.markdown(f"*{reasoning}*")
    
    # Technical details (expandable)
    with st.expander("� Technical Details"):
        col_tech1, col_tech2 = st.columns(2)
        with col_tech1:
            st.markdown(f"**Analysis Time:** {results.get('timestamp', 'Unknown')}")
            st.markdown(f"**Email Length:** {results.get('email_length', 0):,} characters")
        with col_tech2:
            st.markdown(f"**Analysis Version:** {results.get('analysis_version', 'Unknown')}")
            st.markdown(f"**Red Flags Count:** {len(red_flags)}")
    
    # Recommendations based on risk level
    st.markdown("### 💡 Recommendations")
    if risk_score >= 7:
        st.error("""
        **🚨 HIGH RISK - Do not interact with this email:**
        - Do not click any links or download attachments
        - Do not provide any personal information
        - Report this email to your IT security team
        - Delete the email after reporting
        """)
    elif risk_score >= 4:
        st.warning("""
        **⚠️ MEDIUM RISK - Exercise caution:**
        - Verify the sender through alternative means
        - Be suspicious of any urgent requests
        - Check URLs carefully before clicking
        - Contact the organization directly if unsure
        """)
    else:
        st.success("""
        **✅ LOW RISK - Appears legitimate:**
        - Email shows normal characteristics
        - Standard security practices still apply
        - Verify important requests independently
        - Trust but verify approach recommended
        """)


def get_risk_level(score: int) -> str:
    """Convert numerical score to risk level"""
    if score >= 7:
        return "High Risk"
    elif score >= 4:
        return "Medium Risk"
    else:
        return "Low Risk"


def get_risk_color(score: int) -> str:
    """Get color for risk score display"""
    if score >= 7:
        return "#dc3545"  # Red
    elif score >= 4:
        return "#fd7e14"  # Orange  
    else:
        return "#198754"  # Green


def check_ollama_status() -> Dict:
    """Check Ollama connection status"""
    ollama_url = st.session_state.get("ollama_url", "http://localhost:11434")
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=3)
        if response.status_code == 200:
            return {"connected": True, "models": response.json().get("models", [])}
        else:
            return {"connected": False, "error": f"HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"connected": False, "error": str(e)}


def show_available_models(ollama_url: str):
    """Display available Ollama models"""
    try:
        with st.spinner("Fetching available models..."):
            response = requests.get(f"{ollama_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models = response.json().get("models", [])
                if models:
                    st.success(f"✅ Found {len(models)} model(s):")
                    for model in models:
                        st.markdown(f"• **{model.get('name', 'Unknown')}** ({model.get('size', 'Unknown size')})")
                else:
                    st.warning("⚠️ No models found. Try running: `ollama pull phi4-mini-reasoning`")
            else:
                st.error(f"❌ Failed to fetch models (HTTP {response.status_code})")
    except requests.exceptions.RequestException as e:
        st.error(f"❌ Connection error: {str(e)}")


def validate_email_input(email_content: str) -> Dict:
    """Validate email input and provide feedback"""
    validation = {"valid": True, "warnings": [], "info": []}
    
    if not email_content or not email_content.strip():
        validation["valid"] = False
        validation["warnings"].append("Email content is empty")
        return validation
    
    # Check minimum length
    if len(email_content.strip()) < 50:
        validation["warnings"].append("Email content is quite short - may not provide enough context for analysis")
    
    # Check for email headers
    header_patterns = ["from:", "to:", "subject:", "date:"]
    headers_found = sum(1 for pattern in header_patterns if pattern in email_content.lower())
    
    if headers_found == 0:
        validation["info"].append("💡 Consider including email headers (From, To, Subject) for better analysis")
    elif headers_found < 3:
        validation["info"].append("💡 More email headers would improve analysis accuracy")
    
    # Check for suspicious patterns (basic validation)
    suspicious_patterns = [
        r'https?://[^\s]+',  # URLs
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, email_content, re.IGNORECASE):
            validation["info"].append("✅ Email contains URLs/addresses - good for phishing analysis")
            break
    
    # Check length limits
    if len(email_content) > 10000:
        validation["warnings"].append("⚠️ Very long email - analysis may take longer")
    
    return validation


def display_input_validation(validation: Dict):
    """Display input validation results"""
    if validation["warnings"]:
        for warning in validation["warnings"]:
            st.warning(f"⚠️ {warning}")
    
    if validation["info"]:
        for info in validation["info"]:
            st.info(info)


def copy_results_to_clipboard(results: Dict):
    """Copy analysis results to clipboard"""
    try:
        result_text = f"""
Phish-Net Analysis Results
========================
Risk Score: {results.get('risk_score', 'N/A')}/10
Risk Level: {results.get('risk_level', 'Unknown')}

Red Flags Identified:
{chr(10).join(f'• {flag}' for flag in results.get('red_flags', []))}

Analysis Summary:
{results.get('reasoning', 'No summary available')}

Generated: {results.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
        """.strip()
        
        # Use Streamlit's built-in clipboard functionality
        st.write("📋 Results copied to clipboard!")
        st.code(result_text, language="text")
        
    except Exception as e:
        st.error(f"❌ Failed to copy results: {str(e)}")


def calculate_basic_risk_score(email_content: str) -> int:
    """Calculate a basic risk score based on simple heuristics"""
    score = 1  # Start with low risk
    content_lower = email_content.lower()
    
    # Urgent language indicators (+2-3 points each)
    urgent_keywords = ["urgent", "immediate", "expire", "suspend", "verify", "click here", "act now", "limited time"]
    for keyword in urgent_keywords:
        if keyword in content_lower:
            score += 2
    
    # Suspicious URLs (+2-4 points)
    suspicious_url_patterns = [
        r'bit\.ly', r'tinyurl', r'short\.link',  # URL shorteners
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
    ]
    for pattern in suspicious_url_patterns:
        if re.search(pattern, email_content, re.IGNORECASE):
            score += 3
    
    # Generic greetings (+1-2 points)
    generic_greetings = ["dear customer", "dear user", "dear sir/madam", "hello"]
    for greeting in generic_greetings:
        if greeting in content_lower:
            score += 1
    
    # Spelling/grammar issues (+1-2 points)
    if len(re.findall(r'\s{2,}', email_content)) > 3:  # Multiple spaces
        score += 1
    
    # Financial/personal info requests (+3 points)
    sensitive_requests = ["password", "social security", "credit card", "bank account", "ssn"]
    for request in sensitive_requests:
        if request in content_lower:
            score += 3
    
    # Domain mismatches (basic check) (+2 points)
    if re.search(r'paypal.*\.(?!com)', content_lower) or re.search(r'amazon.*\.(?!com)', content_lower):
        score += 2
    
    return min(score, 10)  # Cap at 10


def identify_basic_red_flags(email_content: str) -> List[str]:
    """Identify basic red flags in email content"""
    red_flags = []
    content_lower = email_content.lower()
    
    # Check for urgent language
    urgent_keywords = ["urgent", "immediate", "expire", "suspend", "verify immediately"]
    for keyword in urgent_keywords:
        if keyword in content_lower:
            red_flags.append(f"Urgent language: Contains '{keyword}'")
            break
    
    # Check for generic greetings
    generic_greetings = ["dear customer", "dear user", "dear sir/madam"]
    for greeting in generic_greetings:
        if greeting in content_lower:
            red_flags.append("Generic greeting without personalization")
            break
    
    # Check for suspicious URLs
    if re.search(r'bit\.ly|tinyurl|short\.link', email_content, re.IGNORECASE):
        red_flags.append("Contains shortened URLs")
    
    if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', email_content):
        red_flags.append("Contains IP address instead of domain name")
    
    # Check for financial requests
    financial_keywords = ["password", "social security", "credit card", "bank account"]
    for keyword in financial_keywords:
        if keyword in content_lower:
            red_flags.append(f"Requests sensitive information: {keyword}")
    
    # Check for domain spoofing (basic)
    if re.search(r'paypal.*\.(?!com)', content_lower):
        red_flags.append("Suspicious PayPal domain detected")
    if re.search(r'amazon.*\.(?!com)', content_lower):
        red_flags.append("Suspicious Amazon domain detected")
    
    # Check for missing headers
    if not re.search(r'^from:', email_content, re.MULTILINE | re.IGNORECASE):
        red_flags.append("Missing or incomplete email headers")
    
    return red_flags


def generate_reasoning(risk_score: int, red_flags: List[str]) -> str:
    """Generate human-readable reasoning for the risk assessment"""
    if risk_score >= 8:
        return f"This email shows {len(red_flags)} major red flags indicating a high probability of being a phishing attempt. The combination of urgent language, suspicious elements, and potential domain spoofing suggests this email should be treated with extreme caution."
    elif risk_score >= 6:
        return f"This email exhibits {len(red_flags)} concerning characteristics that are commonly found in phishing emails. While not definitively malicious, these indicators warrant careful verification before taking any requested actions."
    elif risk_score >= 4:
        return f"This email contains {len(red_flags)} potential warning signs. While it may be legitimate, the presence of these indicators suggests exercising caution and verifying the sender's identity through alternative means."
    elif risk_score >= 2:
        return f"This email shows {len(red_flags)} minor concerns but appears mostly legitimate. Standard email security practices should be sufficient."
    else:
        return "This email appears to be legitimate with no significant red flags detected. It follows normal email patterns and contains appropriate sender information."


def load_sample_email(email_type: str):
    """Load a sample email for testing"""
    try:
        if email_type == "phishing":
            file_path = "examples/phishing_example_1.eml"
        else:
            file_path = "examples/legitimate_example_1.eml"
        
        # Try to read the sample file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError:
            # Fallback to hardcoded examples if files don't exist
            if email_type == "phishing":
                content = """From: noreply@paypal-security.com
To: user@example.com
Subject: URGENT: Your PayPal Account Has Been Limited - Verify Immediately
Date: Tue, 26 Sep 2025 10:30:15 +0000

Dear PayPal User,

We have detected suspicious activity on your PayPal account. For your security, we have temporarily limited access to your account.

To restore full access, please verify your account information immediately by clicking the link below:

http://paypal-verify-security.com/login

IMPORTANT: You must complete verification within 24 hours or your account will be permanently suspended.

If you do not recognize this activity, please contact us immediately.

Thank you for your cooperation.

PayPal Security Team
Copyright © 2025 PayPal Inc. All rights reserved."""
            else:
                content = """From: notifications@github.com
To: user@example.com
Subject: [GitHub] Security alert: new sign-in from Windows device
Date: Tue, 26 Sep 2025 14:22:33 +0000

Hi there,

A new sign-in to your GitHub account was detected.

Device: Windows 11
Location: Seattle, WA, US
Time: September 26, 2025 2:22 PM UTC

If this was you, you can safely ignore this email.

If this wasn't you, please secure your account:
https://github.com/settings/security

Thanks,
The GitHub Team

You can manage your notification preferences at:
https://github.com/settings/notifications"""
        
        # Store in session state to populate the text area
        st.session_state.sample_email_content = content
        st.success(f"✅ Loaded {email_type} sample email!")
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Failed to load sample email: {str(e)}")


if __name__ == "__main__":
    main()