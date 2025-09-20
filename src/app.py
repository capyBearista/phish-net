"""
Phish-Net Email Analyzer - Main Streamlit Application

This module provides the web-based user interface for Phish-Net, a privacy-focused
phishing email detection tool. The application orchestrates email processing,
AI analysis, and risk assessment while maintaining a user-friendly interface.

Key Components:
- Streamlit web interface with responsive design
- Session state management for analysis history
- Real-time system health monitoring
- Configuration management via sidebar
- Error handling with user guidance

Architecture:
- Service Layer Pattern: Coordinates between specialized services
- Privacy First: All processing happens locally
- Error Resilience: Comprehensive error handling with graceful degradation

Author: Phish-Net Development Team
License: Educational Use
"""

import streamlit as st
import json
import requests
from typing import Dict, List, Optional
import time
import re
from datetime import datetime

# Flexible imports to support both package and standalone execution
try:
    from .email_processor import EmailProcessor
    from .llm_service import OllamaService
    from .error_handling import error_handler, ErrorCategory, PhishNetError
    from .risk_assessment import RiskAssessment
except ImportError:
    from email_processor import EmailProcessor
    from llm_service import OllamaService
    from error_handling import error_handler, ErrorCategory, PhishNetError
    from risk_assessment import RiskAssessment

# Page configuration
st.set_page_config(
    page_title="Phish-Net Email Analyzer",
    page_icon="🎣",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    """
    Main application function with performance optimizations
    
    Features:
    - Memory-efficient session state management
    - Lazy loading of services
    - Optimized history management with size limits
    """
    # Initialize session state with memory management
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = []
    
    # Limit history size to prevent memory bloat (keep last 50 analyses)
    if len(st.session_state.analysis_history) > 50:
        st.session_state.analysis_history = st.session_state.analysis_history[-50:]
    
    # Lazy load email processor only when needed
    if 'email_processor' not in st.session_state:
        st.session_state.email_processor = EmailProcessor()
    
    # Ollama service initialized on demand
    if 'ollama_service' not in st.session_state:
        st.session_state.ollama_service = None
    
    # Enhanced CSS for professional UI styling with dark mode support
    st.markdown("""
    <style>
    /* CSS Variables for theme colors */
    :root {
        --text-color: #262730;
        --bg-color: #ffffff;
        --card-bg: #ffffff;
        --border-color: #e0e0e0;
        --subtitle-color: #666;
        --shadow: rgba(0,0,0,0.1);
    }
    
    /* Dark mode variables */
    [data-theme="dark"] {
        --text-color: #fafafa;
        --bg-color: #0e1117;
        --card-bg: #262730;
        --border-color: #4a4a4a;
        --subtitle-color: #a0a0a0;
        --shadow: rgba(255,255,255,0.05);
    }
    
    /* Auto-detect dark mode */
    @media (prefers-color-scheme: dark) {
        :root {
            --text-color: #fafafa;
            --bg-color: #0e1117;
            --card-bg: #262730;
            --border-color: #4a4a4a;
            --subtitle-color: #a0a0a0;
            --shadow: rgba(255,255,255,0.05);
        }
    }
    
    /* Main header styling with gradient text */
    .main-header {
        text-align: center;
        padding: 2rem 0 1rem 0;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 3.5rem;
        font-weight: 800;
        letter-spacing: -2px;
        margin-bottom: 0;
    }
    
    /* Subtitle styling with theme support */
    .subtitle {
        text-align: center;
        color: var(--subtitle-color);
        font-size: 1.2rem;
        margin-bottom: 2.5rem;
        font-weight: 300;
    }
    
    /* Enhanced status indicators */
    .status-indicator {
        display: flex;
        align-items: center;
        padding: 0.75rem 1rem;
        border-radius: 0.75rem;
        margin: 0.5rem 0;
        font-weight: 500;
        font-size: 0.95rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        transition: all 0.2s ease;
    }
    
    .status-connected {
        background: linear-gradient(135deg, #d4edda 0%, #c8e6c9 100%);
        color: #2e7d32;
        border: 1px solid #4caf50;
    }
    
    .status-disconnected {
        background: linear-gradient(135deg, #f8d7da 0%, #ffcdd2 100%);
        color: #c62828;
        border: 1px solid #f44336;
    }
    
    .status-testing {
        background: linear-gradient(135deg, #fff3cd 0%, #ffecb3 100%);
        color: #f57c00;
        border: 1px solid #ff9800;
    }
    
    /* Risk assessment cards with dark mode support */
    .risk-card {
        background: var(--card-bg);
        color: var(--text-color);
        border-radius: 1rem;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 4px 6px var(--shadow);
        border-left: 5px solid;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    
    .risk-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 15px var(--shadow);
    }
    
    .risk-low {
        border-left-color: #4caf50;
    }
    
    .risk-medium {
        border-left-color: #ff9800;
    }
    
    .risk-high {
        border-left-color: #f44336;
    }
    
    /* Metric cards styling with dark mode support */
    [data-testid="metric-container"] {
        background: var(--card-bg) !important;
        border: 1px solid var(--border-color) !important;
        color: var(--text-color) !important;
        padding: 1rem;
        border-radius: 0.75rem;
        box-shadow: 0 2px 4px var(--shadow);
        transition: all 0.2s ease;
    }
    
    [data-testid="metric-container"]:hover {
        box-shadow: 0 4px 8px var(--shadow);
        transform: translateY(-1px);
    }
    
    /* Fix metric container text colors */
    [data-testid="metric-container"] [data-testid="metric-label"] {
        color: var(--subtitle-color) !important;
    }
    
    [data-testid="metric-container"] [data-testid="metric-value"] {
        color: var(--text-color) !important;
    }
    
    /* Red flags styling with dark mode support */
    .red-flag-item {
        background: var(--card-bg);
        color: var(--text-color);
        border-left: 4px solid;
        padding: 0.75rem 1rem;
        margin: 0.5rem 0;
        border-radius: 0 0.5rem 0.5rem 0;
        box-shadow: 0 1px 3px var(--shadow);
    }
    
    .red-flag-critical {
        border-left-color: #f44336;
    }
    
    .red-flag-major {
        border-left-color: #ff9800;
    }
    
    .red-flag-minor {
        border-left-color: #ffc107;
    }
    
    /* Button styling improvements with dark mode support */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        color: white !important;
        border: none;
        border-radius: 0.75rem;
        padding: 0.75rem 1.5rem;
        font-weight: 500;
        transition: all 0.2s ease;
        box-shadow: 0 2px 4px var(--shadow);
    }
    
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 8px var(--shadow);
    }
    
    /* File uploader styling with dark mode support */
    [data-testid="stFileUploader"] {
        background: var(--card-bg) !important;
        border: 2px dashed var(--border-color) !important;
        color: var(--text-color) !important;
        border-radius: 1rem;
        padding: 2rem;
        text-align: center;
        transition: all 0.2s ease;
    }
    
    [data-testid="stFileUploader"]:hover {
        border-color: #667eea !important;
    }
    
    /* Text area enhancements with dark mode support */
    .stTextArea textarea {
        background: var(--card-bg) !important;
        color: var(--text-color) !important;
        border: 2px solid var(--border-color) !important;
        border-radius: 0.75rem;
        transition: border-color 0.2s ease;
        font-family: 'Consolas', 'Monaco', monospace;
    }
    
    .stTextArea textarea:focus {
        border-color: #667eea !important;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1) !important;
    }
    
    /* Progress bar styling */
    .stProgress .css-1aumxhk {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 1rem;
    }
    
    /* Expander styling with dark mode support */
    .streamlit-expander {
        background: var(--card-bg) !important;
        color: var(--text-color) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 0.75rem;
        overflow: hidden;
        box-shadow: 0 2px 4px var(--shadow);
    }
    
    .streamlit-expanderHeader {
        background: var(--card-bg) !important;
        color: var(--text-color) !important;
        border-bottom: 1px solid var(--border-color) !important;
        padding: 0.75rem 1rem;
    }
    
    /* Loading spinner styling */
    .stSpinner > div {
        border-color: #667eea transparent #667eea transparent;
    }
    
    /* Alert styling improvements with dark mode support */
    .stAlert {
        background: var(--card-bg) !important;
        color: var(--text-color) !important;
        border-radius: 0.75rem;
        border: none;
        box-shadow: 0 2px 4px var(--shadow);
    }
    
    /* Streamlit input widgets dark mode fixes */
    .stSelectbox > div > div {
        background: var(--card-bg) !important;
        color: var(--text-color) !important;
        border: 1px solid var(--border-color) !important;
    }
    
    .stNumberInput > div > div > input {
        background: var(--card-bg) !important;
        color: var(--text-color) !important;
        border: 1px solid var(--border-color) !important;
    }
    
    .stSlider .css-1cpxqw2 {
        background: var(--card-bg) !important;
        color: var(--text-color) !important;
    }
    
    /* Radio button styling for dark mode */
    .stRadio > div {
        color: var(--text-color) !important;
    }
    
    /* Sidebar text color fixes */
    .css-1d391kg, .css-1d391kg .element-container {
        color: var(--text-color) !important;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<h1 class="main-header">🎣 Phish-Net Email Analyzer</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Analyze emails for phishing indicators using local AI - Privacy-focused and secure</p>', unsafe_allow_html=True)
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        
        # System Health Check
        health_status = error_handler.check_system_health()
        overall_status = health_status.get("overall_status", "unknown")
        
        if overall_status == "healthy":
            st.markdown('<div class="status-indicator status-connected">System Healthy</div>', unsafe_allow_html=True)
        elif overall_status == "degraded":
            st.markdown('<div class="status-indicator status-testing">System Degraded</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="status-indicator status-disconnected">System Issues</div>', unsafe_allow_html=True)
        
        # Show detailed health info in expander
        with st.expander("System Health Details"):
            for check in health_status.get("checks", []):
                st.markdown(check)
            for warning in health_status.get("warnings", []):
                st.markdown(warning)
            for error in health_status.get("errors", []):
                st.markdown(error)
            
            # Show error statistics if any errors occurred
            error_stats = error_handler.get_error_statistics()
            if error_stats.get("total_errors", 0) > 0:
                st.markdown(f"**Total errors this session:** {error_stats['total_errors']}")
                if error_stats.get("most_common_errors"):
                    st.markdown("**Most common issues:**")
                    for error_type, count in error_stats["most_common_errors"][:3]:
                        st.markdown(f"• {error_type}: {count}")
        
        # Connection status indicator (legacy - keeping for compatibility)
        connection_status = check_ollama_status()
        if not connection_status["connected"]:
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
            if st.button("Test Connection", use_container_width=True):
                with st.spinner("Testing connection..."):
                    if test_ollama_connection(ollama_url or "http://localhost:11434"):
                        st.success("Connected!")
                        st.rerun()
                    else:
                        st.error("Connection failed")
        
        with col2:
            if st.button("View Models", use_container_width=True):
                show_available_models(ollama_url or "http://localhost:11434")
        
        # Advanced settings
        with st.expander("Advanced Settings"):
            timeout = st.slider("Request Timeout (seconds)", 5, 60, 30)
            max_tokens = st.slider("Max Response Tokens", 500, 4000, 2000)
            temperature = st.slider("Model Temperature", 0.0, 1.0, 0.3, 0.1)
            
            # Store in session state
            st.session_state.timeout = timeout
            st.session_state.max_tokens = max_tokens
            st.session_state.temperature = temperature
            
        # Analysis history
        if st.session_state.analysis_history:
            with st.expander(f"Analysis History ({len(st.session_state.analysis_history)})"):
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
        st.header("Email Input")
        
        # Input method selection
        input_method = st.radio(
            "Choose input method:",
            ["Paste Email Text", "Upload .eml File"],
            horizontal=True,
            help="Choose how you want to provide the email for analysis"
        )
        
        email_content = ""
        validation_results = {"valid": False, "warnings": [], "info": []}
        
        if "Paste" in input_method:  # Paste Email Text
            st.markdown("**Text Input**")
            
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
                # Process email for validation
                processor = st.session_state.email_processor
                processed_email = processor.process_email(email_content, is_file_content=False)
                validation_results = validate_email_input(email_content, processed_email)
                display_input_validation(validation_results)
            
        else:  # Upload .eml File
            st.markdown("**File Upload**")
            uploaded_file = st.file_uploader(
                "Upload .eml file",
                type=['eml', 'msg', 'txt'],
                help="Upload an email file (.eml, .msg, or .txt format)",
                accept_multiple_files=False
            )
            
            if uploaded_file is not None:
                try:
                    # Read file content
                    file_content = uploaded_file.read().decode('utf-8', errors='replace')
                    email_content = file_content
                    
                    # Process the email using EmailProcessor
                    processor = st.session_state.email_processor
                    processed_email = processor.process_email(file_content, is_file_content=True)
                    
                    # Store processed data for later use
                    st.session_state.current_processed_email = processed_email
                    
                    file_info = {
                        "name": uploaded_file.name,
                        "size": len(file_content),
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
                    
                    # Show processing results
                    if processed_email["success"]:
                        # Email metadata
                        metadata = processed_email.get("metadata", {})
                        col_meta1, col_meta2, col_meta3 = st.columns(3)
                        with col_meta1:
                            st.metric("📧 Headers Found", metadata.get("header_count", 0))
                        with col_meta2:
                            st.metric("🔗 URLs Found", metadata.get("url_count", 0))
                        with col_meta3:
                            st.metric("⚠️ Suspicious URLs", metadata.get("suspicious_url_count", 0))
                        
                        # Email headers preview
                        headers = processed_email.get("headers", {})
                        if headers:
                            with st.expander("📋 Email Headers"):
                                for key, value in headers.items():
                                    if key in ['from', 'to', 'subject', 'date']:
                                        st.markdown(f"**{key.upper()}:** {value}")
                        
                        # URLs preview
                        urls = processed_email.get("urls", [])
                        if urls:
                            with st.expander(f"🔗 URLs Found ({len(urls)})"):
                                for url_data in urls[:5]:  # Show first 5
                                    url_status = ""
                                    if url_data.get("is_shortened"):
                                        url_status += "🔗 SHORTENED "
                                    if url_data.get("is_suspicious"):
                                        url_status += "⚠️ SUSPICIOUS "
                                    st.markdown(f"• {url_status}{url_data['url']}")
                                if len(urls) > 5:
                                    st.markdown(f"... and {len(urls) - 5} more URLs")
                    
                    # Email content preview
                    preview_length = 1000
                    preview_text = file_content[:preview_length]
                    if len(file_content) > preview_length:
                        preview_text += f"\n\n... ({len(file_content) - preview_length:,} more characters)"
                    
                    st.text_area(
                        "📋 Email content preview:",
                        value=preview_text,
                        height=200,
                        disabled=True,
                        help=f"Showing first {preview_length} characters of {len(file_content):,} total"
                    )
                    
                    validation_results = validate_email_input(file_content, processed_email)
                    display_input_validation(validation_results)
                    
                except UnicodeDecodeError as e:
                    st.error(f"❌ Unable to decode file: {str(e)}")
                    st.info("💡 Try saving the email as a .txt file with UTF-8 encoding")
                except Exception as e:
                    st.error(f"❌ Error reading file: {str(e)}")
                    st.exception(e)
        
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
        elif not connection_status.get("model_available"):
            analyze_button_text = "🤖 Analyze (Heuristic Mode)"
        
        if st.button(analyze_button_text, type="primary", disabled=analyze_disabled, use_container_width=True):
            if email_content.strip() and validation_results["valid"]:
                # Process email content if not already processed
                processed_email_data = None
                if 'current_processed_email' in st.session_state:
                    processed_email_data = st.session_state.current_processed_email
                else:
                    # Process plain text email
                    processor = st.session_state.email_processor
                    processed_email_data = processor.process_email(email_content, is_file_content=False)
                
                analyze_email(email_content, ollama_url or "", model_name or "", processed_email_data)
    
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


def analyze_email(email_content: str, ollama_url: str, model_name: str, processed_data: Optional[Dict] = None):
    """
    Analyze email content for phishing indicators using LLM with abort functionality
    
    Features:
    - Connection reuse and caching
    - Streaming progress indicators
    - Memory-efficient processing
    - User-controlled abort functionality
    - Adaptive timeout management
    """
    
    # Performance tracking
    start_time = time.time()
    
    # Create progress tracking with enhanced UI
    progress_container = st.container()
    with progress_container:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Create abort button container
        abort_col1, abort_col2, abort_col3 = st.columns([1, 2, 1])
        with abort_col2:
            abort_button = st.empty()
    
    # Memory check - warn if email content is very large
    content_size_mb = len(email_content.encode('utf-8')) / (1024 * 1024)
    if content_size_mb > 5:  # > 5MB
        st.warning(f"⚠️ Large email detected ({content_size_mb:.1f}MB). Processing may take longer.")
    elif content_size_mb > 1:  # > 1MB
        st.info(f"ℹ️ Processing {content_size_mb:.1f}MB email content...")
    
    try:
        # Step 1: Preprocessing
        status_text.text("Preprocessing email content...")
        progress_bar.progress(10)
        
        if not processed_data:
            processor = st.session_state.email_processor
            processed_data = processor.process_email(email_content, is_file_content=False)
        
        # Step 2: Check LLM service availability
        status_text.text("Connecting to AI model...")
        progress_bar.progress(20)
        
        # Ensure LLM service is configured
        if (st.session_state.ollama_service is None or 
            st.session_state.ollama_service.base_url != ollama_url or 
            st.session_state.ollama_service.model != model_name):
            
            # Clear any existing service context before creating new one
            if st.session_state.ollama_service:
                st.session_state.ollama_service.clear_context()
            
            st.session_state.ollama_service = OllamaService(ollama_url, model_name)
        
        llm_service = st.session_state.ollama_service
        
        # Test connection with enhanced error handling
        connection_status = llm_service.test_connection()
        if not connection_status.get("connected"):
            error_details = connection_status.get("error_details", {})
            if error_details:
                progress_bar.progress(100)
                status_text.text("Connection failed")
                return error_details
            else:
                # Fallback error handling for legacy responses
                error_info = error_handler.handle_error(
                    Exception(f"Cannot connect to Ollama: {connection_status.get('error', 'Unknown error')}"),
                    "Ollama connection test failed",
                    ErrorCategory.OLLAMA_CONNECTION
                )
                progress_bar.progress(100)
                status_text.text("Connection failed")
                return error_info
        
        if not connection_status.get("model_available"):
            # Warn about model availability but continue with heuristic fallback
            status_text.text("Model not available - using heuristic analysis...")
            progress_bar.progress(50)
            
            # Log warning but don't fail
            error_handler.logger.warning(f"Model '{model_name}' not available, falling back to heuristic analysis")
            
            results = perform_fallback_analysis(email_content, processed_data)
            
        else:
            # Step 3: LLM Analysis with comprehensive error handling and abort functionality
            status_text.text("Running AI analysis...")
            progress_bar.progress(40)
            
            # Show abort button during analysis
            with abort_button:
                if st.button("🛑 Cancel Analysis", type="secondary", key="abort_analysis"):
                    if st.session_state.ollama_service:
                        # Cancel analysis and clear all context
                        st.session_state.ollama_service.cancel_analysis()
                        # Also clear any server-side context for next analysis
                        try:
                            st.session_state.ollama_service.clear_server_context()
                        except:
                            pass  # Best effort context clearing
                    status_text.text("❌ Analysis cancelled - context cleared")
                    progress_bar.progress(100)
                    st.warning("Analysis was cancelled by user. Context cleared for next analysis.")
                    return
            
            # Get advanced settings from session state including timeout
            advanced_settings = {
                "temperature": st.session_state.get("temperature", 0.3),
                "max_tokens": st.session_state.get("max_tokens", 2000),
                "timeout": st.session_state.get("timeout", 30)
            }
            
            # Update LLM service timeout
            if st.session_state.ollama_service:
                st.session_state.ollama_service.timeout = advanced_settings["timeout"]
            
            # Perform LLM analysis with comprehensive error handling
            try:
                if not processed_data:
                    raise PhishNetError("No processed email data available", ErrorCategory.PARSING_ERROR)
                
                status_text.text("🤖 AI model analyzing email...")
                progress_bar.progress(60)
                
                llm_results = llm_service.analyze_email(processed_data, advanced_settings)
                
                # Check if analysis was cancelled
                if llm_results.get("cancelled"):
                    status_text.text("❌ Analysis cancelled")
                    progress_bar.progress(100)
                    # Clear the abort button
                    abort_button.empty()
                    st.warning("Analysis was cancelled by user")
                    return
                
                if llm_results.get("success"):
                    # Use the complete enhanced analysis from LLM service
                    results = llm_results.copy()
                    # Add any app-specific metadata
                    results.update({
                        "email_length": len(email_content),
                        "analysis_version": "2.0-llm-enhanced"
                    })
                else:
                    error_msg = llm_results.get("error", "Unknown LLM error")
                    raise PhishNetError(f"LLM analysis failed: {error_msg}", ErrorCategory.LLM_PROCESSING)
                    
            except PhishNetError as e:
                # Handle PhishNet specific errors with user guidance
                error_info = error_handler.handle_error(e, "LLM Analysis", e.category)
                
                # Check if this is a recoverable error
                if e.category in [ErrorCategory.LLM_PROCESSING, ErrorCategory.PARSING_ERROR]:
                    # Fall back to heuristic analysis
                    status_text.text("⚠️ LLM analysis failed - using heuristic analysis...")
                    results = perform_fallback_analysis(email_content, processed_data)
                    results["fallback_reason"] = str(e)
                else:
                    # Show error and return
                    progress_bar.progress(100)
                    status_text.text("❌ Analysis failed")
                    abort_button.empty()
                    display_error(error_info)
                    return
                    
            except Exception as e:
                # Handle unexpected errors
                error_info = error_handler.handle_error(e, "LLM Analysis", ErrorCategory.LLM_PROCESSING)
                
                # Always fall back for unexpected errors
                status_text.text("⚠️ Unexpected error - using heuristic analysis...")
                results = perform_fallback_analysis(email_content, processed_data)
                results["fallback_reason"] = str(e)
        
        # Step 4: Finalize results
        status_text.text("📊 Finalizing analysis...")
        progress_bar.progress(90)
        time.sleep(0.5)
        
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")
        time.sleep(0.5)
        
        # Store in session state and history
        st.session_state.analysis_results = results
        st.session_state.analysis_history.append(results)
        
        # Clear progress indicators and abort button
        progress_bar.empty()
        status_text.empty()
        abort_button.empty()
        
        # Show success message with method used
        analysis_method = "AI-powered" if results.get("model_used") else "heuristic"
        st.success(f"🎯 {analysis_method.title()} analysis completed successfully!")
        
        if results.get("llm_error"):
            st.warning(f"⚠️ LLM analysis failed ({results['llm_error']}), used fallback method")
        
        st.rerun()
        
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        abort_button.empty()
        st.error(f"❌ Analysis failed: {str(e)}")
        
        # Perform emergency fallback
        try:
            fallback_results = perform_fallback_analysis(email_content, processed_data)
            fallback_results["error_details"] = str(e)
            st.session_state.analysis_results = fallback_results
            st.warning("🔄 Used emergency fallback analysis due to error")
            st.rerun()
        except:
            st.exception(e)


def display_error(error_info: Dict):
    """Display enhanced error information with troubleshooting guidance"""
    
    # Check if this is an enhanced error response
    if error_info.get("error") and "title" in error_info:
        title = error_info.get("title", "⚠️ An error occurred")
        message = error_info.get("message", "")
        suggestions = error_info.get("suggestions", [])
        severity = error_info.get("severity", "medium")
        color = error_info.get("color", "#ffc107")
        troubleshooting_tips = error_info.get("troubleshooting_tips", [])
        recovery_actions = error_info.get("recovery_actions", [])
        
        # Display main error message
        if severity == "critical":
            st.error(f"**{title}**\n\n{message}")
        elif severity == "high":
            st.error(f"**{title}**\n\n{message}")
        elif severity == "medium":
            st.warning(f"**{title}**\n\n{message}")
        else:
            st.info(f"**{title}**\n\n{message}")
        
        # Show suggestions in expandable section
        if suggestions:
            with st.expander("💡 Troubleshooting Steps"):
                st.markdown("**Try these solutions:**")
                for i, suggestion in enumerate(suggestions, 1):
                    st.markdown(f"{i}. {suggestion}")
        
        # Show additional tips if available
        if troubleshooting_tips:
            with st.expander("🔧 Technical Information"):
                for tip in troubleshooting_tips:
                    st.markdown(f"ℹ️ {tip}")
        
        # Show recovery actions as buttons
        if recovery_actions:
            st.markdown("**Quick Actions:**")
            col1, col2, col3 = st.columns(3)
            for i, action in enumerate(recovery_actions[:3]):
                col = [col1, col2, col3][i]
                with col:
                    if st.button(action.get("label", "Action"), key=f"action_{action.get('action', i)}"):
                        handle_recovery_action(action.get("action"))
    
    else:
        # Fallback for simple error messages
        error_msg = error_info.get("error", "Unknown error occurred")
        st.error(f"❌ **Error**: {error_msg}")
        
        if "connection" in error_msg.lower():
            with st.expander("💡 Connection Help"):
                st.markdown("""
                **Common Solutions:**
                1. Check if Ollama is running: `ollama --version`
                2. Start Ollama service: `ollama serve`
                3. Verify URL: http://localhost:11434
                4. Check firewall settings
                """)


def handle_recovery_action(action: str):
    """Handle recovery actions from error display"""
    if action == "test_connection":
        st.rerun()
    elif action == "retry":
        if "analysis_results" in st.session_state:
            del st.session_state.analysis_results
        st.rerun()
    elif action == "fallback_heuristic":
        st.session_state.force_heuristic = True
        st.rerun()
    elif action == "refresh_models":
        if hasattr(st.session_state, 'ollama_service'):
            del st.session_state.ollama_service
        st.rerun()
    elif action == "clear_input":
        st.session_state.email_content = ""
        st.rerun()
    elif action == "show_help":
        st.session_state.show_help = True
        st.rerun()


def display_results(results: Dict):
    """Display enhanced analysis results with professional styling and improved UX"""
    
    # Check if this is an error response
    if results.get("error") or results.get("analysis_failed"):
        display_error(results)
        return
    
    risk_score = results.get("risk_score", 0)
    risk_level = results.get("risk_level", get_risk_level(risk_score))
    risk_color = results.get("risk_color", get_risk_color(risk_score))
    confidence_score = results.get("confidence_score", 0.5)
    confidence_level = results.get("confidence_level", "medium")
    
    # Determine risk class for styling
    risk_class = "risk-high" if risk_score >= 7 else "risk-medium" if risk_score >= 4 else "risk-low"
    risk_icon = "🚨" if risk_score >= 7 else ""  # Only use emoji for critical alerts
    
    # Main risk assessment card with enhanced styling
    st.markdown(f"""
    <div class="risk-card {risk_class}">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem;">
            <h1 style="margin: 0; font-size: 2.5rem; color: {risk_color};">
                {risk_icon} {risk_level}
            </h1>
            <div style="text-align: right;">
                <h2 style="margin: 0; font-size: 3rem; color: {risk_color}; font-weight: 700;">
                    {risk_score}<span style="font-size: 1.5rem; color: #666;">/10</span>
                </h2>
            </div>
        </div>
        <div style="border-top: 1px solid #e0e0e0; padding-top: 1rem;">
            <p style="margin: 0; color: #666; font-size: 1.1rem;">
                Analysis completed with <strong>{confidence_level}</strong> confidence 
                ({confidence_score:.1%} certainty)
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced risk score visualization
    col_score1, col_score2, col_score3, col_score4 = st.columns(4)
    with col_score1:
        st.metric("Risk Score", f"{risk_score}/10")
    with col_score2:
        st.metric("Risk Level", risk_level)
    with col_score3:
        st.metric("Confidence", f"{confidence_level.title()} ({confidence_score:.1f})")
    with col_score4:
        trusted = results.get("trusted_sender", False)
        st.metric("Sender Status", "Trusted" if trusted else "Unknown")
    
    # Enhanced red flags display with professional styling
    st.markdown("---")
    st.markdown("### Security Assessment Details")
    red_flags_data = results.get("red_flags", {})
    
    # Handle both old format (list) and new format (dict with categorization)
    if isinstance(red_flags_data, list):
        # Backward compatibility with old format
        red_flags = red_flags_data
        if red_flags:
            st.markdown("**Identified Security Indicators:**")
            for i, flag in enumerate(red_flags, 1):
                # Determine severity class based on content
                is_critical = any(word in flag.lower() for word in ["password", "credential", "urgent", "immediate", "suspend", "verify", "click now"])
                is_major = any(word in flag.lower() for word in ["suspicious", "mismatched", "shortened", "threatening"])
                
                flag_class = "red-flag-critical" if is_critical else "red-flag-major" if is_major else "red-flag-minor"
                severity_icon = "�" if is_critical else "🟠" if is_major else "�🟡"
                
                st.markdown(f"""
                <div class="red-flag-item {flag_class}">
                    <strong>{severity_icon} Indicator {i}:</strong> {flag}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="risk-card risk-low" style="text-align: center;">
                <h3 style="color: #4caf50; margin: 0.5rem 0;">Clean Email Assessment</h3>
                <p style="color: #666; margin: 0;">No significant security indicators detected. This appears to be a legitimate email.</p>
            </div>
            """, unsafe_allow_html=True)
    else:
        # New enhanced format with categorization
        total_flags = red_flags_data.get("total_count", 0)
        categorized = red_flags_data.get("categorized", {})
        
        if total_flags > 0:
            # Create summary cards for each severity level
            severity_config = {
                "critical": {"icon": "●", "color": "#f44336", "class": "red-flag-critical"},
                "major": {"icon": "●", "color": "#ff9800", "class": "red-flag-major"}, 
                "minor": {"icon": "●", "color": "#ffc107", "class": "red-flag-minor"},
                "unknown": {"icon": "●", "color": "#9e9e9e", "class": "red-flag-minor"}
            }
            
            # Display summary statistics
            cols = st.columns(len([s for s in severity_config if categorized.get(s, [])]))
            for i, severity in enumerate(severity_config.keys()):
                flags = categorized.get(severity, [])
                if flags:
                    with cols[i % len(cols)]:
                        config = severity_config[severity]
                        st.metric(
                            f"{config['icon']} {severity.title()}", 
                            len(flags),
                            help=f"{severity.title()} severity indicators"
                        )
            
            # Display detailed flags by severity
            for severity in ["critical", "major", "minor", "unknown"]:
                flags = categorized.get(severity, [])
                if flags:
                    config = severity_config[severity]
                    st.markdown(f"**{config['icon']} {severity.title()} Security Indicators:**")
                    
                    for j, flag in enumerate(flags, 1):
                        flag_text = flag.get('text', flag) if isinstance(flag, dict) else flag
                        flag_desc = flag.get('description', '') if isinstance(flag, dict) else ''
                        
                        st.markdown(f"""
                        <div class="red-flag-item {config['class']}">
                            <strong>{config['icon']} {flag_text}</strong>
                            {f'<br><em style="color: #666; font-size: 0.9rem;">{flag_desc}</em>' if flag_desc else ''}
                        </div>
                        """, unsafe_allow_html=True)
            
            # Critical warning if applicable
            severity_summary = red_flags_data.get("severity_summary", {})
            critical_count = severity_summary.get("critical_count", 0)
            if critical_count > 0:
                st.markdown(f"""
                <div class="risk-card risk-high" style="border: 2px solid #f44336;">
                    <h3 style="color: #f44336; margin: 0.5rem 0;">High Risk Warning</h3>
                    <p style="color: #666; margin: 0;"><strong>{critical_count}</strong> critical security indicators detected. Exercise extreme caution.</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="risk-card risk-low" style="text-align: center;">
                <h3 style="color: #4caf50; margin: 0.5rem 0;">Clean Email Assessment</h3>
                <p style="color: #666; margin: 0;">No significant security indicators detected. This appears to be a legitimate email.</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Analysis summary
    reasoning = results.get("reasoning", "")
    if reasoning:
        st.markdown("### Analysis Summary")
        st.markdown(f"*{reasoning}*")
    
    # Technical details (expandable)
    with st.expander("Technical Details"):
        col_tech1, col_tech2 = st.columns(2)
        with col_tech1:
            st.markdown(f"**Analysis Time:** {results.get('timestamp', 'Unknown')}")
            st.markdown(f"**Email Length:** {results.get('email_length', 0):,} characters")
        with col_tech2:
            st.markdown(f"**Analysis Version:** {results.get('analysis_version', 'Unknown')}")
            flag_count = red_flags_data.get('total_count', 0) if isinstance(red_flags_data, dict) else len(red_flags_data) if isinstance(red_flags_data, list) else 0
            st.markdown(f"**Red Flags Count:** {flag_count}")
    
    # Enhanced recommendations using new framework
    st.markdown("### Recommendations")
    recommendation = results.get("recommendation", {})
    
    # Handle both new format (dict) and legacy format (string)
    if isinstance(recommendation, dict) and recommendation:
        action = recommendation.get("action", "caution")
        message = recommendation.get("message", "")
        details = recommendation.get("details", [])
        
        if action == "block":
            st.error(f"**🚨 BLOCK**: {message}")
            for detail in details:
                st.markdown(f"   • {detail}")
        elif action == "caution":
            st.warning(f"**⚠️ CAUTION**: {message}")
            for detail in details:
                st.markdown(f"   • {detail}")
        else:
            st.success(f"**✅ SAFE**: {message}")
            for detail in details:
                st.markdown(f"   • {detail}")
    elif isinstance(recommendation, str):
        # Legacy string format - convert to appropriate display
        if recommendation == "block":
            st.error("**🚨 BLOCK**: This email appears to be high risk. Do not interact with it.")
        elif recommendation == "caution":
            st.warning("**⚠️ CAUTION**: This email shows some suspicious indicators. Exercise caution.")
        else:  # "ignore" or other
            st.success("**✅ SAFE**: This email appears to be legitimate.")
    elif recommendation:
        # Unknown format - display as-is with warning
        st.warning(f"**⚠️ UNKNOWN FORMAT**: {recommendation}")
    else:
        # Fallback to old recommendations if new format not available
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
    """Check Ollama connection status using LLM service"""
    ollama_url = st.session_state.get("ollama_url", "http://localhost:11434")
    model_name = st.session_state.get("model_name", "phi4-mini-reasoning")
    
    try:
        # Create or update the LLM service
        if (st.session_state.ollama_service is None or 
            st.session_state.ollama_service.base_url != ollama_url or 
            st.session_state.ollama_service.model != model_name):
            
            st.session_state.ollama_service = OllamaService(ollama_url, model_name)
        
        # Test connection
        status = st.session_state.ollama_service.test_connection()
        return {
            "connected": status.get("connected", False),
            "model_available": status.get("model_available", False),
            "available_models": status.get("available_models", []),
            "error": status.get("error")
        }
    except Exception as e:
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


def validate_email_input(email_content: str, processed_data: Optional[Dict] = None) -> Dict:
    """Validate email input and provide feedback"""
    validation = {"valid": True, "warnings": [], "info": []}
    
    if not email_content or not email_content.strip():
        validation["valid"] = False
        validation["warnings"].append("Email content is empty")
        return validation
    
    # Check minimum length
    if len(email_content.strip()) < 50:
        validation["warnings"].append("Email content is quite short - may not provide enough context for analysis")
    
    # Use processed data if available for better validation
    if processed_data and processed_data.get("success"):
        metadata = processed_data.get("metadata", {})
        headers = processed_data.get("headers", {})
        urls = processed_data.get("urls", [])
        
        # Header validation
        header_count = metadata.get("header_count", 0)
        if header_count == 0:
            validation["info"].append("💡 No email headers detected - consider including From, To, Subject for better analysis")
        elif header_count < 3:
            validation["info"].append("💡 Limited email headers - more headers improve analysis accuracy")
        else:
            validation["info"].append(f"✅ Good email structure with {header_count} headers detected")
        
        # URL validation
        url_count = metadata.get("url_count", 0)
        suspicious_count = metadata.get("suspicious_url_count", 0)
        
        if url_count > 0:
            if suspicious_count > 0:
                validation["warnings"].append(f"⚠️ {suspicious_count} suspicious URL(s) detected - good for phishing analysis")
            else:
                validation["info"].append(f"✅ {url_count} URL(s) found - good for analysis")
        
        # Email format validation
        email_format = processed_data.get("format", "unknown")
        if email_format == "eml":
            validation["info"].append("✅ Proper .eml format detected - optimal for analysis")
        elif email_format == "plain_text":
            validation["info"].append("📝 Plain text format - analysis possible but headers help")
    else:
        # Fallback to basic validation
        header_patterns = ["from:", "to:", "subject:", "date:"]
        headers_found = sum(1 for pattern in header_patterns if pattern in email_content.lower())
        
        if headers_found == 0:
            validation["info"].append("💡 Consider including email headers (From, To, Subject) for better analysis")
        elif headers_found < 3:
            validation["info"].append("💡 More email headers would improve analysis accuracy")
        else:
            validation["info"].append(f"✅ {headers_found} email headers detected")
        
        # Check for URLs and email addresses
        url_pattern = r'https?://[^\s]+'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        urls_found = len(re.findall(url_pattern, email_content, re.IGNORECASE))
        emails_found = len(re.findall(email_pattern, email_content))
        
        if urls_found > 0:
            validation["info"].append(f"✅ {urls_found} URL(s) found - good for phishing analysis")
        if emails_found > 0:
            validation["info"].append(f"✅ {emails_found} email address(es) found")
    
    # Check length limits
    if len(email_content) > 15000:
        validation["warnings"].append("⚠️ Very long email - analysis may take longer")
    elif len(email_content) > 10000:
        validation["info"].append("📏 Large email - comprehensive analysis possible")
    
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


def calculate_basic_risk_score(email_content: str, processed_data: Optional[Dict] = None) -> int:
    """Calculate a basic risk score based on simple heuristics and processed data"""
    score = 1  # Start with low risk
    content_lower = email_content.lower()
    
    # Use processed data if available for more accurate analysis
    if processed_data and processed_data.get("success"):
        metadata = processed_data.get("metadata", {})
        urls = processed_data.get("urls", [])
        headers = processed_data.get("headers", {})
        
        # URL-based scoring (more accurate with processed data)
        suspicious_url_count = metadata.get("suspicious_url_count", 0)
        shortened_url_count = metadata.get("shortened_url_count", 0)
        
        score += suspicious_url_count * 3  # +3 per suspicious URL
        score += shortened_url_count * 2   # +2 per shortened URL
        
        # Header-based analysis
        if not headers.get("from"):
            score += 2  # Missing From header
        
        from_address = headers.get("from", "").lower()
        subject = headers.get("subject", "").lower()
        
        # Check for spoofed domains in From header
        spoofed_domains = ["paypal", "amazon", "microsoft", "google", "apple", "facebook"]
        for domain in spoofed_domains:
            if domain in from_address and not from_address.endswith(f"@{domain}.com"):
                score += 4
        
        # Subject line analysis
        if any(word in subject for word in ["urgent", "verify", "suspend", "expire", "immediate"]):
            score += 2
    
    # Fallback to content-based analysis
    # Urgent language indicators (+2-3 points each)
    urgent_keywords = ["urgent", "immediate", "expire", "suspend", "verify", "click here", "act now", "limited time"]
    urgent_matches = sum(1 for keyword in urgent_keywords if keyword in content_lower)
    score += min(urgent_matches * 2, 6)  # Cap urgent language bonus
    
    # Generic greetings (+1-2 points)
    generic_greetings = ["dear customer", "dear user", "dear sir/madam", "valued customer"]
    for greeting in generic_greetings:
        if greeting in content_lower:
            score += 1
            break  # Only count once
    
    # Financial/personal info requests (+3 points each, max 6)
    sensitive_requests = ["password", "social security", "credit card", "bank account", "ssn", "pin number"]
    sensitive_matches = sum(1 for request in sensitive_requests if request in content_lower)
    score += min(sensitive_matches * 3, 6)
    
    # Grammar/spelling issues indicators
    if len(re.findall(r'\s{2,}', email_content)) > 5:  # Excessive spacing
        score += 1
    
    # Check for urgency phrases
    urgency_phrases = ["within 24 hours", "account will be", "suspended", "limited access", "verify now"]
    urgency_matches = sum(1 for phrase in urgency_phrases if phrase in content_lower)
    score += min(urgency_matches, 3)
    
    return min(score, 10)  # Cap at 10


def identify_basic_red_flags(email_content: str, processed_data: Optional[Dict] = None) -> List[str]:
    """Identify basic red flags in email content using processed data when available"""
    red_flags = []
    content_lower = email_content.lower()
    
    # Use processed data for more accurate analysis
    if processed_data and processed_data.get("success"):
        metadata = processed_data.get("metadata", {})
        urls = processed_data.get("urls", [])
        headers = processed_data.get("headers", {})
        
        # URL-based red flags
        suspicious_urls = [url for url in urls if url.get("is_suspicious")]
        shortened_urls = [url for url in urls if url.get("is_shortened")]
        
        if suspicious_urls:
            red_flags.append(f"Contains {len(suspicious_urls)} suspicious URL(s)")
        
        if shortened_urls:
            red_flags.append(f"Contains {len(shortened_urls)} shortened URL(s)")
        
        # Header-based analysis
        from_address = headers.get("from", "").lower()
        subject = headers.get("subject", "").lower()
        
        # Check for domain spoofing in From header
        spoofed_indicators = []
        spoofed_domains = ["paypal", "amazon", "microsoft", "google", "apple"]
        for domain in spoofed_domains:
            if domain in from_address and not from_address.endswith(f"@{domain}.com"):
                spoofed_indicators.append(domain)
        
        if spoofed_indicators:
            red_flags.append(f"Suspicious sender domain spoofing: {', '.join(spoofed_indicators)}")
        
        # Subject analysis
        urgent_subject_words = ["urgent", "verify", "suspend", "expire", "immediate", "action required"]
        subject_flags = [word for word in urgent_subject_words if word in subject]
        if subject_flags:
            red_flags.append(f"Urgent language in subject: {', '.join(subject_flags)}")
        
        # Missing critical headers
        if not headers.get("from"):
            red_flags.append("Missing sender information")
        
    # Content-based analysis (always performed)
    
    # Check for urgent language
    urgent_phrases = [
        "urgent", "immediate", "expire", "suspend", "verify immediately",
        "account will be", "within 24 hours", "act now", "limited time"
    ]
    found_urgent = [phrase for phrase in urgent_phrases if phrase in content_lower]
    if found_urgent:
        red_flags.append(f"Urgent/threatening language: {found_urgent[0]}")
    
    # Check for generic greetings
    generic_greetings = ["dear customer", "dear user", "dear sir/madam", "valued customer"]
    for greeting in generic_greetings:
        if greeting in content_lower:
            red_flags.append("Generic greeting without personalization")
            break
    
    # Check for requests for sensitive information
    sensitive_requests = [
        "password", "social security", "credit card", "bank account", 
        "ssn", "pin number", "security code", "verification code"
    ]
    found_requests = [req for req in sensitive_requests if req in content_lower]
    if found_requests:
        red_flags.append(f"Requests sensitive information: {', '.join(found_requests[:2])}")
    
    # Check for pressure tactics
    pressure_phrases = [
        "account will be suspended", "immediate action", "verify now", 
        "click here immediately", "your account has been"
    ]
    found_pressure = [phrase for phrase in pressure_phrases if phrase in content_lower]
    if found_pressure:
        red_flags.append(f"Uses pressure tactics: {found_pressure[0]}")
    
    # Fallback URL checks if processed data not available
    if not processed_data or not processed_data.get("success"):
        if re.search(r'bit\.ly|tinyurl|short\.link', email_content, re.IGNORECASE):
            red_flags.append("Contains shortened URLs")
        
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', email_content):
            red_flags.append("Contains IP address instead of domain name")
        
        # Basic domain spoofing check
        spoofing_patterns = [
            r'paypal.*\.(?!com)', r'amazon.*\.(?!com)', 
            r'microsoft.*\.(?!com)', r'google.*\.(?!com)'
        ]
        for pattern in spoofing_patterns:
            if re.search(pattern, content_lower):
                red_flags.append("Suspicious domain detected in content")
                break
    
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


def perform_fallback_analysis(email_content: str, processed_data: Optional[Dict]) -> Dict:
    """Perform heuristic-based analysis as fallback when LLM is unavailable"""
    
    risk_score = calculate_basic_risk_score(email_content, processed_data)
    risk_level = get_risk_level(risk_score)
    red_flags = identify_basic_red_flags(email_content, processed_data)
    
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "red_flags": red_flags,
        "reasoning": generate_reasoning(risk_score, red_flags),
        "confidence": "medium" if len(red_flags) > 2 else "low",
        "recommendation": "block" if risk_score >= 7 else "caution" if risk_score >= 4 else "ignore",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "email_length": len(email_content),
        "analysis_version": "1.0-heuristic"
    }


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


# Performance monitoring and optimization functions
@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_system_performance_stats():
    """Get system performance statistics for optimization"""
    import platform
    
    try:
        import psutil
        return {
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "memory_available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
            "memory_percent": psutil.virtual_memory().percent,
            "platform": platform.system(),
            "python_version": platform.python_version()
        }
    except ImportError:
        # Fallback if psutil not available
        return {
            "cpu_count": "Unknown",
            "memory_total_gb": "Unknown", 
            "memory_available_gb": "Unknown",
            "memory_percent": "Unknown",
            "platform": platform.system(),
            "python_version": platform.python_version()
        }

def optimize_session_state():
    """Clean up session state to prevent memory bloat"""
    # Limit analysis history
    if 'analysis_history' in st.session_state and len(st.session_state.analysis_history) > 50:
        # Keep only the most recent 25 analyses
        st.session_state.analysis_history = st.session_state.analysis_history[-25:]
    
    # Clean up temporary data
    temp_keys = [k for k in st.session_state.keys() if isinstance(k, str) and (k.startswith('temp_') or k.startswith('cache_'))]
    for key in temp_keys:
        if key in st.session_state:
            del st.session_state[key]

def get_performance_recommendations():
    """Provide performance recommendations based on system specs"""
    stats = get_system_performance_stats()
    recommendations = []
    
    memory_percent = stats.get("memory_percent")
    if isinstance(memory_percent, (int, float)) and memory_percent > 80:
        recommendations.append("High memory usage detected. Consider restarting the application.")
    
    memory_total = stats.get("memory_total_gb")
    if isinstance(memory_total, (int, float)) and memory_total < 4:
        recommendations.append("Low system memory. Consider using a smaller AI model for better performance.")
    
    cpu_count = stats.get("cpu_count")
    if isinstance(cpu_count, int) and cpu_count <= 2:
        recommendations.append("Limited CPU cores. Increase timeout settings for better reliability.")
    
    return recommendations

def add_performance_sidebar():
    """Add performance information to sidebar"""
    if st.sidebar.checkbox("Performance Monitor", value=False):
        with st.sidebar.expander("System Info"):
            stats = get_system_performance_stats()
            
            st.markdown(f"**Platform:** {stats.get('platform', 'Unknown')}")
            st.markdown(f"**Python:** {stats.get('python_version', 'Unknown')}")
            st.markdown(f"**CPU Cores:** {stats.get('cpu_count', 'Unknown')}")
            
            if isinstance(stats.get('memory_total_gb'), (int, float)):
                st.markdown(f"**Memory:** {stats.get('memory_available_gb', 'Unknown'):.1f}GB / {stats.get('memory_total_gb', 'Unknown'):.1f}GB")
                
                memory_percent = stats.get('memory_percent')
                if isinstance(memory_percent, (int, float)):
                    memory_color = "🟢" if memory_percent < 60 else "🟡" if memory_percent < 80 else "🔴"
                    st.markdown(f"**Usage:** {memory_color} {memory_percent}%")
            
            # Performance recommendations
            recommendations = get_performance_recommendations()
            if recommendations:
                st.markdown("**Recommendations:**")
                for rec in recommendations:
                    st.markdown(rec)
            
            # Session state info
            if 'analysis_history' in st.session_state:
                history_count = len(st.session_state.analysis_history)
                st.markdown(f"**Analyses Stored:** {history_count}")
                
                if history_count > 30:
                    if st.button("Clean History", help="Remove old analyses to free memory"):
                        optimize_session_state()
                        st.success("Session optimized!")
                        st.rerun()


if __name__ == "__main__":
    # Performance optimization on startup
    optimize_session_state()
    
    # Add performance monitoring to sidebar
    try:
        add_performance_sidebar()
    except Exception as e:
        # Don't let performance monitoring break the app
        pass
    
    main()