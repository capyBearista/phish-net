"""
LLM Service Module for Phish-Net

This module handles communication with Ollama and prompt engineering designed for the LLM.
"""

import json
import requests
from typing import Dict, List, Optional, Tuple
import time
import threading
from datetime import datetime

# Handle both relative and absolute imports
try:
    from .risk_assessment import RiskAssessment
    from .error_handling import error_handler, handle_ollama_error, ErrorCategory, PhishNetError
except ImportError:
    from risk_assessment import RiskAssessment
    from error_handling import error_handler, handle_ollama_error, ErrorCategory, PhishNetError


class OllamaService:
    """
    Service for communicating with Ollama API and managing the LLM.
    
    Features:
    - Connection pooling and caching for improved performance
    - Adaptive timeout based on response times
    - Memory-efficient request handling
    - Request cancellation and abort functionality
    - Batch processing capabilities (future enhancement)
    
    Handles prompt engineering, API communication, and response validation
    specifically optimized for phishing email analysis.
    """
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "phi4-mini"):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = 90  # Adaptive timeout, will be adjusted based on performance
        self.max_retries = 3
        self.risk_assessor = RiskAssessment()
        
        # Performance tracking for adaptive optimization
        self._request_times = []
        self._connection_cache = None
        self._cache_timestamp = None
        
        # Cancellation support
        self._cancel_event = threading.Event()
        self._current_session = None
        
    def test_connection(self) -> Dict:
        """Test connection to Ollama and model availability"""
        try:
            # Test basic connection
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code != 200:
                error_info = handle_ollama_error(
                    Exception(f"HTTP {response.status_code}"),
                    f"Ollama server returned HTTP {response.status_code}"
                )
                return {
                    "connected": False, 
                    "error": f"HTTP {response.status_code}",
                    "error_details": error_info
                }
            
            # Check if our model is available
            models = response.json().get("models", [])
            model_names = [model.get("name", "") for model in models]
            
            model_available = any(self.model in name for name in model_names)
            
            # Warn if model not available
            if not model_available and model_names:
                error_handler.logger.warning(
                    f"Model '{self.model}' not found. Available: {', '.join(model_names[:3])}"
                )
            
            return {
                "connected": True,
                "model_available": model_available,
                "available_models": model_names,
                "ollama_version": response.headers.get("server", "unknown"),
                "health_status": "healthy" if model_available else "degraded"
            }
            
        except requests.exceptions.ConnectionError as e:
            error_info = handle_ollama_error(e, "Cannot connect to Ollama service")
            return {
                "connected": False, 
                "error": "Connection refused", 
                "error_details": error_info
            }
        except requests.exceptions.Timeout as e:
            error_info = error_handler.handle_error(e, "Ollama connection timeout", ErrorCategory.NETWORK_TIMEOUT)
            return {
                "connected": False, 
                "error": "Connection timeout", 
                "error_details": error_info
            }
        except Exception as e:
            error_info = handle_ollama_error(e, "Unexpected error during connection test")
            return {
                "connected": False, 
                "error": str(e), 
                "error_details": error_info
            }
    
    def cancel_analysis(self):
        """Cancel any ongoing analysis request and clear context"""
        self._cancel_event.set()
        
        # Clear any ongoing session to prevent context leakage
        if self._current_session:
            try:
                self._current_session.close()
            except:
                pass
            self._current_session = None
        
        # Clear any cached connection context
        self._connection_cache = None
        self._cache_timestamp = None
        
        error_handler.logger.info("Analysis cancellation requested and context cleared")
    
    def reset_cancel_state(self):
        """Reset cancellation state for new analysis and ensure clean context"""
        self._cancel_event.clear()
        
        # Ensure clean session for new analysis
        if self._current_session:
            try:
                self._current_session.close()
            except:
                pass
            self._current_session = None
    
    def clear_context(self):
        """Explicitly clear all context and cached data to ensure session isolation"""
        # Clear HTTP session
        if self._current_session:
            try:
                self._current_session.close()
            except:
                pass
            self._current_session = None
        
        # Clear connection cache
        self._connection_cache = None
        self._cache_timestamp = None
        
        # Clear performance tracking that might contain residual data
        self._request_times.clear()
        
        error_handler.logger.info("LLM service context cleared for new session")
    
    def clear_server_context(self):
        """Clear any server-side context in Ollama to ensure session isolation"""
        try:
            # Send a context-clearing request to Ollama
            # This uses a minimal prompt to reset any potential server-side state
            clear_request = {
                "model": self.model,
                "prompt": "Clear context.",
                "stream": False,
                "options": {
                    "temperature": 0.0,
                    "max_tokens": 1
                }
            }
            
            # Use a fresh session for context clearing
            with requests.Session() as session:
                response = session.post(
                    f"{self.base_url}/api/generate",
                    json=clear_request,
                    timeout=5  # Short timeout for context clearing
                )
                
                if response.status_code == 200:
                    error_handler.logger.debug("Server context cleared successfully")
                else:
                    error_handler.logger.warning(f"Context clearing failed with HTTP {response.status_code}")
                    
        except Exception as e:
            # Context clearing is best-effort, don't fail if it doesn't work
            error_handler.logger.debug(f"Context clearing attempt failed: {e}")
    
    def is_cancelled(self) -> bool:
        """Check if analysis has been cancelled"""
        return self._cancel_event.is_set()
    
    # ============================================================================
    # CHUNKED ANALYSIS PIPELINE - THREE PHASE APPROACH
    # ============================================================================
    
    def _analyze_structure(self, processed_email: Dict, settings: Optional[Dict] = None) -> Dict:
        """
        Phase 1: Analyze email structure, headers, and technical indicators.
        
        Focused on technical validation without content analysis to reduce
        hallucinations and improve accuracy on structural issues.
        
        Args:
            processed_email: Output from EmailProcessor
            settings: Optional LLM settings
            
        Returns:
            Dict with structural analysis results
        """
        if self.is_cancelled():
            return {"success": False, "cancelled": True, "phase": "structural"}
        
        try:
            # Create focused structural prompt
            prompt = self._create_structural_analysis_prompt(processed_email)
            
            # Set up request with phase-specific parameters
            request_data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": (settings or {}).get("temperature", 0.2),  # Lower temp for structured analysis
                    "top_p": 0.8,
                    "max_tokens": 800,  # Smaller response expected
                    "stop": ["</structural_analysis>", "Human:", "Assistant:"]
                }
            }
            
            # Make API request with shorter timeout for focused analysis
            start_time = time.time()
            response = self._make_api_request(request_data, timeout=45)
            response_time = time.time() - start_time
            
            if response.get("success"):
                # Parse structural response
                analysis_result = self._parse_structural_response(
                    response.get("response", ""), 
                    processed_email,
                    response_time
                )
                return analysis_result
            else:
                return self._create_phase_error_response("structural", response.get("error", "API request failed"))
                
        except Exception as e:
            error_info = error_handler.handle_error(
                e, "Phase 1 structural analysis failed", ErrorCategory.LLM_PROCESSING
            )
            return {
                "success": False,
                "phase": "structural", 
                "error": str(e),
                "user_message": error_info.get("user_message", "Structural analysis failed"),
                "timestamp": datetime.now().isoformat()
            }
    
    def _create_structural_analysis_prompt(self, processed_email: Dict) -> str:
        """Create focused prompt for Phase 1: Structural Analysis"""
        headers = processed_email.get("headers", {})
        metadata = processed_email.get("metadata", {})
        
        # Extract key structural information
        sender = headers.get("from", "Unknown")
        return_path = headers.get("return-path", "Not provided") 
        message_id = headers.get("message-id", "Not provided")
        mime_version = headers.get("mime-version", "Not provided")
        received_headers = headers.get("received", "Not provided")
        
        sender_domain = metadata.get("sender_domain", "")
        format_type = processed_email.get("format", "unknown")
        
        prompt = f"""<structural_analysis>
You are analyzing the technical structure of an email for format and authentication issues.

FOCUS: Technical indicators only - NOT content analysis or familiarity judgments.

EMAIL HEADERS:
=============
From: {sender}
Return-Path: {return_path}
Message-ID: {message_id}
MIME-Version: {mime_version}
Received: {received_headers[:200] if isinstance(received_headers, str) else "Multiple headers"}
Format Type: {format_type}

SENDER DOMAIN ANALYSIS:
======================
Domain: {sender_domain}

ANALYSIS REQUIREMENTS:
=====================
1. HEADER CONSISTENCY: Check if headers are properly formatted and consistent
2. DOMAIN LEGITIMACY: Assess if sender domain appears legitimate (NOT familiar - legitimate)
3. FORMAT QUALITY: Evaluate technical email format compliance
4. AUTHENTICATION HINTS: Note any obvious authentication indicators

IMPORTANT RULES:
- ANY .com/.org/.net domain = LEGITIMATE corporate domain (default assumption)
- .gov/.edu = INSTITUTIONAL (highly legitimate) 
- Missing headers = FORMAT ISSUE (not suspicious domain)
- microsft.com vs microsoft.com = SPOOFING (obvious typo domains)
- Raw IP addresses as senders = SUSPICIOUS
- Brief emails may lack some headers (normal for internal communications)

LEGITIMATE DOMAIN EXAMPLES (default assumption for standard TLDs):
- company.com = LEGITIMATE (standard corporate domain)
- github.com = LEGITIMATE (established service)
- randomcompany.com = LEGITIMATE (corporate domain)  
- university.edu = LEGITIMATE (educational)
- agency.gov = LEGITIMATE (government)
- business.org = LEGITIMATE (organization domain)
- service.net = LEGITIMATE (network domain)

SUSPICIOUS DOMAIN EXAMPLES (only clear spoofing/malicious patterns):
- microsft.com = SPOOFING (typo of microsoft.com)
- paypaI.com = SPOOFING (capital I instead of l)
- 192.168.1.1 = SUSPICIOUS (IP address sender)
- malicious.tk/.ru/.ml = SUSPICIOUS (known high-risk TLD patterns)
- phishing-site.suspicious = SUSPICIOUS (obviously malicious names)

CRITICAL: For domain_assessment, use "legitimate" for ALL standard business domains (.com/.org/.net) unless there's clear spoofing evidence like typos.

OUTPUT REQUIRED (JSON only):
{{
    "structural_risk": [1-4],
    "format_quality": "[good|poor|suspicious]",
    "header_issues": ["issue1", "issue2"],
    "domain_assessment": "[legitimate|suspicious|unknown]", 
    "authentication_hints": {{}},
    "confidence": "[high|medium|low]"
}}

DOMAIN ASSESSMENT RULES:
- company.com = "legitimate" (standard business domain)
- any-business.com = "legitimate" (standard business domain)  
- service.org = "legitimate" (organization domain)
- network.net = "legitimate" (network domain)
- university.edu = "legitimate" (educational domain)
- agency.gov = "legitimate" (government domain)
- microsft.com = "suspicious" (typo of microsoft.com)
- phishing.tk = "suspicious" (high-risk TLD)
- 192.168.1.1 = "suspicious" (IP address)
- Use "unknown" ONLY if domain is completely missing or malformed

SCORING GUIDELINES:
1: Perfect headers, .gov/.edu domains, excellent format
2: Good headers, standard .com/.org domains, good format  
3: Minor format issues, missing some headers (but legitimate domain)
4: Clear spoofing, IP senders, or obvious malicious patterns

Begin structural analysis now. Output only JSON:
</structural_analysis>"""
        
        return prompt
    
    def _parse_structural_response(self, raw_response: str, processed_email: Dict, response_time: float) -> Dict:
        """Parse and validate structural analysis response"""
        try:
            # Extract JSON from response
            json_match = self._extract_json_from_response(raw_response)
            
            if json_match:
                analysis = json.loads(json_match)
                
                # Validate structural response structure
                validated = self._validate_structural_response(analysis)
                
                # Add metadata
                validated.update({
                    "success": True,
                    "phase": "structural",
                    "processing_time": round(response_time, 2),
                    "timestamp": datetime.now().isoformat(),
                    "raw_response_length": len(raw_response)
                })
                
                return validated
            else:
                # Fallback parsing for structural analysis
                return self._fallback_structural_parse(raw_response, processed_email, response_time)
                
        except json.JSONDecodeError:
            return self._fallback_structural_parse(raw_response, processed_email, response_time)
        except Exception as e:
            return self._create_phase_error_response("structural", f"Parsing error: {str(e)}")
    
    def _validate_structural_response(self, analysis: Dict) -> Dict:
        """Validate and clean structural analysis response"""
        validated = {}
        
        # Validate structural_risk (1-4)
        structural_risk = analysis.get("structural_risk", 2)
        validated["structural_risk"] = max(1, min(4, int(structural_risk))) if isinstance(structural_risk, (int, float)) else 2
        
        # Validate format_quality
        format_quality = analysis.get("format_quality", "unknown")
        valid_qualities = ["good", "poor", "suspicious", "unknown"]
        validated["format_quality"] = format_quality if format_quality in valid_qualities else "unknown"
        
        # Validate header_issues
        header_issues = analysis.get("header_issues", [])
        if isinstance(header_issues, list):
            validated["header_issues"] = [str(issue)[:100] for issue in header_issues[:5]]
        else:
            validated["header_issues"] = []
        
        # Validate domain_assessment
        domain_assessment = analysis.get("domain_assessment", "unknown")
        valid_assessments = ["legitimate", "suspicious", "unknown"]
        validated["domain_assessment"] = domain_assessment if domain_assessment in valid_assessments else "unknown"
        
        # Validate authentication_hints
        auth_hints = analysis.get("authentication_hints", {})
        validated["authentication_hints"] = auth_hints if isinstance(auth_hints, dict) else {}
        
        # Validate confidence
        confidence = analysis.get("confidence", "medium")
        valid_confidences = ["low", "medium", "high"]
        validated["confidence"] = confidence if confidence in valid_confidences else "medium"
        
        return validated
    
    def _fallback_structural_parse(self, raw_response: str, processed_email: Dict, response_time: float) -> Dict:
        """Fallback parsing for structural analysis when JSON extraction fails"""
        
        # Basic heuristic analysis based on available data
        headers = processed_email.get("headers", {})
        metadata = processed_email.get("metadata", {})
        
        sender_domain = metadata.get("sender_domain", "").lower()
        
        # Simple domain assessment - default to legitimate for standard TLDs
        domain_assessment = "legitimate"  # Default assumption
        structural_risk = 2
        
        if sender_domain:
            if sender_domain.endswith(('.gov', '.edu')):
                domain_assessment = "legitimate"
                structural_risk = 1  # Institutional domains get best score
            elif sender_domain.endswith(('.com', '.org', '.net')):
                domain_assessment = "legitimate"  # Standard business domains
                structural_risk = 2
            elif sender_domain.endswith(('.ru', '.tk', '.ml', '.ga', '.cf')):
                domain_assessment = "suspicious" 
                structural_risk = 4  # High-risk TLDs
            elif '.' in sender_domain:
                domain_assessment = "legitimate"  # Any reasonable domain structure
                structural_risk = 2
            else:
                domain_assessment = "unknown"
                structural_risk = 3
        
        return {
            "success": True,
            "phase": "structural",
            "structural_risk": structural_risk,
            "format_quality": "unknown",
            "header_issues": ["Unable to parse detailed structural analysis"],
            "domain_assessment": domain_assessment,
            "authentication_hints": {},
            "confidence": "low",
            "processing_time": round(response_time, 2),
            "timestamp": datetime.now().isoformat(),
            "parsing_method": "fallback_heuristic"
        }
    
    def _make_api_request(self, request_data: Dict, timeout: Optional[int] = None) -> Dict:
        """Make API request with error handling and cancellation support"""
        timeout = timeout or self.timeout
        
        try:
            # Create session for this request to support cancellation
            self._current_session = requests.Session()
            
            response = self._current_session.post(
                f"{self.base_url}/api/generate",
                json=request_data,
                timeout=timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "response": result.get("response", ""),
                    "status_code": response.status_code
                }
            else:
                return {
                    "success": False,
                    "error": f"API request failed (HTTP {response.status_code})",
                    "status_code": response.status_code
                }
                
        except requests.exceptions.Timeout as e:
            return {
                "success": False,
                "error": f"Request timeout after {timeout}s",
                "exception_type": "timeout"
            }
        except requests.exceptions.ConnectionError as e:
            return {
                "success": False,
                "error": "Cannot connect to Ollama",
                "exception_type": "connection"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Request error: {str(e)}",
                "exception_type": "general"
            }
    
    def _create_phase_error_response(self, phase: str, error_message: str) -> Dict:
        """Create standardized error response for a specific phase"""
        return {
            "success": False,
            "phase": phase,
            "error": error_message,
            "timestamp": datetime.now().isoformat()
        }
    
    def _analyze_content(self, processed_email: Dict, structural_context: Dict, settings: Optional[Dict] = None) -> Dict:
        """
        Phase 2: Analyze email content, URLs, language patterns, and request types.
        
        Focused on message content without structural complexity to improve
        accuracy on phishing indicators and reduce false positives.
        
        Args:
            processed_email: Output from EmailProcessor
            structural_context: Results from Phase 1 structural analysis
            settings: Optional LLM settings
            
        Returns:
            Dict with content analysis results
        """
        if self.is_cancelled():
            return {"success": False, "cancelled": True, "phase": "content"}
        
        try:
            # Create focused content prompt
            prompt = self._create_content_analysis_prompt(processed_email, structural_context)
            
            # Set up request with phase-specific parameters
            request_data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": (settings or {}).get("temperature", 0.3),
                    "top_p": 0.85,
                    "max_tokens": 1000,  # Medium response expected
                    "stop": ["</content_analysis>", "Human:", "Assistant:"]
                }
            }
            
            # Make API request
            start_time = time.time()
            response = self._make_api_request(request_data, timeout=60)
            response_time = time.time() - start_time
            
            if response.get("success"):
                # Parse content response
                analysis_result = self._parse_content_response(
                    response.get("response", ""), 
                    processed_email,
                    structural_context,
                    response_time
                )
                return analysis_result
            else:
                return self._create_phase_error_response("content", response.get("error", "API request failed"))
                
        except Exception as e:
            error_info = error_handler.handle_error(
                e, "Phase 2 content analysis failed", ErrorCategory.LLM_PROCESSING
            )
            return {
                "success": False,
                "phase": "content", 
                "error": str(e),
                "user_message": error_info.get("user_message", "Content analysis failed"),
                "timestamp": datetime.now().isoformat()
            }
    
    def _create_content_analysis_prompt(self, processed_email: Dict, structural_context: Dict) -> str:
        """Create focused prompt for Phase 2: Content Analysis"""
        headers = processed_email.get("headers", {})
        body = processed_email.get("body", {})
        urls = processed_email.get("urls", [])
        
        # Extract key content information
        subject = headers.get("subject", "No subject")
        email_body = body.get("text", "") or body.get("html_text", "")
        
        # Get structural context
        domain_assessment = structural_context.get("domain_assessment", "unknown")
        structural_risk = structural_context.get("structural_risk", 2)
        
        # Prepare URL information  
        url_info = "None found"
        if urls:
            url_list = []
            for url in urls[:5]:  # Limit to first 5 URLs
                status = []
                if url.get("is_suspicious"): status.append("SUSPICIOUS")
                if url.get("is_shortened"): status.append("SHORTENED")
                status_text = f" [{', '.join(status)}]" if status else ""
                url_list.append(f"- {url['url']}{status_text}")
            url_info = "\n".join(url_list)
        
        prompt = f"""<content_analysis>
You are analyzing email content for phishing language patterns and malicious requests.

STRUCTURAL CONTEXT (from Phase 1):
Domain Assessment: {domain_assessment}
Structural Risk: {structural_risk}/4

CONTENT TO ANALYZE:
==================
Subject: {subject}

Body (first 1500 chars):
{email_body[:1500]}{"..." if len(email_body) > 1500 else ""}

URLs Found:
{url_info}

ANALYSIS FOCUS AREAS:
====================
1. LANGUAGE PATTERNS: Urgency, threats, poor grammar, generic greetings
2. REQUEST ANALYSIS: What is the email asking the recipient to do?
3. URL ASSESSMENT: Are links legitimate and consistent with sender?
4. CONTENT-SENDER ALIGNMENT: Does content match expected communication from this sender?

LEGITIMATE CONTENT TYPES (LOW CONTENT RISK 1-2):
- Professional business updates, newsletters, meeting invitations
- Standard notifications from services (GitHub, Microsoft, etc.)
- Personal communications between colleagues/friends
- Brief informational emails without requests
- Password reset confirmations from known services
- Standard corporate communications with professional language

SUSPICIOUS CONTENT TYPES (MEDIUM CONTENT RISK 3-4):
- Generic urgency without specific context ("act now", "limited time")
- Unsolicited offers or lottery notifications
- Poor grammar or spelling in professional contexts
- Generic greetings from services that should know your name
- Requests for personal information without clear business purpose

PHISHING CONTENT TYPES (HIGH CONTENT RISK 5-6):
- Direct requests for passwords, credentials, SSN, financial information  
- Threats of account closure or legal action with urgent deadlines
- Links to suspicious domains that don't match sender
- Obvious impersonation attempts with fake branding
- Download links for unexpected attachments or software
- Credential harvesting forms or fake login pages

REQUEST TYPE CATEGORIES:
- none: Informational only, no action requested
- information: Asking for non-sensitive information or confirmation
- credential: Requesting passwords, logins, or authentication details
- download: Asking to download files or software
- financial: Requesting money, payment info, or financial actions

URL ASSESSMENT GUIDELINES:
- Links to sender's own domain = LOW RISK (github.com email with github.com links)
- Links to unrelated but legitimate domains = MEDIUM RISK (needs explanation)
- Links to suspicious/shortened URLs = HIGH RISK
- No links = NO RISK

OUTPUT REQUIRED (JSON only):
{{
    "content_risk": [1-6],
    "language_flags": ["flag1", "flag2"],
    "url_risk": [1-4],
    "request_type": "[none|information|credential|download|financial]",
    "urgency_indicators": ["indicator1", "indicator2"],
    "confidence": "[high|medium|low]"
}}

SCORING GUIDELINES:
1-2: Professional content, no suspicious requests, legitimate URLs
3-4: Minor concerns, generic language, or unclear requests
5-6: Clear phishing indicators, credential requests, or malicious URLs

Begin content analysis now. Output only JSON:
</content_analysis>"""
        
        return prompt
    
    def _parse_content_response(self, raw_response: str, processed_email: Dict, structural_context: Dict, response_time: float) -> Dict:
        """Parse and validate content analysis response"""
        try:
            # Extract JSON from response
            json_match = self._extract_json_from_response(raw_response)
            
            if json_match:
                analysis = json.loads(json_match)
                
                # Validate content response structure
                validated = self._validate_content_response(analysis)
                
                # Add metadata
                validated.update({
                    "success": True,
                    "phase": "content",
                    "processing_time": round(response_time, 2),
                    "timestamp": datetime.now().isoformat(),
                    "raw_response_length": len(raw_response)
                })
                
                return validated
            else:
                # Fallback parsing for content analysis
                return self._fallback_content_parse(raw_response, processed_email, structural_context, response_time)
                
        except json.JSONDecodeError:
            return self._fallback_content_parse(raw_response, processed_email, structural_context, response_time)
        except Exception as e:
            return self._create_phase_error_response("content", f"Parsing error: {str(e)}")
    
    def _validate_content_response(self, analysis: Dict) -> Dict:
        """Validate and clean content analysis response"""
        validated = {}
        
        # Validate content_risk (1-6)
        content_risk = analysis.get("content_risk", 3)
        validated["content_risk"] = max(1, min(6, int(content_risk))) if isinstance(content_risk, (int, float)) else 3
        
        # Validate language_flags
        language_flags = analysis.get("language_flags", [])
        if isinstance(language_flags, list):
            validated["language_flags"] = [str(flag)[:100] for flag in language_flags[:5]]
        else:
            validated["language_flags"] = []
        
        # Validate url_risk (1-4)
        url_risk = analysis.get("url_risk", 1)
        validated["url_risk"] = max(1, min(4, int(url_risk))) if isinstance(url_risk, (int, float)) else 1
        
        # Validate request_type
        request_type = analysis.get("request_type", "none")
        valid_types = ["none", "information", "credential", "download", "financial"]
        validated["request_type"] = request_type if request_type in valid_types else "none"
        
        # Validate urgency_indicators
        urgency_indicators = analysis.get("urgency_indicators", [])
        if isinstance(urgency_indicators, list):
            validated["urgency_indicators"] = [str(indicator)[:100] for indicator in urgency_indicators[:3]]
        else:
            validated["urgency_indicators"] = []
        
        # Validate confidence
        confidence = analysis.get("confidence", "medium")
        valid_confidences = ["low", "medium", "high"]
        validated["confidence"] = confidence if confidence in valid_confidences else "medium"
        
        return validated
    
    def _fallback_content_parse(self, raw_response: str, processed_email: Dict, structural_context: Dict, response_time: float) -> Dict:
        """Fallback parsing for content analysis when JSON extraction fails"""
        
        # Basic heuristic analysis of content
        body = processed_email.get("body", {})
        email_body = body.get("text", "") or body.get("html_text", "")
        urls = processed_email.get("urls", [])
        
        # Simple content risk assessment
        content_risk = 2  # Default neutral
        language_flags = []
        urgency_indicators = []
        
        # Check for obvious phishing indicators
        phishing_keywords = ['urgent', 'immediately', 'suspend', 'verify', 'click here', 'act now']
        for keyword in phishing_keywords:
            if keyword.lower() in email_body.lower():
                content_risk += 1
                language_flags.append(f"Contains '{keyword}'")
        
        # URL risk assessment
        url_risk = 1
        if urls:
            suspicious_count = sum(1 for url in urls if url.get("is_suspicious", False))
            if suspicious_count > 0:
                url_risk = min(4, suspicious_count + 1)
        
        # Request type detection
        request_type = "none"
        if any(word in email_body.lower() for word in ['password', 'login', 'signin']):
            request_type = "credential"
        elif any(word in email_body.lower() for word in ['download', 'install', 'click']):
            request_type = "download"
        elif any(word in email_body.lower() for word in ['pay', 'money', 'payment']):
            request_type = "financial"
        elif '?' in email_body:
            request_type = "information"
        
        return {
            "success": True,
            "phase": "content",
            "content_risk": max(1, min(6, content_risk)),
            "language_flags": language_flags[:5],
            "url_risk": url_risk,
            "request_type": request_type,
            "urgency_indicators": urgency_indicators,
            "confidence": "low",
            "processing_time": round(response_time, 2),
            "timestamp": datetime.now().isoformat(),
            "parsing_method": "fallback_heuristic"
        }
    
    def _assess_intent(self, processed_email: Dict, structural_result: Dict, content_result: Dict, settings: Optional[Dict] = None) -> Dict:
        """
        Phase 3: Assess overall intent by synthesizing structural and content analysis.
        
        Combines results from Phases 1-2, applies domain trust weights, and generates
        final risk score with comprehensive reasoning.
        
        Args:
            processed_email: Output from EmailProcessor  
            structural_result: Results from Phase 1
            content_result: Results from Phase 2
            settings: Optional LLM settings
            
        Returns:
            Dict with final intent assessment results
        """
        if self.is_cancelled():
            return {"success": False, "cancelled": True, "phase": "intent"}
        
        try:
            # Calculate domain trust weight using risk assessor
            metadata = processed_email.get("metadata", {})
            sender_domain = metadata.get("sender_domain", "")
            trust_weight, trust_reason = self.risk_assessor.calculate_domain_trust_weight(sender_domain)
            
            # Create focused intent assessment prompt
            prompt = self._create_intent_assessment_prompt(
                structural_result, content_result, trust_weight, trust_reason
            )
            
            # Set up request with phase-specific parameters
            request_data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": (settings or {}).get("temperature", 0.25),  # Lower temp for final assessment
                    "top_p": 0.8,
                    "max_tokens": 800,  # Focused response expected  
                    "stop": ["</intent_assessment>", "Human:", "Assistant:"]
                }
            }
            
            # Make API request
            start_time = time.time()
            response = self._make_api_request(request_data, timeout=45)
            response_time = time.time() - start_time
            
            if response.get("success"):
                # Parse intent response
                analysis_result = self._parse_intent_response(
                    response.get("response", ""), 
                    processed_email,
                    structural_result,
                    content_result,
                    trust_weight,
                    response_time
                )
                return analysis_result
            else:
                return self._create_phase_error_response("intent", response.get("error", "API request failed"))
                
        except Exception as e:
            error_info = error_handler.handle_error(
                e, "Phase 3 intent assessment failed", ErrorCategory.LLM_PROCESSING
            )
            return {
                "success": False,
                "phase": "intent", 
                "error": str(e),
                "user_message": error_info.get("user_message", "Intent assessment failed"),
                "timestamp": datetime.now().isoformat()
            }
    
    def _create_intent_assessment_prompt(self, structural_result: Dict, content_result: Dict, trust_weight: int, trust_reason: str) -> str:
        """Create focused prompt for Phase 3: Intent Assessment"""
        
        # Extract key findings from previous phases
        structural_risk = structural_result.get("structural_risk", 2)
        domain_assessment = structural_result.get("domain_assessment", "unknown")
        format_quality = structural_result.get("format_quality", "unknown")
        
        content_risk = content_result.get("content_risk", 3)
        request_type = content_result.get("request_type", "none")
        language_flags = content_result.get("language_flags", [])
        url_risk = content_result.get("url_risk", 1)
        
        prompt = f"""<intent_assessment>
You are making the final assessment of email intent by synthesizing previous analysis phases.

PHASE 1 RESULTS (Structural):
=============================
Structural Risk: {structural_risk}/4
Domain Assessment: {domain_assessment}
Format Quality: {format_quality}

PHASE 2 RESULTS (Content):
==========================
Content Risk: {content_risk}/6
Request Type: {request_type}
URL Risk: {url_risk}/4
Language Flags: {language_flags}

DOMAIN TRUST ANALYSIS:
=====================
Trust Weight: {trust_weight} (negative reduces risk, positive increases)
Trust Reason: {trust_reason}

SYNTHESIS GUIDELINES:
====================
1. COMBINE RISKS: Add structural + content risks as base score
2. APPLY TRUST WEIGHT: Adjust score based on domain trust
3. ASSESS INTENT: Determine overall malicious intent level
4. FINAL SCORE: Generate 1-10 risk score with clear reasoning

RISK COMBINATION LOGIC:
Base Score = Structural Risk + Content Risk
Adjusted Score = Base Score + Trust Weight  
Final Score = max(1, min(10, Adjusted Score))

CRITICAL: Trust weight application is MANDATORY and MATHEMATICAL:
- Government domains (.gov): Trust weight -4 means SUBTRACT 4 from base score
- Educational domains (.edu): Trust weight -3 means SUBTRACT 3 from base score  
- Trusted corporate domains: Trust weight -2 means SUBTRACT 2 from base score
- If trust weight is negative, it STRONGLY indicates legitimate sender

INTENT CATEGORIES WITH TRUST WEIGHTING:
- LEGITIMATE: Business communication, newsletters, notifications (1-3)
  * Especially from trusted domains (.gov, .edu, major corporations)
- SUSPICIOUS: Unsolicited offers, unclear intent (4-6) 
  * Usually from unknown or unverified domains
- MALICIOUS: Clear phishing attempt, credential harvesting (7-10)
  * Rarely from genuinely trusted domains unless clear indicators present

RECOMMENDATION LOGIC:
- ignore: Risk score 1-3, legitimate business communication
- caution: Risk score 4-6, suspicious but not clearly malicious
- block: Risk score 7-10, clear phishing or malicious intent

PRIMARY CONCERN IDENTIFICATION:
Focus on the most significant risk factors from both phases.

OUTPUT REQUIRED (JSON only):
{{
    "risk_score": [1-10],
    "confidence": "[high|medium|low]",
    "primary_concerns": ["concern1", "concern2"],
    "recommendation": "[ignore|caution|block]",
    "reasoning": "Brief synthesis explanation including how phases combined and trust weight applied",
    "domain_trust_applied": {trust_weight}
}}

EXAMPLE REASONING:
"Structural analysis shows legitimate domain (company.com) with minor format issues (2/4). Content analysis indicates professional newsletter with no suspicious requests (2/6). Applied trust weight of 0 for standard business domain. Combined score: 2+2+0=4. Legitimate business communication."

Begin final intent assessment. Output only JSON:
</intent_assessment>"""
        
        return prompt
    
    def _parse_intent_response(self, raw_response: str, processed_email: Dict, structural_result: Dict, content_result: Dict, trust_weight: int, response_time: float) -> Dict:
        """Parse and validate intent assessment response"""
        try:
            # Extract JSON from response
            json_match = self._extract_json_from_response(raw_response)
            
            if json_match:
                analysis = json.loads(json_match)
                
                # Validate intent response structure
                validated = self._validate_intent_response(analysis)
                
                # Add comprehensive metadata including phase synthesis
                phase_synthesis = {
                    "structural_risk": structural_result.get("structural_risk", 0),
                    "content_risk": content_result.get("content_risk", 0), 
                    "trust_weight_applied": trust_weight,
                    "domain_assessment": structural_result.get("domain_assessment", "unknown"),
                    "request_type": content_result.get("request_type", "none"),
                    "total_processing_time": (
                        structural_result.get("processing_time", 0) + 
                        content_result.get("processing_time", 0) + 
                        response_time
                    )
                }
                
                validated.update({
                    "success": True,
                    "phase": "intent",
                    "processing_time": round(response_time, 2),
                    "timestamp": datetime.now().isoformat(),
                    "raw_response_length": len(raw_response),
                    "phase_synthesis": phase_synthesis
                })
                
                return validated
            else:
                # Fallback parsing for intent assessment
                return self._fallback_intent_parse(raw_response, processed_email, structural_result, content_result, trust_weight, response_time)
                
        except json.JSONDecodeError:
            return self._fallback_intent_parse(raw_response, processed_email, structural_result, content_result, trust_weight, response_time)
        except Exception as e:
            return self._create_phase_error_response("intent", f"Parsing error: {str(e)}")
    
    def _validate_intent_response(self, analysis: Dict) -> Dict:
        """Validate and clean intent assessment response"""
        validated = {}
        
        # Validate risk_score (1-10)
        risk_score = analysis.get("risk_score", 5)
        validated["risk_score"] = max(1, min(10, int(risk_score))) if isinstance(risk_score, (int, float)) else 5
        
        # Validate confidence
        confidence = analysis.get("confidence", "medium")
        valid_confidences = ["low", "medium", "high"]
        validated["confidence"] = confidence if confidence in valid_confidences else "medium"
        
        # Validate primary_concerns
        primary_concerns = analysis.get("primary_concerns", [])
        if isinstance(primary_concerns, list):
            validated["primary_concerns"] = [str(concern)[:100] for concern in primary_concerns[:5]]
        else:
            validated["primary_concerns"] = []
        
        # Validate recommendation
        recommendation = analysis.get("recommendation", "caution")
        valid_recommendations = ["ignore", "caution", "block"]
        validated["recommendation"] = recommendation if recommendation in valid_recommendations else "caution"
        
        # Validate reasoning
        reasoning = analysis.get("reasoning", "")
        validated["reasoning"] = str(reasoning)[:500] if reasoning else "Analysis completed based on available indicators."
        
        # Validate domain_trust_applied
        domain_trust_applied = analysis.get("domain_trust_applied", 0)
        validated["domain_trust_applied"] = int(domain_trust_applied) if isinstance(domain_trust_applied, (int, float)) else 0
        
        return validated
    
    def _fallback_intent_parse(self, raw_response: str, processed_email: Dict, structural_result: Dict, content_result: Dict, trust_weight: int, response_time: float) -> Dict:
        """Fallback parsing for intent assessment when JSON extraction fails"""
        
        # Calculate risk using simple heuristic combination
        structural_risk = structural_result.get("structural_risk", 2)
        content_risk = content_result.get("content_risk", 3)
        
        # Simple risk combination
        base_score = structural_risk + content_risk
        adjusted_score = max(1, min(10, base_score + trust_weight))
        
        # Simple recommendation logic
        if adjusted_score <= 3:
            recommendation = "ignore"
        elif adjusted_score <= 6:
            recommendation = "caution"
        else:
            recommendation = "block"
        
        # Extract key concerns from previous phases
        primary_concerns = []
        if structural_result.get("domain_assessment") == "suspicious":
            primary_concerns.append("Suspicious domain detected")
        if content_result.get("request_type") in ["credential", "financial"]:
            primary_concerns.append(f"Requests {content_result.get('request_type')} information")
        if not primary_concerns:
            primary_concerns = ["Unable to parse detailed assessment"]
        
        return {
            "success": True,
            "phase": "intent",
            "risk_score": adjusted_score,
            "confidence": "low",
            "primary_concerns": primary_concerns[:3],
            "recommendation": recommendation,
            "reasoning": f"Heuristic assessment: structural ({structural_risk}) + content ({content_risk}) + trust ({trust_weight}) = {adjusted_score}",
            "domain_trust_applied": trust_weight,
            "processing_time": round(response_time, 2),
            "timestamp": datetime.now().isoformat(),
            "parsing_method": "fallback_heuristic",
            "phase_synthesis": {
                "structural_risk": structural_risk,
                "content_risk": content_risk,
                "trust_weight_applied": trust_weight,
                "domain_assessment": structural_result.get("domain_assessment", "unknown"),
                "request_type": content_result.get("request_type", "none"),
                "total_processing_time": (
                    structural_result.get("processing_time", 0) + 
                    content_result.get("processing_time", 0) + 
                    response_time
                )
            }
        }
    
    def analyze_email_legacy(self, processed_email: Dict, advanced_settings: Optional[Dict] = None) -> Dict:
        """
        LEGACY: Original single-prompt analysis method (kept as fallback)
        
        Args:
            processed_email: Output from EmailProcessor
            advanced_settings: Optional settings (temperature, max_tokens, etc.)
            
        Returns:
            Dict containing analysis results or error information
        """
        
        # Reset cancellation state and clear context for new analysis
        self.reset_cancel_state()
        self.clear_context()
        
        # Optionally clear server-side context for complete isolation
        # This is done asynchronously to avoid blocking the main analysis
        try:
            import threading
            context_thread = threading.Thread(target=self.clear_server_context, daemon=True)
            context_thread.start()
        except Exception:
            # If threading fails, continue without server context clearing
            pass
        
        if not processed_email.get("success"):
            return self._create_error_response("Invalid email data provided")
        
        # Create the analysis prompt
        prompt = self._create_phishing_analysis_prompt(processed_email)
        
        # Set up request parameters
        settings = advanced_settings or {}
        request_data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": settings.get("temperature", 0.3),
                "top_p": settings.get("top_p", 0.9),
                "max_tokens": settings.get("max_tokens", 2000),
                "stop": ["</analysis>", "Human:", "Assistant:"]
            }
        }
        
        # Make the API request with retries
        for attempt in range(self.max_retries):
            # Check for cancellation before each attempt
            if self.is_cancelled():
                return {
                    "success": False,
                    "cancelled": True,
                    "user_message": "Analysis was cancelled by user",
                    "timestamp": datetime.now().isoformat()
                }
            
            try:
                start_time = time.time()
                
                # Create session for this request to support cancellation
                self._current_session = requests.Session()
                
                response = self._current_session.post(
                    f"{self.base_url}/api/generate",
                    json=request_data,
                    timeout=self.timeout
                )
                
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Extract and validate the response
                    analysis_result = self._parse_llm_response(
                        result.get("response", ""), 
                        processed_email, 
                        response_time
                    )
                    
                    return analysis_result
                
                else:
                    error_msg = f"API request failed (HTTP {response.status_code})"
                    if attempt == self.max_retries - 1:
                        return self._create_error_response(error_msg)
            
            except requests.exceptions.Timeout as e:
                if attempt == self.max_retries - 1:
                    error_info = error_handler.handle_error(
                        e, f"LLM request timeout after {attempt + 1} attempts", 
                        ErrorCategory.NETWORK_TIMEOUT
                    )
                    return {**error_info, "analysis_failed": True}
                
                # Check for cancellation during backoff
                for i in range(2 ** attempt):
                    if self.is_cancelled():
                        return {
                            "success": False,
                            "cancelled": True,
                            "user_message": "Analysis was cancelled during retry",
                            "timestamp": datetime.now().isoformat()
                        }
                    time.sleep(1)
                
            except requests.exceptions.ConnectionError as e:
                if attempt == self.max_retries - 1:
                    error_info = handle_ollama_error(e, "Cannot connect to Ollama during analysis")
                    return {**error_info, "analysis_failed": True}
                
                # Check for cancellation during retry delay
                if not self.is_cancelled():
                    time.sleep(1)
                
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    error_info = error_handler.handle_error(
                        e, f"Network error during LLM analysis", 
                        ErrorCategory.NETWORK_TIMEOUT
                    )
                    return {**error_info, "analysis_failed": True}
                
                # Check for cancellation during retry delay
                if not self.is_cancelled():
                    time.sleep(1)
        
        # Max retries exceeded
        error_info = error_handler.handle_error(
            Exception("Max retries exceeded"),
            f"Failed after {self.max_retries} attempts",
            ErrorCategory.LLM_PROCESSING
        )
        return {**error_info, "analysis_failed": True}
    
    def analyze_email(self, processed_email: Dict, advanced_settings: Optional[Dict] = None) -> Dict:
        """
        NEW: Three-phase chunked analysis pipeline for improved accuracy.
        
        Uses focused prompts in sequence:
        1. Structural Analysis - headers, format, domain assessment
        2. Content Analysis - language, URLs, request types  
        3. Intent Assessment - synthesis with domain trust weights
        
        Args:
            processed_email: Output from EmailProcessor
            advanced_settings: Optional settings (temperature, max_tokens, etc.)
            
        Returns:
            Dict containing comprehensive analysis results or error information
        """
        
        # Reset cancellation state and clear context for new analysis
        self.reset_cancel_state()
        self.clear_context()
        
        # Optionally clear server-side context for complete isolation
        try:
            import threading
            context_thread = threading.Thread(target=self.clear_server_context, daemon=True)
            context_thread.start()
        except Exception:
            # If threading fails, continue without server context clearing
            pass
        
        if not processed_email.get("success"):
            return self._create_error_response("Invalid email data provided")
        
        try:
            total_start_time = time.time()
            
            # Phase 1: Structural Analysis
            if self.is_cancelled():
                return self._create_cancelled_response()
            
            structural_result = self._analyze_structure(processed_email, advanced_settings)
            
            if not structural_result.get("success"):
                return self._handle_phase_failure("structural", structural_result, processed_email)
            
            # Phase 2: Content Analysis
            if self.is_cancelled():
                return self._create_cancelled_response()
            
            content_result = self._analyze_content(processed_email, structural_result, advanced_settings)
            
            if not content_result.get("success"):
                return self._handle_phase_failure("content", content_result, processed_email, structural_result)
            
            # Phase 3: Intent Assessment
            if self.is_cancelled():
                return self._create_cancelled_response()
            
            intent_result = self._assess_intent(processed_email, structural_result, content_result, advanced_settings)
            
            if not intent_result.get("success"):
                return self._handle_phase_failure("intent", intent_result, processed_email, structural_result, content_result)
            
            # Success: Finalize comprehensive analysis result
            total_processing_time = time.time() - total_start_time
            
            # Apply comprehensive risk assessment framework (existing integration)
            comprehensive_report = self.risk_assessor.generate_comprehensive_report(
                intent_result, 
                processed_email.get("metadata", {})
            )
            
            # Add chunked analysis metadata
            comprehensive_report.update({
                "analysis_method": "chunked_pipeline",
                "total_processing_time": round(total_processing_time, 2),
                "phases_completed": 3,
                "model_used": self.model,
                "timestamp": datetime.now().isoformat()
            })
            
            return comprehensive_report
            
        except Exception as e:
            # Fallback to legacy method on unexpected errors
            error_info = error_handler.handle_error(
                e, "Chunked analysis pipeline failed", ErrorCategory.LLM_PROCESSING
            )
            
            # Try legacy method as fallback
            try:
                legacy_result = self.analyze_email_legacy(processed_email, advanced_settings)
                legacy_result["fallback_used"] = True
                legacy_result["fallback_reason"] = f"Chunked pipeline failed: {str(e)}"
                return legacy_result
            except Exception as fallback_error:
                return {
                    **error_info,
                    "analysis_failed": True,
                    "chunked_pipeline_error": str(e),
                    "legacy_fallback_error": str(fallback_error)
                }
    
    def _create_cancelled_response(self) -> Dict:
        """Create standardized cancellation response"""
        return {
            "success": False,
            "cancelled": True,
            "user_message": "Analysis was cancelled by user",
            "timestamp": datetime.now().isoformat()
        }
    
    def _handle_phase_failure(self, failed_phase: str, phase_result: Dict, processed_email: Dict, *completed_phases) -> Dict:
        """
        Handle failure in a specific phase with graceful degradation.
        
        Attempts to provide partial results or fallback to legacy method.
        """
        
        # If we have completed some phases, try to provide partial results
        if completed_phases:
            # Attempt heuristic synthesis of completed phases
            try:
                if failed_phase == "content" and len(completed_phases) >= 1:
                    # We have structural results, can provide basic assessment
                    structural_result = completed_phases[0]
                    return self._create_partial_result_from_structural(structural_result, processed_email)
                
                elif failed_phase == "intent" and len(completed_phases) >= 2:
                    # We have structural + content, can provide synthesis
                    structural_result, content_result = completed_phases[0], completed_phases[1]
                    return self._create_partial_result_from_phases(structural_result, content_result, processed_email)
            
            except Exception as synthesis_error:
                pass  # Fall through to legacy fallback
        
        # Fallback to legacy method
        try:
            legacy_result = self.analyze_email_legacy(processed_email)
            legacy_result.update({
                "fallback_used": True,
                "fallback_reason": f"Phase {failed_phase} failed",
                "failed_phase": failed_phase,
                "phase_error": phase_result.get("error", "Unknown phase error")
            })
            return legacy_result
        except Exception as legacy_error:
            return {
                "success": False,
                "analysis_failed": True,
                "failed_phase": failed_phase,
                "phase_error": phase_result.get("error", "Unknown error"),
                "legacy_fallback_error": str(legacy_error),
                "timestamp": datetime.now().isoformat()
            }
    
    def _create_partial_result_from_structural(self, structural_result: Dict, processed_email: Dict) -> Dict:
        """Create partial analysis result from structural phase only"""
        
        # Simple heuristic scoring based on structural analysis
        structural_risk = structural_result.get("structural_risk", 2)
        domain_assessment = structural_result.get("domain_assessment", "unknown")
        
        # Map structural risk to final risk score
        risk_score = min(10, max(1, structural_risk * 2))  # Scale 1-4 to 1-8 range
        
        if domain_assessment == "legitimate":
            risk_score = max(1, risk_score - 2)  # Trust bonus
        elif domain_assessment == "suspicious":
            risk_score = min(10, risk_score + 3)  # Risk penalty
        
        recommendation = "ignore" if risk_score <= 3 else "caution" if risk_score <= 6 else "block"
        
        return {
            "success": True,
            "risk_score": risk_score,
            "confidence": "low",  # Partial analysis has low confidence
            "red_flags": structural_result.get("header_issues", []),
            "reasoning": f"Partial analysis based on structural assessment only. {domain_assessment.title()} domain with structural risk {structural_risk}/4.",
            "recommendation": recommendation,
            "risk_level": self._get_risk_level(risk_score),
            "analysis_method": "partial_structural",
            "phases_completed": 1,
            "timestamp": datetime.now().isoformat()
        }
    
    def _create_partial_result_from_phases(self, structural_result: Dict, content_result: Dict, processed_email: Dict) -> Dict:
        """Create partial analysis result from structural + content phases"""
        
        # Combine risks from both phases
        structural_risk = structural_result.get("structural_risk", 2)
        content_risk = content_result.get("content_risk", 3)
        
        # Simple combination logic
        combined_risk = min(10, structural_risk + content_risk)
        
        # Apply domain trust
        metadata = processed_email.get("metadata", {})
        sender_domain = metadata.get("sender_domain", "")
        trust_weight, _ = self.risk_assessor.calculate_domain_trust_weight(sender_domain)
        
        final_risk = max(1, min(10, combined_risk + trust_weight))
        
        recommendation = "ignore" if final_risk <= 3 else "caution" if final_risk <= 6 else "block"
        
        # Combine concerns from both phases
        concerns = []
        if structural_result.get("header_issues"):
            concerns.extend(structural_result["header_issues"][:2])
        if content_result.get("language_flags"):
            concerns.extend(content_result["language_flags"][:2])
        
        return {
            "success": True,
            "risk_score": final_risk,
            "confidence": "medium",  # Better confidence with two phases
            "red_flags": concerns[:5],
            "reasoning": f"Partial analysis from structural ({structural_risk}/4) and content ({content_risk}/6) phases. Trust weight: {trust_weight}. Combined risk: {final_risk}/10.",
            "recommendation": recommendation,
            "risk_level": self._get_risk_level(final_risk),
            "analysis_method": "partial_two_phase",
            "phases_completed": 2,
            "timestamp": datetime.now().isoformat()
        }
    
    def _create_phishing_analysis_prompt(self, processed_email: Dict) -> str:
        """
        Create a structured prompt for the LLM.
        
        This prompt is specifically designed to:
        1. Avoid circular thinking loops
        2. Produce structured JSON output
        3. Focus on phishing indicators
        4. Provide clear reasoning
        """
        
        headers = processed_email.get("headers", {})
        body = processed_email.get("body", {})
        urls = processed_email.get("urls", [])
        metadata = processed_email.get("metadata", {})
        
        # Extract key information for analysis
        sender = headers.get("from", "Unknown")
        subject = headers.get("subject", "No subject")
        email_body = body.get("text", "") or body.get("html_text", "")
        
        # Get sender trust information
        sender_trusted = metadata.get("sender_trusted", False)
        sender_domain = metadata.get("sender_domain", "")
        
        # Prepare URL information
        url_info = ""
        if urls:
            url_info = "\nURLs found in email:\n"
            for url in urls[:5]:  # Limit to first 5 URLs
                status = []
                if url.get("is_suspicious"): status.append("SUSPICIOUS")
                if url.get("is_shortened"): status.append("SHORTENED")
                status_text = f" [{', '.join(status)}]" if status else ""
                url_info += f"- {url['url']}{status_text}\n"
        
        # Add trust information
        trust_info = f"\nSENDER ANALYSIS:\nDomain: {sender_domain}\nTrusted Domain: {'YES' if sender_trusted else 'NO'}"
        
        prompt = f"""<analysis>
You are a cybersecurity expert analyzing an email for phishing indicators.

CRITICAL INSTRUCTIONS:
1. Focus ONLY on actual phishing indicators, not unfamiliar domains
2. Corporate and business domains (.com, .org) are typically LEGITIMATE
3. Output ONLY valid JSON in the exact format specified below
4. Look for clear malicious intent, not just unknown senders

EMAIL TO ANALYZE:
==================
From: {sender}
Subject: {subject}

Body:
{email_body[:2000]}{"..." if len(email_body) > 2000 else ""}

{url_info}

{trust_info}

ANALYSIS FRAMEWORK:
==================
LEGITIMATE EMAIL TYPES (LOW RISK 1-3):
- Corporate newsletters, meeting invitations, company communications
- Professional business communications from .com/.org domains
- Emails with consistent branding and professional language
- Service notifications from established companies (GitHub, Microsoft, etc.)
- Internal communications between colleagues
- Legitimate business domains (even if not widely known)
- Personal emails between friends/colleagues without suspicious elements
- Brief/short emails that don't contain phishing indicators
- Password reset confirmations from legitimate services
- Professional emails with proper signatures and contact info

SUSPICIOUS EMAIL TYPES (MEDIUM RISK 4-6):
- Unsolicited lottery/prize notifications from unknown organizations
- Urgent account verification requests from unfamiliar services
- Poor grammar or unprofessional formatting in business communications  
- Generic greetings from services that should know your name ("Dear Customer")
- Investment opportunities or "get rich quick" schemes
- Requests for personal information without clear legitimate purpose

NOTE: Company newsletters to employees, service notifications from known companies, and professional business communications are NOT suspicious.

HIGH RISK PHISHING ATTEMPTS (RISK 7-10):
- Clear domain spoofing (microsft.com, paypaI.com, amaz0n.com)
- Direct requests for passwords, SSN, credit card numbers
- URLs pointing to obviously malicious domains (.ru, .tk, suspicious-domain.com)
- Threats of immediate account closure with urgent action required
- Credential harvesting forms or suspicious download links
- Impersonation of banks/financial institutions with fake urgency

DOMAIN ANALYSIS RULES:
- company.com = LEGITIMATE corporate domain (not spoofing)
- github.com = LEGITIMATE (established service)
- microsoft.com = LEGITIMATE (established service)  
- microsft.com = PHISHING (typo domain)
- paypal.com = LEGITIMATE (established service)
- paypaI.com = PHISHING (using capital i instead of l)
- bankoamerica-verify.suspicious-domain.ru = PHISHING (clearly malicious)
- service-center.com = SUSPICIOUS but not definitive phishing (could be legitimate business)
- international-lottery.org = SUSPICIOUS (unsolicited lottery) but not high-risk phishing
- example.com = TEST/PERSONAL domain (legitimate for testing/personal use)

LEGITIMATE EMAIL EXAMPLES:
- Company newsletter to employees about business updates = LOW RISK (1) - Internal business communication
- Password reset confirmation from github.com = LOW RISK (1-2) - Legitimate service communication  
- Meeting invitation from colleague at company.com = LOW RISK (1) - Internal business communication
- Personal dinner plans between friends = LOW RISK (1) - Personal correspondence
- Short "Hello" email without suspicious elements = LOW RISK (2) - Brief legitimate communication  
- Service notification from established company = LOW RISK (2-3) - Legitimate business notification
- Security notifications from known services (GitHub, Microsoft) = LOW RISK (1-2) - Legitimate security communication

CRITICAL: Do NOT flag legitimate business communications as suspicious:
- Company newsletters/updates to employees are LEGITIMATE
- Password/security notifications from established services are LEGITIMATE  
- Internal business communications are LEGITIMATE
Only flag emails with ACTUAL phishing indicators like fake domains, credential harvesting, or threats.

REQUIRED OUTPUT FORMAT (JSON ONLY):
{{
    "risk_score": [number 1-10],
    "confidence": "[high|medium|low]",
    "red_flags": [
        "specific indicator 1",
        "specific indicator 2"
    ],
    "reasoning": "Brief explanation focusing on actual phishing indicators found or absence thereof",
    "recommendation": "[ignore|caution|block]"
}}

SCORING GUIDELINES:
- 1-2: Clearly legitimate (established services, personal emails, professional business communications)
- 3-4: Likely legitimate but with minor concerns (unfamiliar but professional senders)
- 5-6: Suspicious elements present but not definitively malicious (unsolicited offers, generic urgency)
- 7-8: Likely phishing with multiple suspicious indicators
- 9-10: Definitive phishing attempt with clear malicious intent

IMPORTANT: Only score 7+ when you see ACTUAL phishing indicators like:
- Domain spoofing/typos (microsft.com vs microsoft.com)
- Direct credential harvesting requests
- Suspicious domains (.ru, .tk, clearly fake domains)
- Obvious impersonation attempts

Begin analysis now. Output only the JSON response:
</analysis>"""

        return prompt
    
    def _parse_llm_response(self, raw_response: str, processed_email: Dict, response_time: float) -> Dict:
        """Parse and validate LLM response"""
        
        try:
            # Try to extract JSON from the response
            json_match = self._extract_json_from_response(raw_response)
            
            if json_match:
                analysis = json.loads(json_match)
                
                # Validate the response structure
                validated_analysis = self._validate_analysis_response(analysis, processed_email)
                
                # Add basic metadata
                validated_analysis.update({
                    "success": True,
                    "model_used": self.model,
                    "response_time": round(response_time, 2),
                    "timestamp": datetime.now().isoformat(),
                    "raw_response_length": len(raw_response)
                })
                
                # Apply comprehensive risk assessment framework
                comprehensive_report = self.risk_assessor.generate_comprehensive_report(
                    validated_analysis, 
                    processed_email.get("metadata", {})
                )
                
                return comprehensive_report
            
            else:
                # Fallback: try to parse the entire response as JSON
                analysis = json.loads(raw_response.strip())
                validated_analysis = self._validate_analysis_response(analysis, processed_email)
                validated_analysis.update({
                    "success": True,
                    "model_used": self.model,
                    "response_time": round(response_time, 2),
                    "timestamp": datetime.now().isoformat()
                })
                
                # Apply comprehensive risk assessment framework
                comprehensive_report = self.risk_assessor.generate_comprehensive_report(
                    validated_analysis, 
                    processed_email.get("metadata", {})
                )
                
                return comprehensive_report
                
        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract information manually
            return self._fallback_parse_response(raw_response, processed_email, response_time)
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
        """Extract JSON content from model response"""
        import re
        
        # Look for JSON blocks in various formats
        patterns = [
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',  # Basic JSON pattern
            r'```json\s*(\{.*?\})\s*```',         # Markdown code blocks
            r'```\s*(\{.*?\})\s*```',             # Generic code blocks
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            if matches:
                return matches[0] if isinstance(matches[0], str) else matches[0]
        
        # Try to find JSON-like content by looking for key patterns
        json_start = response.find('{')
        json_end = response.rfind('}')
        
        if json_start != -1 and json_end != -1 and json_end > json_start:
            return response[json_start:json_end + 1]
        
        return None
    
    def _validate_analysis_response(self, analysis: Dict, processed_email: Dict) -> Dict:
        """Validate and normalize analysis response"""
        
        validated = {
            "risk_score": self._validate_risk_score(analysis.get("risk_score", 5)),
            "confidence": self._validate_confidence(analysis.get("confidence", "medium")),
            "red_flags": self._validate_red_flags(analysis.get("red_flags", [])),
            "reasoning": self._validate_reasoning(analysis.get("reasoning", "Analysis completed")),
            "recommendation": self._validate_recommendation(analysis.get("recommendation", "caution"))
        }
        
        # Ensure risk score aligns with recommendation
        validated["risk_score"] = self._align_score_with_recommendation(
            validated["risk_score"], 
            validated["recommendation"]
        )
        
        # Add risk level
        validated["risk_level"] = self._get_risk_level(validated["risk_score"])
        
        return validated
    
    def _validate_risk_score(self, score) -> int:
        """Validate and normalize risk score"""
        try:
            score = float(score)
            return max(1, min(10, int(round(score))))
        except (ValueError, TypeError):
            return 5  # Default to medium risk
    
    def _validate_confidence(self, confidence) -> str:
        """Validate confidence level"""
        valid_levels = ["low", "medium", "high"]
        if isinstance(confidence, str) and confidence.lower() in valid_levels:
            return confidence.lower()
        return "medium"
    
    def _validate_red_flags(self, red_flags) -> List[str]:
        """Validate and clean red flags list"""
        if not isinstance(red_flags, list):
            return []
        
        cleaned_flags = []
        for flag in red_flags[:10]:  # Limit to 10 flags
            if isinstance(flag, str) and len(flag.strip()) > 0:
                cleaned_flags.append(flag.strip()[:200])  # Limit flag length
        
        return cleaned_flags
    
    def _validate_reasoning(self, reasoning) -> str:
        """Validate reasoning text"""
        if isinstance(reasoning, str) and len(reasoning.strip()) > 0:
            return reasoning.strip()[:1000]  # Limit reasoning length
        return "Analysis completed based on available indicators."
    
    def _validate_recommendation(self, recommendation) -> str:
        """Validate recommendation"""
        valid_recommendations = ["ignore", "caution", "block"]
        if isinstance(recommendation, str) and recommendation.lower() in valid_recommendations:
            return recommendation.lower()
        return "caution"
    
    def _align_score_with_recommendation(self, score: int, recommendation: str) -> int:
        """Ensure risk score aligns with recommendation"""
        # Temporarily disabled to debug score inflation issues
        # Only adjust if there's a clear mismatch
        if recommendation == "ignore" and score > 6:
            return 3  # Only adjust very high scores with ignore recommendation
        elif recommendation == "block" and score < 4:
            return 7  # Only adjust very low scores with block recommendation
        return score  # Preserve LLM's score in most cases
    
    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level"""
        if score >= 7:
            return "High Risk"
        elif score >= 4:
            return "Medium Risk"
        else:
            return "Low Risk"
    
    def _fallback_parse_response(self, raw_response: str, processed_email: Dict, response_time: float) -> Dict:
        """Fallback parsing when JSON extraction fails"""
        
        # Try to extract key information using regex patterns
        import re
        
        # Look for risk score
        score_match = re.search(r'(?:risk|score).*?(\d+)', raw_response, re.IGNORECASE)
        risk_score = int(score_match.group(1)) if score_match else 5
        
        # Look for red flags or indicators
        red_flags = []
        flag_patterns = [
            r'red flag[s]?[:\-\s]+([^\n]+)',
            r'indicator[s]?[:\-\s]+([^\n]+)',
            r'warning[s]?[:\-\s]+([^\n]+)'
        ]
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, raw_response, re.IGNORECASE)
            red_flags.extend(matches[:3])  # Limit flags
        
        return {
            "success": True,
            "risk_score": max(1, min(10, risk_score)),
            "confidence": "low",  # Low confidence for fallback parsing
            "red_flags": red_flags[:5] if red_flags else ["Unable to parse detailed indicators"],
            "reasoning": "Fallback analysis - original response could not be parsed as JSON",
            "recommendation": "caution",
            "risk_level": self._get_risk_level(risk_score),
            "model_used": self.model,
            "response_time": round(response_time, 2),
            "timestamp": datetime.now().isoformat(),
            "parsing_method": "fallback"
        }
    
    def _create_error_response(self, error_message: str) -> Dict:
        """Create standardized error response"""
        return {
            "success": False,
            "error": error_message,
            "risk_score": 5,
            "confidence": "low",
            "red_flags": ["Analysis failed - unable to process email"],
            "reasoning": f"Error during analysis: {error_message}",
            "recommendation": "caution",
            "risk_level": "Medium Risk",
            "timestamp": datetime.now().isoformat()
        }