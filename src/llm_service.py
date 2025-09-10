"""
LLM Service Module for Phish-Net

This module handles communication with Ollama and prompt engineering
specifically designed for phi4-mini-reasoning model.
"""

import json
import requests
from typing import Dict, List, Optional, Tuple
import time
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
    Service for communicating with Ollama API and managing phi4-mini-reasoning model.
    
    Handles prompt engineering, API communication, and response validation
    specifically optimized for phishing email analysis.
    """
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "phi4-mini"):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = 90  # Increased timeout for slower systems
        self.max_retries = 3
        self.risk_assessor = RiskAssessment()
        
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
    
    def analyze_email(self, processed_email: Dict, advanced_settings: Optional[Dict] = None) -> Dict:
        """
        Analyze email using phi4-mini-reasoning model.
        
        Args:
            processed_email: Output from EmailProcessor
            advanced_settings: Optional settings (temperature, max_tokens, etc.)
            
        Returns:
            Dict containing analysis results or error information
        """
        
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
            try:
                start_time = time.time()
                
                response = requests.post(
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
                time.sleep(2 ** attempt)  # Exponential backoff
                
            except requests.exceptions.ConnectionError as e:
                if attempt == self.max_retries - 1:
                    error_info = handle_ollama_error(e, "Cannot connect to Ollama during analysis")
                    return {**error_info, "analysis_failed": True}
                time.sleep(1)
                
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    error_info = error_handler.handle_error(
                        e, f"Network error during LLM analysis", 
                        ErrorCategory.NETWORK_TIMEOUT
                    )
                    return {**error_info, "analysis_failed": True}
                time.sleep(1)
        
        # Max retries exceeded
        error_info = error_handler.handle_error(
            Exception("Max retries exceeded"),
            f"Failed after {self.max_retries} attempts",
            ErrorCategory.LLM_PROCESSING
        )
        return {**error_info, "analysis_failed": True}
    
    def _create_phishing_analysis_prompt(self, processed_email: Dict) -> str:
        """
        Create a structured prompt for phi4-mini-reasoning model.
        
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
1. Distinguish between legitimate notifications and phishing attempts
2. Consider the sender's legitimacy and domain reputation
3. Output ONLY valid JSON in the exact format specified below
4. Security notifications from legitimate services are typically LOW RISK

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
PRIMARY RULE: If "Trusted Domain: YES", this is likely LEGITIMATE (Risk 1-3) unless clear phishing indicators exist.

LEGITIMATE INDICATORS (LOW RISK 1-3):
- Sender from trusted domain (github.com, microsoft.com, google.com, paypal.com, etc.)
- Security notifications with URLs matching sender domain
- Professional language and consistent branding
- URLs pointing to legitimate service domains matching the sender
- Automated notification language ("Hi there", "Dear user")

PHISHING INDICATORS (MEDIUM/HIGH RISK 4-10):
- Domain spoofing (e.g., githbub.com, microsft.com, paypaI.com)
- Requests for passwords, credit card numbers, SSN, or personal information
- Suspicious/shortened URLs or mismatched domains
- Poor grammar, spelling errors, unprofessional formatting
- Immediate threats of account closure with urgent action required
- Generic greetings from services that should know your name

SPECIAL CONSIDERATIONS:
- Security notifications from legitimate services are NORMAL and LOW RISK
- Cautionary language in security alerts is EXPECTED, not threatening
- URLs like "github.com/settings/security" are LEGITIMATE for GitHub emails
- "Hi there" is STANDARD for automated notifications from legitimate services

REQUIRED OUTPUT FORMAT (JSON ONLY):
{{
    "risk_score": [number 1-10],
    "confidence": "[high|medium|low]",
    "red_flags": [
        "specific indicator 1",
        "specific indicator 2"
    ],
    "reasoning": "Brief explanation of assessment focusing on key indicators found",
    "recommendation": "[ignore|caution|block]"
}}

SCORING GUIDELINES:
- 1-3: Legitimate email with no significant concerns
- 4-6: Suspicious elements present, exercise caution
- 7-10: High risk phishing attempt, recommend blocking

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
        if recommendation == "ignore" and score > 4:
            return 3
        elif recommendation == "block" and score < 6:
            return 7
        return score
    
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