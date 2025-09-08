"""
Risk Assessment Module for Phish-Net

This module implements the risk scoring framework with predefined categories,
validation, and quality control measures for phishing email analysis.
"""

from enum import Enum
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import re


class RiskLevel(Enum):
    """Risk level categories with score ranges"""
    LOW = ("Low Risk", 1, 3, "green")
    MEDIUM = ("Medium Risk", 4, 6, "orange") 
    HIGH = ("High Risk", 7, 10, "red")
    
    def __init__(self, display_name: str, min_score: int, max_score: int, color: str):
        self.display_name = display_name
        self.min_score = min_score
        self.max_score = max_score
        self.color = color
    
    @classmethod
    def from_score(cls, score: int) -> 'RiskLevel':
        """Get risk level from numerical score"""
        for level in cls:
            if level.min_score <= score <= level.max_score:
                return level
        # Default to HIGH for out-of-range scores
        return cls.HIGH


class RedFlagCategory(Enum):
    """Categories of phishing red flags with severity levels"""
    
    # Critical indicators (usually 7-10 risk)
    CREDENTIAL_REQUEST = ("credential_request", "Requests passwords/credentials", 3, "Critical")
    DOMAIN_SPOOFING = ("domain_spoofing", "Domain impersonation/spoofing", 3, "Critical")
    MALICIOUS_ATTACHMENT = ("malicious_attachment", "Suspicious attachments", 3, "Critical")
    
    # Major indicators (usually 4-7 risk)
    SUSPICIOUS_LINKS = ("suspicious_links", "Suspicious or shortened URLs", 2, "Major")
    URGENT_THREATS = ("urgent_threats", "Threatening/urgent language", 2, "Major")
    POOR_FORMATTING = ("poor_formatting", "Poor grammar/formatting", 2, "Major")
    
    # Minor indicators (usually 1-4 risk)
    GENERIC_GREETING = ("generic_greeting", "Generic greeting when personalization expected", 1, "Minor")
    SUSPICIOUS_TIMING = ("suspicious_timing", "Unusual timing/frequency", 1, "Minor")
    MISMATCHED_BRANDING = ("mismatched_branding", "Inconsistent branding", 1, "Minor")
    
    def __init__(self, flag_id: str, description: str, severity: int, category: str):
        self.flag_id = flag_id
        self.description = description
        self.severity = severity  # 1=Minor, 2=Major, 3=Critical
        self.category = category


class RiskAssessment:
    """
    Comprehensive risk assessment system for phishing analysis.
    
    Handles risk scoring, validation, red flag categorization, and quality control.
    """
    
    def __init__(self):
        self.confidence_thresholds = {
            "high": 0.8,
            "medium": 0.5,
            "low": 0.0
        }
    
    def validate_risk_score(self, score: int, confidence: str = "medium") -> Tuple[int, bool, str]:
        """
        Validate and potentially adjust risk score.
        
        Args:
            score: Raw risk score (should be 1-10)
            confidence: Confidence level from LLM
            
        Returns:
            Tuple of (adjusted_score, is_valid, reason)
        """
        validation_notes = []
        is_valid = True
        adjusted_score = score
        
        # Basic range validation
        if score < 1:
            adjusted_score = 1
            is_valid = False
            validation_notes.append("Score below minimum, adjusted to 1")
        elif score > 10:
            adjusted_score = 10
            is_valid = False
            validation_notes.append("Score above maximum, adjusted to 10")
        
        # Confidence-based adjustments
        if confidence == "low" and score >= 7:
            adjusted_score = min(6, score)
            validation_notes.append("High risk score with low confidence, reduced to medium risk")
        
        reason = "; ".join(validation_notes) if validation_notes else "Score validated successfully"
        
        return adjusted_score, is_valid, reason
    
    def categorize_red_flags(self, red_flags: List[str]) -> Dict[str, List[Dict]]:
        """
        Categorize and enrich red flags with severity and descriptions.
        
        Args:
            red_flags: List of red flag strings from LLM
            
        Returns:
            Dict with categorized flags by severity
        """
        categorized = {
            "critical": [],
            "major": [],
            "minor": [],
            "unknown": []
        }
        
        for flag in red_flags:
            flag_lower = flag.lower().strip()
            matched = False
            
            # Match against known red flag categories
            for category in RedFlagCategory:
                if self._flag_matches_category(flag_lower, category):
                    categorized[category.category.lower()].append({
                        "text": flag,
                        "category": category.flag_id,
                        "description": category.description,
                        "severity": category.severity
                    })
                    matched = True
                    break
            
            # Handle unknown flags
            if not matched:
                categorized["unknown"].append({
                    "text": flag,
                    "category": "unknown",
                    "description": "Unrecognized indicator",
                    "severity": 1
                })
        
        return categorized
    
    def _flag_matches_category(self, flag_text: str, category: RedFlagCategory) -> bool:
        """Check if a red flag text matches a specific category"""
        
        # Define keyword patterns for each category
        patterns = {
            RedFlagCategory.CREDENTIAL_REQUEST: [
                "password", "credential", "login", "signin", "verify account", 
                "update payment", "confirm identity"
            ],
            RedFlagCategory.DOMAIN_SPOOFING: [
                "suspicious sender", "spoofing", "impersonation", "fake domain",
                "domain mismatch", "suspicious domain"
            ],
            RedFlagCategory.MALICIOUS_ATTACHMENT: [
                "suspicious attachment", "malicious file", "executable", "zip file"
            ],
            RedFlagCategory.SUSPICIOUS_LINKS: [
                "suspicious url", "shortened url", "suspicious link", "redirect",
                "suspicious domain", "malicious link"
            ],
            RedFlagCategory.URGENT_THREATS: [
                "urgent", "threatening", "immediate action", "account closure",
                "suspended", "expires", "deadline"
            ],
            RedFlagCategory.POOR_FORMATTING: [
                "poor grammar", "spelling", "formatting", "unprofessional",
                "grammar error", "typo"
            ],
            RedFlagCategory.GENERIC_GREETING: [
                "generic greeting", "dear customer", "dear user", "impersonal"
            ],
            RedFlagCategory.SUSPICIOUS_TIMING: [
                "timing", "frequency", "unusual time", "off hours"
            ],
            RedFlagCategory.MISMATCHED_BRANDING: [
                "branding", "inconsistent", "mismatch", "logo", "design"
            ]
        }
        
        keywords = patterns.get(category, [])
        return any(keyword in flag_text for keyword in keywords)
    
    def calculate_confidence_score(self, llm_confidence: str, red_flag_count: int, 
                                 trusted_sender: bool, response_time: float) -> float:
        """
        Calculate overall confidence score based on multiple factors.
        
        Args:
            llm_confidence: Confidence level from LLM ("high", "medium", "low")
            red_flag_count: Number of red flags detected
            trusted_sender: Whether sender is from trusted domain
            response_time: LLM response time in seconds
            
        Returns:
            Float confidence score between 0.0 and 1.0
        """
        base_confidence = self.confidence_thresholds.get(llm_confidence, 0.5)
        
        # Adjust based on red flag consistency
        if red_flag_count == 0 and trusted_sender:
            base_confidence += 0.2  # High confidence for clean trusted emails
        elif red_flag_count > 3:
            base_confidence -= 0.1  # Lower confidence for many flags (might be over-detection)
        
        # Adjust for response time (very fast or very slow might indicate issues)
        if response_time > 30:
            base_confidence -= 0.1  # Slower responses might be less reliable
        elif response_time < 2:
            base_confidence -= 0.05  # Suspiciously fast responses
        
        return max(0.0, min(1.0, base_confidence))
    
    def cross_validate_with_heuristics(self, llm_score: int, metadata: Dict) -> Dict:
        """
        Cross-validate LLM score with simple heuristic checks.
        
        Args:
            llm_score: Score from LLM analysis
            metadata: Email metadata from processing
            
        Returns:
            Dict with heuristic analysis and validation notes
        """
        heuristic_flags = []
        heuristic_score = 1  # Start with low risk
        
        # Check trusted sender
        if metadata.get("sender_trusted", False):
            heuristic_score = max(1, min(heuristic_score, 3))  # Cap at low risk
        else:
            heuristic_score += 2  # Unknown sender increases risk
        
        # Check URL analysis
        suspicious_urls = metadata.get("suspicious_url_count", 0)
        if suspicious_urls > 0:
            heuristic_score += suspicious_urls * 2
            heuristic_flags.append(f"Found {suspicious_urls} suspicious URLs")
        
        # Check for IP addresses instead of domains
        if metadata.get("url_count", 0) > 0 and suspicious_urls > 0:
            heuristic_flags.append("URLs point to suspicious domains")
        
        # Calculate agreement level
        score_diff = abs(llm_score - heuristic_score)
        agreement_level = "high" if score_diff <= 2 else "medium" if score_diff <= 4 else "low"
        
        return {
            "heuristic_score": min(10, heuristic_score),
            "heuristic_flags": heuristic_flags,
            "score_difference": score_diff,
            "agreement_level": agreement_level,
            "validation_notes": self._generate_validation_notes(llm_score, heuristic_score)
        }
    
    def _generate_validation_notes(self, llm_score: int, heuristic_score: int) -> List[str]:
        """Generate validation notes based on score comparison"""
        notes = []
        diff = abs(llm_score - heuristic_score)
        
        if diff <= 1:
            notes.append("LLM and heuristic analysis in strong agreement")
        elif diff <= 3:
            notes.append("LLM and heuristic analysis show moderate agreement")
        else:
            if llm_score > heuristic_score:
                notes.append("LLM detected additional risk factors beyond basic heuristics")
            else:
                notes.append("Heuristic analysis suggests higher risk than LLM assessment")
        
        return notes
    
    def generate_comprehensive_report(self, llm_analysis: Dict, email_metadata: Dict) -> Dict:
        """
        Generate comprehensive risk assessment report.
        
        Args:
            llm_analysis: Analysis results from LLM
            email_metadata: Metadata from email processing
            
        Returns:
            Enhanced analysis with risk framework applied
        """
        # Extract key values
        raw_score = llm_analysis.get("risk_score", 5)
        confidence = llm_analysis.get("confidence", "medium")
        red_flags = llm_analysis.get("red_flags", [])
        response_time = llm_analysis.get("response_time", 0)
        
        # Validate and adjust score
        validated_score, is_valid, validation_reason = self.validate_risk_score(raw_score, confidence)
        
        # Determine risk level
        risk_level = RiskLevel.from_score(validated_score)
        
        # Categorize red flags
        categorized_flags = self.categorize_red_flags(red_flags)
        
        # Calculate comprehensive confidence
        overall_confidence = self.calculate_confidence_score(
            confidence, len(red_flags), 
            email_metadata.get("sender_trusted", False), 
            response_time
        )
        
        # Cross-validate with heuristics
        heuristic_validation = self.cross_validate_with_heuristics(validated_score, email_metadata)
        
        # Generate final report
        report = {
            # Enhanced core analysis
            "risk_score": validated_score,
            "risk_level": risk_level.display_name,
            "risk_color": risk_level.color,
            "confidence_score": round(overall_confidence, 2),
            "confidence_level": "high" if overall_confidence >= 0.8 else "medium" if overall_confidence >= 0.5 else "low",
            
            # Red flag analysis
            "red_flags": {
                "total_count": len(red_flags),
                "categorized": categorized_flags,
                "severity_summary": self._summarize_flag_severity(categorized_flags)
            },
            
            # Validation and quality control
            "validation": {
                "score_adjusted": not is_valid,
                "original_score": raw_score,
                "adjustment_reason": validation_reason,
                "heuristic_validation": heuristic_validation
            },
            
            # Recommendations
            "recommendation": self._generate_recommendation(validated_score, categorized_flags),
            
            # Metadata
            "assessment_timestamp": datetime.now().isoformat(),
            "trusted_sender": email_metadata.get("sender_trusted", False),
            "sender_domain": email_metadata.get("sender_domain", ""),
            
            # Original LLM data (preserved)
            "llm_analysis": llm_analysis
        }
        
        return report
    
    def _summarize_flag_severity(self, categorized_flags: Dict) -> Dict:
        """Summarize red flag severity distribution"""
        return {
            "critical_count": len(categorized_flags.get("critical", [])),
            "major_count": len(categorized_flags.get("major", [])),
            "minor_count": len(categorized_flags.get("minor", [])),
            "unknown_count": len(categorized_flags.get("unknown", []))
        }
    
    def _generate_recommendation(self, score: int, categorized_flags: Dict) -> Dict:
        """Generate action recommendations based on risk assessment"""
        risk_level = RiskLevel.from_score(score)
        critical_flags = len(categorized_flags.get("critical", []))
        
        if risk_level == RiskLevel.HIGH or critical_flags > 0:
            action = "block"
            message = "This email shows strong indicators of phishing. Block and report as spam."
            details = ["Do not click any links", "Do not download attachments", "Report to IT security"]
        elif risk_level == RiskLevel.MEDIUM:
            action = "caution"
            message = "This email shows some suspicious indicators. Proceed with caution."
            details = ["Verify sender through alternative means", "Be cautious with links and attachments", "When in doubt, don't interact"]
        else:
            action = "ignore"
            message = "This email appears to be legitimate with low risk indicators."
            details = ["Safe to interact normally", "Standard email security practices apply"]
        
        return {
            "action": action,
            "message": message,
            "details": details,
            "risk_level": risk_level.display_name
        }