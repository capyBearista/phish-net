"""
Error Handling and User Guidance Module for Phish-Net

This module provides comprehensive error handling, user-friendly error messages,
and guidance for troubleshooting common issues.
"""

import logging
import traceback
from enum import Enum
from typing import Dict, List, Optional, Union, Callable
from datetime import datetime
import requests
import json


class ErrorCategory(Enum):
    """Categories of errors with severity levels and user guidance"""
    
    # Connection & Network Errors
    OLLAMA_CONNECTION = ("ollama_connection", "Ollama Connection Failed", "critical")
    MODEL_UNAVAILABLE = ("model_unavailable", "AI Model Not Available", "high") 
    NETWORK_TIMEOUT = ("network_timeout", "Network Timeout", "medium")
    
    # Input & Content Errors
    INVALID_EMAIL = ("invalid_email", "Invalid Email Content", "medium")
    FILE_ENCODING = ("file_encoding", "File Encoding Error", "medium")
    CONTENT_TOO_LARGE = ("content_too_large", "Email Content Too Large", "low")
    
    # Processing Errors
    PARSING_ERROR = ("parsing_error", "Email Parsing Failed", "medium")
    LLM_PROCESSING = ("llm_processing", "AI Analysis Failed", "high")
    VALIDATION_ERROR = ("validation_error", "Data Validation Failed", "medium")
    
    # System & Configuration Errors
    MISSING_DEPENDENCY = ("missing_dependency", "Missing Required Component", "high")
    CONFIG_ERROR = ("config_error", "Configuration Error", "medium")
    PERMISSION_ERROR = ("permission_error", "File Permission Error", "medium")
    
    def __init__(self, error_id: str, display_name: str, severity: str):
        self.error_id = error_id
        self.display_name = display_name
        self.severity = severity


class PhishNetError(Exception):
    """Base exception class for Phish-Net specific errors"""
    
    def __init__(self, message: str, category: ErrorCategory, 
                 details: Optional[str] = None, suggestions: Optional[List[str]] = None):
        super().__init__(message)
        self.category = category
        self.details = details
        self.suggestions = suggestions or []
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        """Convert error to dictionary for UI display"""
        return {
            "error_id": self.category.error_id,
            "display_name": self.category.display_name,
            "severity": self.category.severity,
            "message": str(self),
            "details": self.details,
            "suggestions": self.suggestions,
            "timestamp": self.timestamp.isoformat()
        }


class ErrorHandler:
    """
    Comprehensive error handling system with user guidance and troubleshooting.
    """
    
    def __init__(self, log_level: str = "INFO"):
        self.logger = self._setup_logging(log_level)
        self.error_count = {}
        self.last_errors = []
        self.max_error_history = 50
    
    def _setup_logging(self, level: str) -> logging.Logger:
        """Set up logging configuration"""
        logger = logging.getLogger("phish-net")
        
        if not logger.handlers:  # Avoid duplicate handlers
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, level.upper()))
        
        return logger
    
    def handle_error(self, error: Exception, context: str = "", 
                    category: Optional[ErrorCategory] = None) -> Dict:
        """
        Central error handling with categorization and user guidance.
        
        Args:
            error: The exception that occurred
            context: Additional context about where the error occurred
            category: Optional error category (will be auto-detected if not provided)
            
        Returns:
            Dict containing error information and user guidance
        """
        
        # Auto-detect category if not provided
        if category is None:
            category = self._categorize_error(error)
        
        # Create PhishNetError if not already one
        if not isinstance(error, PhishNetError):
            suggestions = self._get_suggestions_for_category(category)
            phish_error = PhishNetError(
                message=str(error),
                category=category,
                details=f"{context}: {traceback.format_exc()}" if context else traceback.format_exc(),
                suggestions=suggestions
            )
        else:
            phish_error = error
        
        # Log the error
        self._log_error(phish_error, context)
        
        # Track error statistics
        self._track_error(phish_error)
        
        # Generate user-friendly response
        return self._generate_error_response(phish_error)
    
    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """Auto-categorize error based on type and message"""
        error_msg = str(error).lower()
        error_type = type(error).__name__
        
        # Connection errors
        if isinstance(error, requests.exceptions.ConnectionError):
            return ErrorCategory.OLLAMA_CONNECTION
        if isinstance(error, requests.exceptions.Timeout):
            return ErrorCategory.NETWORK_TIMEOUT
        if "connection" in error_msg or "refused" in error_msg:
            return ErrorCategory.OLLAMA_CONNECTION
        
        # File and encoding errors
        if isinstance(error, UnicodeDecodeError) or "encoding" in error_msg:
            return ErrorCategory.FILE_ENCODING
        if isinstance(error, PermissionError):
            return ErrorCategory.PERMISSION_ERROR
        if "file" in error_msg and ("not found" in error_msg or "permission" in error_msg):
            return ErrorCategory.PERMISSION_ERROR
        
        # Content and parsing errors
        if isinstance(error, json.JSONDecodeError) or "json" in error_msg:
            return ErrorCategory.PARSING_ERROR
        if "invalid" in error_msg and "email" in error_msg:
            return ErrorCategory.INVALID_EMAIL
        
        # Model and processing errors
        if "model" in error_msg and ("not found" in error_msg or "unavailable" in error_msg):
            return ErrorCategory.MODEL_UNAVAILABLE
        if "ollama" in error_msg:
            return ErrorCategory.OLLAMA_CONNECTION
        
        # Import and dependency errors
        if isinstance(error, ImportError) or isinstance(error, ModuleNotFoundError):
            return ErrorCategory.MISSING_DEPENDENCY
        
        # Default to processing error
        return ErrorCategory.LLM_PROCESSING
    
    def _get_suggestions_for_category(self, category: ErrorCategory) -> List[str]:
        """Get troubleshooting suggestions for error category"""
        
        suggestions_map = {
            ErrorCategory.OLLAMA_CONNECTION: [
                "Check if Ollama is installed and running (ollama --version)",
                "Start Ollama service (ollama serve)",
                "Verify Ollama is accessible at http://localhost:11434",
                "Check firewall and port settings",
                "Try restarting Ollama service"
            ],
            ErrorCategory.MODEL_UNAVAILABLE: [
                "Check available models: ollama list",
                "Pull the required model: ollama pull phi4-mini",
                "Verify model name spelling and availability",
                "Check Ollama model directory and disk space",
                "Try using a different model (e.g., llama2, mistral)"
            ],
            ErrorCategory.NETWORK_TIMEOUT: [
                "Check internet connection",
                "Increase timeout in advanced settings",
                "Try again - the model might be loading",
                "Check Ollama service status",
                "Restart Ollama if response times are slow"
            ],
            ErrorCategory.INVALID_EMAIL: [
                "Ensure email content is properly formatted",
                "Check for missing headers (From, To, Subject)",
                "Try copying email content as plain text",
                "Verify .eml file is not corrupted",
                "Check character encoding (UTF-8 recommended)"
            ],
            ErrorCategory.FILE_ENCODING: [
                "Save file with UTF-8 encoding",
                "Try opening file in text editor and re-saving",
                "Use 'Save As' and select UTF-8 encoding",
                "Check if file contains special characters",
                "Try converting file encoding with external tool"
            ],
            ErrorCategory.CONTENT_TOO_LARGE: [
                "Email content is very large - analysis may take longer",
                "Consider analyzing key sections separately",
                "Check if email contains large attachments",
                "Increase processing timeout in advanced settings"
            ],
            ErrorCategory.PARSING_ERROR: [
                "Check email format and structure",
                "Ensure .eml file is valid email format",
                "Try copying just the email text content",
                "Remove any non-email content from input",
                "Check for corrupted characters or encoding issues"
            ],
            ErrorCategory.LLM_PROCESSING: [
                "Try again - this may be a temporary issue",
                "Check Ollama service status and logs",
                "Restart Ollama service",
                "Try with a smaller email content",
                "Switch to heuristic analysis mode if available"
            ],
            ErrorCategory.MISSING_DEPENDENCY: [
                "Install missing Python packages: pip install -r requirements.txt",
                "Check Python virtual environment is activated",
                "Update dependencies: pip install --upgrade -r requirements.txt",
                "Check Python version compatibility (3.8+)",
                "Reinstall the application dependencies"
            ],
            ErrorCategory.CONFIG_ERROR: [
                "Check configuration file format",
                "Verify all required settings are present",
                "Reset to default configuration",
                "Check file permissions for config files",
                "Refer to configuration documentation"
            ],
            ErrorCategory.PERMISSION_ERROR: [
                "Check file and directory permissions",
                "Run application with appropriate privileges",
                "Ensure files are not read-only",
                "Check antivirus software blocking access",
                "Move files to user directory if needed"
            ]
        }
        
        return suggestions_map.get(category, ["Please try again or contact support"])
    
    def _log_error(self, error: PhishNetError, context: str = ""):
        """Log error with appropriate level"""
        log_msg = f"[{error.category.error_id}] {error.category.display_name}: {error}"
        if context:
            log_msg += f" (Context: {context})"
        
        if error.category.severity == "critical":
            self.logger.critical(log_msg)
        elif error.category.severity == "high":
            self.logger.error(log_msg)
        else:
            self.logger.warning(log_msg)
    
    def _track_error(self, error: PhishNetError):
        """Track error statistics"""
        category_id = error.category.error_id
        self.error_count[category_id] = self.error_count.get(category_id, 0) + 1
        
        # Add to error history
        self.last_errors.append({
            "timestamp": error.timestamp,
            "category": category_id,
            "message": str(error)
        })
        
        # Limit history size
        if len(self.last_errors) > self.max_error_history:
            self.last_errors = self.last_errors[-self.max_error_history:]
    
    def _generate_error_response(self, error: PhishNetError) -> Dict:
        """Generate comprehensive error response for UI"""
        
        # Determine UI display elements
        severity_icons = {
            "critical": "🚨",
            "high": "⚠️", 
            "medium": "⚠️",
            "low": "ℹ️"
        }
        
        severity_colors = {
            "critical": "#dc3545",  # Red
            "high": "#fd7e14",      # Orange
            "medium": "#ffc107",    # Yellow
            "low": "#17a2b8"        # Info blue
        }
        
        return {
            "success": False,
            "error": True,
            "category": error.category.error_id,
            "title": f"{severity_icons.get(error.category.severity, '⚠️')} {error.category.display_name}",
            "message": str(error),
            "details": error.details,
            "suggestions": error.suggestions,
            "severity": error.category.severity,
            "color": severity_colors.get(error.category.severity, "#ffc107"),
            "timestamp": error.timestamp.isoformat(),
            "troubleshooting_tips": self._get_troubleshooting_tips(error.category),
            "recovery_actions": self._get_recovery_actions(error.category)
        }
    
    def _get_troubleshooting_tips(self, category: ErrorCategory) -> List[str]:
        """Get specific troubleshooting tips"""
        
        tips_map = {
            ErrorCategory.OLLAMA_CONNECTION: [
                "Ollama must be running before starting the analysis",
                "The default Ollama URL is http://localhost:11434",
                "You can test Ollama with: curl http://localhost:11434/api/tags"
            ],
            ErrorCategory.MODEL_UNAVAILABLE: [
                "Models need to be downloaded before first use",
                "Popular models: phi4-mini, llama2, mistral",
                "Model downloads can be large (several GB)"
            ],
            ErrorCategory.NETWORK_TIMEOUT: [
                "First-time model loading takes longer",
                "Complex emails may require more processing time",
                "Local models are faster than online APIs"
            ]
        }
        
        return tips_map.get(category, [])
    
    def _get_recovery_actions(self, category: ErrorCategory) -> List[Dict[str, str]]:
        """Get specific recovery actions with labels"""
        
        actions_map = {
            ErrorCategory.OLLAMA_CONNECTION: [
                {"label": "Test Ollama Connection", "action": "test_connection"},
                {"label": "Restart Analysis", "action": "retry"},
                {"label": "Use Heuristic Mode", "action": "fallback_heuristic"}
            ],
            ErrorCategory.MODEL_UNAVAILABLE: [
                {"label": "Refresh Model List", "action": "refresh_models"},
                {"label": "Select Different Model", "action": "change_model"},
                {"label": "Use Heuristic Mode", "action": "fallback_heuristic"}
            ],
            ErrorCategory.INVALID_EMAIL: [
                {"label": "Clear and Re-enter Email", "action": "clear_input"},
                {"label": "Upload Different File", "action": "change_file"},
                {"label": "View Input Guidelines", "action": "show_help"}
            ]
        }
        
        return actions_map.get(category, [
            {"label": "Try Again", "action": "retry"},
            {"label": "Report Issue", "action": "report_bug"}
        ])
    
    def get_error_statistics(self) -> Dict:
        """Get error statistics for debugging"""
        return {
            "error_counts": self.error_count.copy(),
            "recent_errors": self.last_errors[-10:],
            "total_errors": sum(self.error_count.values()),
            "most_common_errors": sorted(
                self.error_count.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
        }
    
    def check_system_health(self) -> Dict:
        """Perform system health check"""
        health_status = {
            "overall_status": "healthy",
            "checks": [],
            "warnings": [],
            "errors": []
        }
        
        # Check Ollama connection
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                health_status["checks"].append("✅ Ollama service is running")
                
                # Check available models
                models = response.json().get("models", [])
                if models:
                    health_status["checks"].append(f"✅ {len(models)} model(s) available")
                else:
                    health_status["warnings"].append("⚠️ No models installed")
            else:
                health_status["errors"].append("❌ Ollama service not responding properly")
        except requests.exceptions.ConnectionError:
            health_status["errors"].append("❌ Cannot connect to Ollama service")
            health_status["overall_status"] = "unhealthy"
        except Exception as e:
            health_status["warnings"].append(f"⚠️ Ollama check failed: {str(e)}")
        
        # Check dependencies
        try:
            import streamlit
            health_status["checks"].append("✅ Streamlit available")
        except ImportError:
            health_status["errors"].append("❌ Streamlit not installed")
            health_status["overall_status"] = "unhealthy"
        
        # Requests is already imported at module level, just verify it's working
        health_status["checks"].append("✅ Requests library available")
        
        # Check optional dependencies
        optional_warnings = []
        try:
            import chardet
            health_status["checks"].append("✅ Character detection available")
        except ImportError:
            optional_warnings.append("⚠️ chardet not installed (optional - improves file encoding detection)")
        
        try:
            from bs4 import BeautifulSoup
            health_status["checks"].append("✅ HTML parsing available") 
        except ImportError:
            optional_warnings.append("⚠️ BeautifulSoup not installed (optional - improves HTML email parsing)")
        
        # Add optional warnings but don't count them for status degradation
        health_status["warnings"].extend(optional_warnings)
        
        # Set overall status based on critical errors only
        # Optional dependency warnings don't degrade the system status
        critical_warnings = [w for w in health_status["warnings"] if not w.startswith("⚠️ chardet") and not w.startswith("⚠️ BeautifulSoup")]
        
        if health_status["errors"]:
            health_status["overall_status"] = "unhealthy"
        elif critical_warnings:
            health_status["overall_status"] = "degraded"
        
        return health_status


# Global error handler instance
error_handler = ErrorHandler()


# Convenience functions for common error patterns
def handle_ollama_error(error: Exception, context: str = "") -> Dict:
    """Handle Ollama-related errors"""
    return error_handler.handle_error(error, context, ErrorCategory.OLLAMA_CONNECTION)


def handle_processing_error(error: Exception, context: str = "") -> Dict:
    """Handle processing-related errors"""
    return error_handler.handle_error(error, context, ErrorCategory.LLM_PROCESSING)


def handle_input_error(error: Exception, context: str = "") -> Dict:
    """Handle input validation errors"""
    return error_handler.handle_error(error, context, ErrorCategory.INVALID_EMAIL)


def safe_execute(func: Callable, *args, **kwargs) -> Dict:
    """
    Safely execute a function with comprehensive error handling.
    
    Args:
        func: Function to execute
        *args, **kwargs: Arguments for the function
        
    Returns:
        Dict with either success result or error information
    """
    try:
        result = func(*args, **kwargs)
        return {"success": True, "result": result, "error": False}
    except Exception as e:
        return error_handler.handle_error(e, f"Error in {func.__name__}")