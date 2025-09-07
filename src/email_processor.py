"""
Email Content Processing Module for Phish-Net

This module handles email parsing, content extraction, and preparation
for analysis by the LLM. It supports both plain text input and .eml files.
"""

import email
import re
from typing import Dict, List, Optional, Tuple, Union
import html
from datetime import datetime

# Optional imports with fallbacks
try:
    import chardet
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from email.message import Message
from email.parser import Parser


class EmailProcessor:
    """
    Processes email content for phishing analysis.
    
    Handles both plain text emails and .eml files, extracting relevant
    headers, body content, URLs, and metadata for LLM analysis.
    """
    
    # Trusted domains loaded from file
    TRUSTED_DOMAINS = set()
    
    def __init__(self, trusted_domains_path: str = "trusted_domains.txt"):
        self.parser = Parser()
        self._load_trusted_domains(trusted_domains_path)

    def _load_trusted_domains(self, path: str):
        """Load trusted domains from a file (one per line, ignore comments/empty lines)"""
        try:
            with open(path, "r") as f:
                domains = set()
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.add(line.lower())
                self.TRUSTED_DOMAINS = domains
        except Exception as e:
            # If file missing, fallback to empty set
            self.TRUSTED_DOMAINS = set()
            # Optionally log error or print warning
            print(f"WARNING: Could not load trusted domains from {path}: {e}")
        
    def process_email(self, content: str, is_file_content: bool = False) -> Dict:
        """
        Main processing function that handles both plain text and .eml content.
        
        Args:
            content: Raw email content or .eml file content
            is_file_content: True if content is from an uploaded .eml file
            
        Returns:
            Dict containing processed email data
        """
        try:
            if is_file_content or self._is_eml_format(content):
                return self._process_eml_content(content)
            else:
                return self._process_plain_text(content)
        except Exception as e:
            return self._create_error_result(f"Error processing email: {str(e)}")
    
    def _is_eml_format(self, content: str) -> bool:
        """Check if content appears to be in .eml format"""
        # Look for email headers
        header_patterns = [
            r'^Message-ID:\s*.+',
            r'^Return-Path:\s*.+',
            r'^Received:\s*.+',
            r'^MIME-Version:\s*.+'
        ]
        
        lines = content.split('\n')[:10]  # Check first 10 lines
        header_count = 0
        
        for line in lines:
            for pattern in header_patterns:
                if re.match(pattern, line, re.IGNORECASE):
                    header_count += 1
                    break
        
        # Also check for basic headers
        basic_headers = ['from:', 'to:', 'subject:', 'date:']
        for line in lines:
            for header in basic_headers:
                if line.lower().strip().startswith(header):
                    header_count += 1
                    break
        
        return header_count >= 2
    
    def _process_eml_content(self, content: str) -> Dict:
        """Process .eml file content"""
        try:
            # Parse the email
            msg = self.parser.parsestr(content)
            
            # Extract headers
            headers = self._extract_headers(msg)
            
            # Extract body content
            body_data = self._extract_body(msg)
            
            # Extract URLs and email addresses
            all_content = f"{headers.get('subject', '')} {body_data['text']} {body_data['html_text']}"
            urls = self._extract_urls(all_content)
            email_addresses = self._extract_email_addresses(all_content)
            
            # Analyze structure
            structure = self._analyze_email_structure(msg)
            
            return {
                "success": True,
                "format": "eml",
                "headers": headers,
                "body": body_data,
                "urls": urls,
                "email_addresses": email_addresses,
                "structure": structure,
                "metadata": self._generate_metadata(headers, body_data, urls),
                "processed_content": self._prepare_for_analysis(headers, body_data, urls, email_addresses)
            }
            
        except Exception as e:
            return self._create_error_result(f"Error parsing .eml content: {str(e)}")
    
    def _process_plain_text(self, content: str) -> Dict:
        """Process plain text email content"""
        try:
            # Try to parse headers from plain text
            headers = self._extract_headers_from_text(content)
            
            # Separate headers from body
            body_text = self._extract_body_from_text(content, headers)
            
            body_data = {
                "text": body_text,
                "html": "",
                "html_text": "",
                "has_html": False
            }
            
            # Extract URLs and email addresses
            all_content = f"{headers.get('subject', '')} {body_text}"
            urls = self._extract_urls(all_content)
            email_addresses = self._extract_email_addresses(all_content)
            
            return {
                "success": True,
                "format": "plain_text",
                "headers": headers,
                "body": body_data,
                "urls": urls,
                "email_addresses": email_addresses,
                "structure": {"multipart": False, "parts": 1, "attachments": 0},
                "metadata": self._generate_metadata(headers, body_data, urls),
                "processed_content": self._prepare_for_analysis(headers, body_data, urls, email_addresses)
            }
            
        except Exception as e:
            return self._create_error_result(f"Error processing plain text: {str(e)}")
    
    def _extract_headers(self, msg: Message) -> Dict[str, str]:
        """Extract and normalize email headers"""
        headers = {}
        
        # Standard headers
        header_fields = [
            'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 
            'Reply-To', 'Return-Path', 'Message-ID', 'MIME-Version'
        ]
        
        for field in header_fields:
            value = msg.get(field, '')
            if value:
                headers[field.lower()] = self._clean_header_value(value)
        
        # Authentication headers
        auth_headers = [
            'Authentication-Results', 'DKIM-Signature', 'SPF', 'DMARC'
        ]
        
        for field in auth_headers:
            value = msg.get(field, '')
            if value:
                headers[f'auth_{field.lower().replace("-", "_")}'] = value
        
        return headers
    
    def _extract_headers_from_text(self, content: str) -> Dict[str, str]:
        """Extract headers from plain text content"""
        headers = {}
        lines = content.split('\n')
        
        header_patterns = {
            'from': r'^from:\s*(.+)$',
            'to': r'^to:\s*(.+)$',
            'cc': r'^cc:\s*(.+)$',
            'subject': r'^subject:\s*(.+)$',
            'date': r'^date:\s*(.+)$',
            'reply_to': r'^reply-to:\s*(.+)$',
        }
        
        for line in lines[:20]:  # Check first 20 lines for headers
            line = line.strip()
            if not line:
                continue
                
            for header_name, pattern in header_patterns.items():
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    headers[header_name] = self._clean_header_value(match.group(1))
                    break
        
        return headers
    
    def _extract_body(self, msg: Message) -> Dict:
        """Extract body content from email message"""
        body_data = {
            "text": "",
            "html": "",
            "html_text": "",
            "has_html": False
        }
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                
                if content_type == "text/plain":
                    payload = self._get_payload_safely(part)
                    if payload:
                        body_data["text"] += payload + "\n"
                
                elif content_type == "text/html":
                    payload = self._get_payload_safely(part)
                    if payload:
                        body_data["html"] += payload + "\n"
                        body_data["has_html"] = True
                        # Convert HTML to text
                        body_data["html_text"] += self._html_to_text(payload) + "\n"
        else:
            content_type = msg.get_content_type()
            payload = self._get_payload_safely(msg)
            
            if content_type == "text/plain":
                body_data["text"] = payload or ""
            elif content_type == "text/html":
                body_data["html"] = payload or ""
                body_data["has_html"] = True
                body_data["html_text"] = self._html_to_text(payload or "")
        
        # Clean up the text
        body_data["text"] = self._normalize_text(body_data["text"])
        body_data["html_text"] = self._normalize_text(body_data["html_text"])
        
        return body_data
    
    def _extract_body_from_text(self, content: str, headers: Dict) -> str:
        """Extract body text from plain text, removing headers"""
        lines = content.split('\n')
        body_start = 0
        
        # Find where headers end (first empty line or after known headers)
        for i, line in enumerate(lines):
            if not line.strip():  # Empty line typically separates headers from body
                body_start = i + 1
                break
            
            # If line doesn't look like a header, assume body has started
            if not re.match(r'^[a-zA-Z-]+:\s*.+', line):
                body_start = i
                break
        
        body_lines = lines[body_start:]
        return '\n'.join(body_lines).strip()
    
    def _get_payload_safely(self, part) -> Optional[str]:
        """Safely extract payload from email part"""
        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                # Try to decode with detected encoding
                try:
                    if HAS_CHARDET and 'chardet' in globals():
                        detected = chardet.detect(payload)
                        encoding = detected.get('encoding', 'utf-8') if detected else 'utf-8'
                        return payload.decode(encoding, errors='replace')
                    else:
                        return payload.decode('utf-8', errors='replace')
                except:
                    return payload.decode('utf-8', errors='replace')
            return str(payload) if payload else ""
        except Exception:
            return None
    
    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text while preserving structure"""
        try:
            # Unescape HTML entities
            html_content = html.unescape(html_content)
            
            if HAS_BS4 and 'BeautifulSoup' in globals():
                # Parse with BeautifulSoup
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Remove script and style elements
                for script in soup(["script", "style"]):
                    script.decompose()
                
                # Get text and normalize whitespace
                text = soup.get_text()
                lines = (line.strip() for line in text.splitlines())
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                text = ' '.join(chunk for chunk in chunks if chunk)
                
                return text
            else:
                # Fallback: simple tag removal
                return re.sub(r'<[^>]+>', ' ', html_content)
        except Exception:
            # Fallback: simple tag removal
            return re.sub(r'<[^>]+>', ' ', html_content)
    
    def _extract_urls(self, content: str) -> List[Dict]:
        """Extract URLs from content"""
        urls = []
        
        # URL patterns
        url_pattern = r'https?://[^\s<>"\'`]+|www\.[^\s<>"\'`]+'
        
        matches = re.finditer(url_pattern, content, re.IGNORECASE)
        
        for match in matches:
            url = match.group()
            
            # Clean up URL (remove trailing punctuation)
            url = re.sub(r'[.,;:!?\'")\]}>]+$', '', url)
            
            urls.append({
                "url": url,
                "display_text": url,
                "is_shortened": self._is_shortened_url(url),
                "is_suspicious": self._is_suspicious_url(url),
                "domain": self._extract_domain(url)
            })
        
        return urls
    
    def _extract_email_addresses(self, content: str) -> List[str]:
        """Extract email addresses from content"""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(pattern, content)))
    
    def _analyze_email_structure(self, msg: Message) -> Dict:
        """Analyze the structure of the email"""
        structure = {
            "multipart": msg.is_multipart(),
            "parts": 0,
            "attachments": 0,
            "content_types": []
        }
        
        if msg.is_multipart():
            for part in msg.walk():
                structure["parts"] += 1
                content_type = part.get_content_type()
                structure["content_types"].append(content_type)
                
                # Check for attachments
                if part.get_content_disposition() == 'attachment':
                    structure["attachments"] += 1
        else:
            structure["parts"] = 1
            structure["content_types"] = [msg.get_content_type()]
        
        return structure
    
    def _generate_metadata(self, headers: Dict, body: Dict, urls: List) -> Dict:
        """Generate metadata about the email"""
        sender_email = headers.get("from", "")
        is_trusted = self._is_trusted_sender(sender_email)
        
        return {
            "has_headers": len(headers) > 0,
            "header_count": len(headers),
            "has_html": body.get("has_html", False),
            "text_length": len(body.get("text", "")),
            "url_count": len(urls),
            "suspicious_url_count": sum(1 for url in urls if url.get("is_suspicious", False)),
            "shortened_url_count": sum(1 for url in urls if url.get("is_shortened", False)),
            "sender_trusted": is_trusted,
            "sender_domain": sender_email.split('@')[-1].lower() if '@' in sender_email else "",
            "processing_timestamp": datetime.now().isoformat()
        }
    
    def _prepare_for_analysis(self, headers: Dict, body: Dict, urls: List, emails: List) -> str:
        """Prepare structured content for LLM analysis"""
        content_parts = []
        
        # Add headers
        if headers:
            content_parts.append("=== EMAIL HEADERS ===")
            for key, value in headers.items():
                content_parts.append(f"{key.upper()}: {value}")
            content_parts.append("")
        
        # Add body content
        content_parts.append("=== EMAIL BODY ===")
        
        # Prefer plain text, fall back to HTML text
        body_text = body.get("text", "") or body.get("html_text", "")
        content_parts.append(body_text)
        
        # Add URL analysis
        if urls:
            content_parts.append("\n=== EXTRACTED URLS ===")
            for url_data in urls:
                url_info = f"URL: {url_data['url']}"
                if url_data.get("is_shortened"):
                    url_info += " (SHORTENED)"
                if url_data.get("is_suspicious"):
                    url_info += " (SUSPICIOUS)"
                content_parts.append(url_info)
        
        # Add email addresses
        if emails:
            content_parts.append(f"\n=== EXTRACTED EMAIL ADDRESSES ===")
            content_parts.extend(emails)
        
        return "\n".join(content_parts)
    
    # Helper methods
    
    def _clean_header_value(self, value: str) -> str:
        """Clean and normalize header values"""
        # Remove line breaks and excessive whitespace
        value = re.sub(r'\s+', ' ', str(value).strip())
        
        # Handle encoded headers
        try:
            from email.header import decode_header
            decoded_parts = decode_header(value)
            cleaned_parts = []
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    part = part.decode(encoding or 'utf-8', errors='replace')
                cleaned_parts.append(part)
            
            return ''.join(cleaned_parts)
        except:
            return value
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text content"""
        if not text:
            return ""
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove common email artifacts
        text = re.sub(r'\r\n|\r|\n', ' ', text)
        
        return text.strip()
    
    def _is_shortened_url(self, url: str) -> bool:
        """Check if URL is from a URL shortening service"""
        shortened_domains = [
            'bit.ly', 'tinyurl.com', 'short.link', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 't.co', 'goo.gl', 'tiny.cc'
        ]
        
        domain = self._extract_domain(url).lower()
        return any(shortened in domain for shortened in shortened_domains)
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Basic heuristic to identify potentially suspicious URLs"""
        url_lower = url.lower()
        
        # Extract domain from URL
        domain = self._extract_domain(url_lower).lower()
        
        # Check against trusted domains first
        if any(domain.endswith(f'.{trusted}') or domain == trusted for trusted in self.TRUSTED_DOMAINS):
            return False
        
        # Check for IP addresses instead of domains
        if re.search(r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', url):
            return True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'paypal.*\.(?!com)',  # PayPal spoofing
            r'amazon.*\.(?!com)',  # Amazon spoofing
            r'microsoft.*\.(?!com)',  # Microsoft spoofing
            r'google.*\.(?!com)',  # Google spoofing
            r'\.tk$', r'\.ml$', r'\.ga$',  # Suspicious TLDs
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return True
        
        return False
    
    def _is_trusted_sender(self, sender_email: str) -> bool:
        """Check if sender email is from a trusted domain"""
        if not sender_email or '@' not in sender_email:
            return False
            
        domain = sender_email.split('@')[-1].lower()
        return any(domain.endswith(f'.{trusted}') or domain == trusted for trusted in self.TRUSTED_DOMAINS)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Extract domain using regex
            match = re.search(r'https?://([^/]+)', url)
            return match.group(1) if match else url
        except:
            return url
    
    def _create_error_result(self, error_message: str) -> Dict:
        """Create standardized error result"""
        return {
            "success": False,
            "error": error_message,
            "format": "unknown",
            "headers": {},
            "body": {"text": "", "html": "", "html_text": "", "has_html": False},
            "urls": [],
            "email_addresses": [],
            "structure": {},
            "metadata": {},
            "processed_content": ""
        }