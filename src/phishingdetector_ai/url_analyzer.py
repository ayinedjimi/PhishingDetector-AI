"""
URL Analysis Module for Phishing Detection

Author: Ayi NEDJIMI
Website: https://ayinedjimi-consultants.fr
"""

import asyncio
import re
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import dns.resolver
import requests
from bs4 import BeautifulSoup
import structlog

logger = structlog.get_logger(__name__)


class URLAnalyzer:
    """
    Comprehensive URL analyzer for phishing detection.

    Author: Ayi NEDJIMI
    """

    def __init__(self, timeout: int = 10):
        """Initialize URL analyzer."""
        self.timeout = timeout
        self.logger = logger.bind(component="url_analyzer")

    async def analyze_url_comprehensive(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive URL analysis.

        Args:
            url: URL to analyze

        Returns:
            Analysis results
        """
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "structural_analysis": self.analyze_structure(url),
            "dns_analysis": await self.analyze_dns_async(url),
            "ssl_analysis": await self.check_ssl_async(url),
            "content_analysis": await self.analyze_content_async(url),
            "reputation": self.check_reputation(url),
        }

        # Calculate overall risk score
        risk_factors = []

        if not results["structural_analysis"]["is_https"]:
            risk_factors.append("No HTTPS")

        if results["structural_analysis"]["has_ip_address"]:
            risk_factors.append("IP address in URL")

        if not results["ssl_analysis"]["valid_certificate"]:
            risk_factors.append("Invalid SSL certificate")

        if results["dns_analysis"]["is_suspicious"]:
            risk_factors.append("Suspicious DNS")

        results["risk_factors"] = risk_factors
        results["risk_score"] = min(len(risk_factors) * 0.25, 1.0)

        return results

    def analyze_structure(self, url: str) -> Dict[str, Any]:
        """Analyze URL structure."""
        parsed = urlparse(url)

        return {
            "scheme": parsed.scheme,
            "is_https": parsed.scheme == "https",
            "domain": parsed.netloc,
            "path": parsed.path,
            "has_ip_address": bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc)),
            "subdomain_count": len(parsed.netloc.split('.')),
            "url_length": len(url),
            "has_at_symbol": '@' in url,
            "suspicious_tld": any(tld in parsed.netloc.lower() for tld in ['.tk', '.ml', '.ga']),
        }

    async def analyze_dns_async(self, url: str) -> Dict[str, Any]:
        """Analyze DNS records."""
        try:
            domain = urlparse(url).netloc

            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]

            # A record
            a_records = await asyncio.to_thread(
                lambda: list(dns.resolver.resolve(domain, 'A'))
            )

            # MX record
            try:
                mx_records = await asyncio.to_thread(
                    lambda: list(dns.resolver.resolve(domain, 'MX'))
                )
            except Exception:
                mx_records = []

            return {
                "has_dns": True,
                "a_records": [str(r) for r in a_records],
                "mx_records": [str(r.exchange) for r in mx_records],
                "is_suspicious": len(a_records) > 10,  # Many IPs suspicious
            }

        except Exception as e:
            self.logger.warning("DNS lookup failed", error=str(e))
            return {
                "has_dns": False,
                "error": str(e),
                "is_suspicious": True,
            }

    async def check_ssl_async(self, url: str) -> Dict[str, Any]:
        """Check SSL certificate."""
        if not url.startswith('https'):
            return {"valid_certificate": False, "reason": "Not HTTPS"}

        try:
            parsed = urlparse(url)
            hostname = parsed.netloc

            context = ssl.create_default_context()

            def get_cert():
                with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        return ssock.getpeercert()

            cert = await asyncio.to_thread(get_cert)

            return {
                "valid_certificate": True,
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "not_after": cert.get('notAfter'),
            }

        except Exception as e:
            self.logger.warning("SSL check failed", error=str(e))
            return {
                "valid_certificate": False,
                "error": str(e),
            }

    async def analyze_content_async(self, url: str) -> Dict[str, Any]:
        """Analyze page content."""
        try:
            def fetch_content():
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                return response

            response = await asyncio.to_thread(fetch_content)

            soup = BeautifulSoup(response.text, 'html.parser')

            # Count forms
            forms = soup.find_all('form')
            input_fields = soup.find_all('input', {'type': ['password', 'email', 'text']})

            # Check for iframes
            iframes = soup.find_all('iframe')

            # External links
            links = soup.find_all('a', href=True)
            external_links = [
                link['href'] for link in links
                if link['href'].startswith('http') and urlparse(url).netloc not in link['href']
            ]

            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "form_count": len(forms),
                "input_field_count": len(input_fields),
                "iframe_count": len(iframes),
                "external_link_count": len(external_links),
                "has_password_field": any(inp.get('type') == 'password' for inp in input_fields),
                "title": soup.title.string if soup.title else "",
            }

        except Exception as e:
            self.logger.warning("Content analysis failed", error=str(e))
            return {
                "error": str(e),
                "accessible": False,
            }

    def check_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation against known patterns."""
        domain = urlparse(url).netloc.lower()

        # Common legitimate domains
        trusted_domains = [
            'google.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'github.com', 'paypal.com'
        ]

        is_trusted = any(trusted in domain for trusted in trusted_domains)

        # Suspicious patterns
        suspicious_patterns = [
            r'secure[_-]?login',
            r'verify[_-]?account',
            r'update[_-]?payment',
            r'suspended[_-]?account',
        ]

        has_suspicious_pattern = any(
            re.search(pattern, domain) for pattern in suspicious_patterns
        )

        return {
            "is_trusted": is_trusted,
            "has_suspicious_pattern": has_suspicious_pattern,
            "risk_level": "low" if is_trusted else ("high" if has_suspicious_pattern else "medium"),
        }
