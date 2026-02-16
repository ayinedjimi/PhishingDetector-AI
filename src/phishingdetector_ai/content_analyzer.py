"""
Content Analysis Module for Email/Page Content

Author: Ayi NEDJIMI
Website: https://ayinedjimi-consultants.fr
"""

import re
from typing import Dict, List, Any
import structlog

logger = structlog.get_logger(__name__)


class ContentAnalyzer:
    """
    Analyze email and webpage content for phishing indicators.

    Author: Ayi NEDJIMI
    """

    def __init__(self):
        """Initialize content analyzer."""
        self.logger = logger.bind(component="content_analyzer")

        self.phishing_keywords = [
            'urgent', 'verify', 'suspended', 'locked', 'confirm', 'click here',
            'act now', 'limited time', 'winner', 'congratulations', 'prize',
            'tax refund', 'account verification', 'security alert', 'unusual activity'
        ]

        self.urgency_patterns = [
            r'within \d+ (hours?|days?)',
            r'immediately',
            r'as soon as possible',
            r'right now',
            r'expires? (today|tonight|soon)',
        ]

    def analyze_text(self, content: str) -> Dict[str, Any]:
        """Analyze text content for phishing indicators."""
        content_lower = content.lower()

        # Keyword detection
        found_keywords = [kw for kw in self.phishing_keywords if kw in content_lower]

        # Urgency detection
        urgency_matches = [
            pattern for pattern in self.urgency_patterns
            if re.search(pattern, content_lower)
        ]

        # URL extraction
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)

        # Email extraction
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)

        # Phone numbers
        phones = re.findall(r'\+?\d[\d\s\-\(\)]{7,}\d', content)

        # Suspicious patterns
        suspicious_patterns = self._check_suspicious_patterns(content)

        return {
            "phishing_keywords": found_keywords,
            "keyword_count": len(found_keywords),
            "urgency_indicators": urgency_matches,
            "url_count": len(urls),
            "urls": urls,
            "email_addresses": emails,
            "phone_numbers": phones,
            "suspicious_patterns": suspicious_patterns,
            "risk_score": self._calculate_content_risk(
                len(found_keywords),
                len(urgency_matches),
                len(urls),
                len(suspicious_patterns)
            ),
        }

    def _check_suspicious_patterns(self, content: str) -> List[str]:
        """Check for suspicious patterns."""
        patterns = []

        if re.search(r'click\s+(here|this|below)', content, re.I):
            patterns.append("Generic click here links")

        if re.search(r'verify\s+your\s+(account|identity|information)', content, re.I):
            patterns.append("Account verification request")

        if re.search(r'(suspended|blocked|locked|disabled)\s+account', content, re.I):
            patterns.append("Account suspension threat")

        if re.search(r're-?enter\s+your\s+(password|credentials)', content, re.I):
            patterns.append("Credential re-entry request")

        return patterns

    def _calculate_content_risk(
        self,
        keyword_count: int,
        urgency_count: int,
        url_count: int,
        suspicious_pattern_count: int
    ) -> float:
        """Calculate content risk score."""
        score = 0.0

        score += min(keyword_count * 0.1, 0.3)
        score += min(urgency_count * 0.15, 0.3)
        score += min(url_count * 0.05, 0.2)
        score += min(suspicious_pattern_count * 0.1, 0.2)

        return min(score, 1.0)
