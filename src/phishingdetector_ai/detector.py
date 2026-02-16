"""
Phishing Detection Module using BERT and ML

Author: Ayi NEDJIMI
Website: https://ayinedjimi-consultants.fr
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


@dataclass
class DetectionResult:
    """Phishing detection result."""
    is_phishing: bool
    confidence: float
    risk_score: float
    indicators: List[str]
    features: Dict[str, Any]
    url: Optional[str] = None
    email_content: Optional[str] = None
    recommendations: List[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_phishing": self.is_phishing,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "indicators": self.indicators,
            "features": self.features,
            "url": self.url,
            "recommendations": self.recommendations or [],
        }


class PhishingDetector:
    """
    AI-Powered Phishing Detector using BERT.

    Author: Ayi NEDJIMI
    Website: https://ayinedjimi-consultants.fr
    HuggingFace: https://huggingface.co/AYI-NEDJIMI

    Features:
    - BERT-based text classification
    - URL analysis
    - Email content analysis
    - Real-time detection
    - Multi-language support
    """

    def __init__(
        self,
        model_name: str = "bert-base-uncased",
        device: Optional[str] = None
    ):
        """Initialize phishing detector."""
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.logger = logger.bind(component="phishing_detector")

        self.logger.info("Loading BERT model", model=model_name, device=self.device)

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=2
            ).to(self.device)
            self.model.eval()
        except Exception as e:
            self.logger.error("Failed to load model", error=str(e))
            raise

    def analyze_url(self, url: str) -> DetectionResult:
        """
        Analyze URL for phishing indicators.

        Args:
            url: URL to analyze

        Returns:
            Detection result
        """
        indicators = []
        features = {}

        # URL length check
        if len(url) > 75:
            indicators.append("URL too long")
            features["url_length"] = len(url)

        # IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            indicators.append("IP address in URL")
            features["has_ip"] = True

        # @ symbol (user redirection)
        if '@' in url:
            indicators.append("@ symbol found (redirection)")
            features["has_at_symbol"] = True

        # Multiple subdomains
        domain_parts = url.split('://')[1].split('/')[0].split('.')
        if len(domain_parts) > 3:
            indicators.append("Multiple subdomains")
            features["subdomain_count"] = len(domain_parts)

        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        if any(tld in url.lower() for tld in suspicious_tlds):
            indicators.append("Suspicious TLD")
            features["suspicious_tld"] = True

        # HTTPS check
        features["is_https"] = url.startswith('https://')
        if not features["is_https"]:
            indicators.append("No HTTPS")

        # Calculate risk score
        risk_score = min(len(indicators) * 0.2, 1.0)
        is_phishing = risk_score > 0.5

        return DetectionResult(
            is_phishing=is_phishing,
            confidence=risk_score,
            risk_score=risk_score,
            indicators=indicators,
            features=features,
            url=url,
            recommendations=self._get_recommendations(is_phishing, indicators)
        )

    async def analyze_email_async(self, email_content: str) -> DetectionResult:
        """
        Analyze email content for phishing using BERT.

        Args:
            email_content: Email text content

        Returns:
            Detection result
        """
        indicators = []
        features = {}

        # Keyword analysis
        phishing_keywords = [
            'urgent', 'verify', 'suspended', 'locked', 'confirm',
            'click here', 'act now', 'limited time', 'winner',
            'congratulations', 'prize', 'tax refund', 'account',
        ]

        content_lower = email_content.lower()
        found_keywords = [kw for kw in phishing_keywords if kw in content_lower]

        if found_keywords:
            indicators.append(f"Phishing keywords found: {', '.join(found_keywords[:3])}")
            features["phishing_keywords"] = found_keywords

        # Urgency detection
        urgency_patterns = [
            r'within \d+ (hours?|days?)',
            r'immediately',
            r'as soon as possible',
            r'right now'
        ]

        if any(re.search(pattern, content_lower) for pattern in urgency_patterns):
            indicators.append("Urgency language detected")
            features["has_urgency"] = True

        # Link analysis
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
        if urls:
            features["url_count"] = len(urls)
            if len(urls) > 3:
                indicators.append(f"Multiple URLs ({len(urls)} found)")

        # BERT classification
        try:
            inputs = self.tokenizer(
                email_content[:512],  # Limit to 512 tokens
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=512
            ).to(self.device)

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)
                phishing_prob = probs[0][1].item()

            features["bert_score"] = phishing_prob

            if phishing_prob > 0.7:
                indicators.append(f"High BERT phishing score: {phishing_prob:.2f}")

        except Exception as e:
            self.logger.error("BERT classification failed", error=str(e))
            phishing_prob = len(indicators) * 0.2

        # Calculate final score
        rule_score = min(len(indicators) * 0.15, 0.6)
        final_score = (phishing_prob * 0.6 + rule_score * 0.4)

        is_phishing = final_score > 0.5

        return DetectionResult(
            is_phishing=is_phishing,
            confidence=final_score,
            risk_score=final_score,
            indicators=indicators,
            features=features,
            email_content=email_content[:200],
            recommendations=self._get_recommendations(is_phishing, indicators)
        )

    def analyze_email(self, email_content: str) -> DetectionResult:
        """Synchronous email analysis."""
        return asyncio.run(self.analyze_email_async(email_content))

    def _get_recommendations(
        self,
        is_phishing: bool,
        indicators: List[str]
    ) -> List[str]:
        """Generate recommendations based on detection."""
        if not is_phishing:
            return ["Email appears legitimate, but always verify sender"]

        recommendations = [
            "Do not click any links",
            "Do not provide personal information",
            "Verify sender through official channels",
            "Report to your IT security team",
        ]

        if "No HTTPS" in indicators:
            recommendations.append("URLs use HTTP - highly suspicious")

        if any("urgent" in i.lower() for i in indicators):
            recommendations.append("Urgency is a common phishing tactic")

        return recommendations

    async def batch_analyze_async(
        self,
        items: List[Dict[str, str]],
        max_concurrent: int = 10
    ) -> List[DetectionResult]:
        """Analyze multiple emails/URLs concurrently."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_item(item: Dict[str, str]) -> DetectionResult:
            async with semaphore:
                if "url" in item:
                    return self.analyze_url(item["url"])
                elif "email" in item:
                    return await self.analyze_email_async(item["email"])
                else:
                    raise ValueError("Item must have 'url' or 'email' key")

        tasks = [analyze_item(item) for item in items]
        return await asyncio.gather(*tasks)

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            "model_name": self.model.config.name_or_path,
            "device": str(self.device),
            "num_labels": self.model.config.num_labels,
            "author": "Ayi NEDJIMI",
            "website": "https://ayinedjimi-consultants.fr",
            "huggingface": "https://huggingface.co/AYI-NEDJIMI",
        }
