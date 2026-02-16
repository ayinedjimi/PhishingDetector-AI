"""
PhishingDetector-AI: AI-Powered Phishing Detection System

Author: Ayi NEDJIMI
Contact: contact@ayinedjimi-consultants.fr
Website: https://ayinedjimi-consultants.fr
HuggingFace: https://huggingface.co/AYI-NEDJIMI
"""

__version__ = "1.0.0"
__author__ = "Ayi NEDJIMI"
__email__ = "contact@ayinedjimi-consultants.fr"

from .detector import PhishingDetector
from .url_analyzer import URLAnalyzer
from .content_analyzer import ContentAnalyzer

__all__ = ["PhishingDetector", "URLAnalyzer", "ContentAnalyzer"]
