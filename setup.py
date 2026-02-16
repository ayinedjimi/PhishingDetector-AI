"""Setup for PhishingDetector-AI

Author: Ayi NEDJIMI
"""

from setuptools import setup, find_packages

setup(
    name="phishingdetector-ai",
    version="1.0.0",
    author="Ayi NEDJIMI",
    author_email="contact@ayinedjimi-consultants.fr",
    description="AI-Powered Phishing Detection System",
    url="https://github.com/ayinedjimi/PhishingDetector-AI",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=[
        "torch>=2.0.0",
        "transformers>=4.35.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.4.0",
        "requests>=2.31.0",
        "fastapi>=0.104.1",
    ],
    keywords=["phishing", "detection", "ai", "bert", "cybersecurity"],
)
