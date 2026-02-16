# PhishingDetector-AI 🎣

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![HuggingFace](https://img.shields.io/badge/🤗-HuggingFace-yellow)](https://huggingface.co/AYI-NEDJIMI)

**AI-Powered Phishing Detection using BERT and Advanced Analysis**

## Author / Auteur

**Ayi NEDJIMI**
- Website: [ayinedjimi-consultants.fr](https://ayinedjimi-consultants.fr)
- HuggingFace: [AYI-NEDJIMI](https://huggingface.co/AYI-NEDJIMI)
- Email: contact@ayinedjimi-consultants.fr

## Features

- BERT-based email classification
- Comprehensive URL analysis (DNS, SSL, content)
- Real-time phishing detection
- Multi-language support
- REST API with FastAPI
- Batch processing capabilities

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Usage

```python
from phishingdetector_ai import PhishingDetector

detector = PhishingDetector()

# Analyze email
result = detector.analyze_email("Your email content here...")

print(f"Is Phishing: {result.is_phishing}")
print(f"Confidence: {result.confidence:.2%}")
print(f"Indicators: {result.indicators}")

# Analyze URL
url_result = detector.analyze_url("https://suspicious-site.com")
```

## Related Projects

- [VulnScanner-LLM](https://github.com/ayinedjimi/VulnScanner-LLM)
- [ThreatIntel-GPT](https://github.com/ayinedjimi/ThreatIntel-GPT)
- [LogParser-AI](https://github.com/ayinedjimi/LogParser-AI)

## License

MIT License - Copyright (c) 2024 Ayi NEDJIMI

---

Made with ❤️ by Ayi NEDJIMI | [ayinedjimi-consultants.fr](https://ayinedjimi-consultants.fr)
