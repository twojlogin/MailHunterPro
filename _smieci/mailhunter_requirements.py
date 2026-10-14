# Legacy MailHunter dependency list
# This file is intentionally kept as a pure requirements file.
# The project-level dependency source of truth is the root requirements.txt.
# Do not place Python scripts or setup logic in a requirements file.

# Core email + parsing
imaplib3==0.5.2
email-validator>=1.3.1
beautifulsoup4>=4.12.0
lxml>=4.9.0
requests>=2.31.0

# Security / networking
cryptography>=41.0.0
python-whois>=0.8.0
PySocks>=1.7.1

# Data processing
pandas>=2.0.3

# Web UI
flask>=3.0.0

# Testing
pytest>=7.4.0
pytest-cov>=4.1.0

# Optional packages (uncommented only if explicitly needed)
# PyQt5>=5.15.9
# pytesseract>=0.3.10
# pillow>=10.0.0
# matplotlib>=3.7.2
# openai>=0.28.0
# anthropic>=0.3.0
# openpyxl>=3.1.2
# python-docx>=0.8.11
