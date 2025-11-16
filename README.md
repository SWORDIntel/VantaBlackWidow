# BlackWidow TEMPEST Edition

![Security Scanner](SQLi.png)

> **⚠️ DISCLAIMER: For Authorized Security Testing Only**
>
> This software is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Use responsibly and only on systems you own or have explicit written permission to test.

## 🚀 Overview

BlackWidow TEMPEST Edition is an advanced, integrated web security scanner that combines the best features of multiple security testing tools into a single, polished application with a TEMPEST-grade secure user interface.

This is the result of integrating:
- **Enhanced Tarantula** - AI-powered vulnerability analysis
- **BlackWidow** - Comprehensive reconnaissance and data gathering
- **InjectX** - Advanced payload fuzzing library
- **TEMPEST UI** - Secure, professional interface with operational security features

## ✨ Key Features

### 🔍 Enhanced Reconnaissance
- **Subdomain enumeration** - Automatically discover subdomains
- **Email & phone extraction** - Gather contact information
- **Parameter discovery** - Find dynamic URL parameters and form fields
- **Technology fingerprinting** - Identify technologies in use
- **API endpoint discovery** - Locate REST/GraphQL endpoints
- **Sensitive file detection** - Find configuration files, backups, etc.

### 🎯 Advanced Vulnerability Detection
- **SQL Injection** - Multiple techniques and databases
- **Cross-Site Scripting (XSS)** - Reflected, stored, and DOM-based
- **Server-Side Template Injection (SSTI)** - Multiple template engines
- **Local/Remote File Inclusion** - Path traversal and file access
- **XXE (XML External Entity)** - XML parser attacks
- **Command Injection** - OS command execution
- **SSRF** - Server-Side Request Forgery
- **LDAP Injection** - Directory service attacks
- **NoSQL Injection** - MongoDB, Redis, etc.
- **Open Redirect** - URL redirection vulnerabilities
- **CRLF Injection** - HTTP response splitting

### 🤖 AI-Powered Analysis
- **OpenAI GPT integration** - Intelligent vulnerability assessment
- **Context-aware payload generation** - Smart fuzzing strategies
- **Pattern learning** - Learns from failed attempts
- **Confidence scoring** - Prioritizes findings by reliability

### 🛡️ TEMPEST-Grade Secure UI
- **Encrypted configuration storage** - Secure API keys and settings
- **Audit logging with integrity checks** - Track all actions
- **Sensitive data redaction** - Auto-redact credentials in logs
- **Secure clipboard management** - Timed clipboard clearing
- **Professional dark theme** - Reduces electromagnetic emissions
- **Session management** - Secure session handling
- **Minimal data persistence** - Operational security focused

### 📊 Comprehensive Reporting
- **Real-time console output** - Live scan progress
- **Tabular results view** - Easy vulnerability review
- **Statistical analysis** - Scan metrics and findings
- **JSON export** - Machine-readable reports
- **IOC identification** - Extract indicators of compromise

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- Chrome browser (for Selenium)
- OpenAI API key (optional, for AI features)

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/SWORDIntel/BlackWidow.git
cd BlackWidow
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
python BlackWidow.py
```

## 📖 Usage

### Quick Start

1. **Launch the application:**
```bash
python BlackWidow.py
```

2. **Configure settings:**
   - Enter your OpenAI API key (optional, for AI features)
   - Enter target domain (e.g., `example.com`)
   - Select scan options (reconnaissance, vulnerability scan, fuzzing, etc.)

3. **Start the scan:**
   - Click "▶ START SCAN"
   - Monitor progress in the console tab
   - Review findings in the results tab
   - Check statistics in the statistics tab

4. **Save and export:**
   - Click "💾 SAVE CONFIG" to save settings
   - Reports are automatically saved as JSON files
   - Use "🗑️ CLEAR DATA" to securely wipe all data

### Scan Options

- **Reconnaissance** - Gather intelligence (subdomains, emails, phones, etc.)
- **Vulnerability Scan** - Test for common vulnerabilities
- **AI Analysis** - Use GPT for intelligent analysis (requires API key)
- **Deep Crawl** - Comprehensive site mapping with Selenium
- **Advanced Fuzzing** - Test with InjectX payload library

### Command Line Interface

For automated scanning, you can also use individual modules:

```bash
# Run reconnaissance only
python reconnaissance.py example.com

# Run selenium crawler
python selenium_parser.py https://example.com

# Identify IOCs in a response file
python ioc_identifier.py
```

## 🏗️ Architecture

```
BlackWidow TEMPEST/
├── BlackWidow.py           # Main integrated application
├── tempest_ui.py           # TEMPEST-grade secure UI
├── reconnaissance.py       # Enhanced reconnaissance module
├── advanced_fuzzer.py      # Advanced fuzzing with InjectX payloads
├── selenium_parser.py      # Selenium-based crawler
├── ioc_identifier.py       # IOC identification
├── Tarantula.py           # Legacy Tarantula scanner
└── vulnReport.py          # Vulnerability reporting
```

## 🔐 Security Features

### Data Protection
- **Encrypted storage** - All sensitive configuration encrypted with Fernet
- **Secure key management** - Encryption keys stored with restrictive permissions
- **Memory safety** - Sensitive data cleared from memory after use
- **Audit trail** - All actions logged with integrity hashes

### Operational Security (OPSEC)
- **Redaction mode** - Automatically redact sensitive data in logs
- **Secure clipboard** - Clipboard data auto-cleared after timeout
- **Minimal emissions** - TEMPEST-compliant color scheme
- **Session isolation** - Each scan isolated from others

### Network Security
- **TLS/SSL support** - Encrypted communications
- **Proxy support** - Route through intermediary
- **Rate limiting** - Avoid detection and DoS
- **Retry strategy** - Handle network failures gracefully

## 📊 Output Format

### JSON Report Structure
```json
{
  "reconnaissance": {
    "subdomains": [...],
    "emails": [...],
    "phone_numbers": [...],
    "parameters": {...},
    "technologies": [...],
    "api_endpoints": [...]
  },
  "vulnerabilities": [
    {
      "endpoint": "/api/users",
      "parameter": "id",
      "type": "sql_injection",
      "confidence": "HIGH",
      "payload": "' OR '1'='1",
      "evidence": "SQL error: mysql syntax",
      "timestamp": 1234567890
    }
  ],
  "statistics": {
    "total_requests": 1234,
    "vulnerabilities_found": 5,
    "critical_findings": 1,
    "high_findings": 2,
    "medium_findings": 1,
    "low_findings": 1
  }
}
```

## 🎯 Best Practices

1. **Always get written permission** before testing any system
2. **Use responsibly** - Respect rate limits and server resources
3. **Verify findings** - Manual verification recommended for all findings
4. **Document everything** - Keep detailed records of testing
5. **Report responsibly** - Follow responsible disclosure practices
6. **Stay legal** - Understand local laws and regulations
7. **Keep updated** - Regularly update dependencies for security patches

## ⚖️ Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. Users are solely responsible for:

- Obtaining proper authorization before testing
- Compliance with all applicable laws and regulations
- Any consequences resulting from misuse
- Respecting privacy and data protection laws

By using this tool, you agree that:
- You will only use it on systems you own or have explicit written permission to test
- You understand and accept all risks associated with security testing
- You will not use it for any malicious purposes
- The authors are not liable for any misuse or damage caused by this tool

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **OpenAI** - For providing the GPT API
- **Selenium** - For web automation capabilities
- **andrewhenke** - For the original BlackWidow Python 3 port
- **Security community** - For tools, techniques, and inspiration

## 📞 Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Check existing documentation
- Review the code comments

## 🔄 Version History

### v2.0.0 - TEMPEST Edition (Current)
- Integrated Tarantula AI features
- Added BlackWidow reconnaissance capabilities
- Implemented InjectX payload library
- Created TEMPEST-grade secure UI
- Enhanced reporting and statistics
- Added IOC identification
- Improved security features

### v1.0.0 - Original Tarantula
- AI-powered vulnerability analysis
- Basic GUI
- Selenium crawling

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
