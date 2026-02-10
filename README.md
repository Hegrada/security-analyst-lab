# 🔐 Security Audit Lab

![Security Audit Lab](https://img.shields.io/badge/Security-Audit%20Lab-blue?style=for-the-badge)
![Python 3.x](https://img.shields.io/badge/Python-3.x-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

## 🎯 Overview

**Security Audit Lab** is a comprehensive virtual environment designed for security professionals, SOC analysts, and penetration testers to practice, demonstrate, and enhance their security auditing skills. This project showcases advanced Python programming, network security, vulnerability assessment, and SOC operations expertise.

## 🏗️ Architecture

```
security-analyst-lab/
├── audit-tools/              # Core security auditing tools (Python)
│   ├── port_scanner.py       # Multi-threaded port scanner
│   ├── log_analyzer.py       # Log analysis with anomaly detection
│   ├── vuln_scanner.py       # OWASP vulnerability scanner
│   ├── sql_injection_tester.py
│   ├── network_enumeration.py
│   ├── report_generator.py   # Automated report generation
│   └── packet_sniffer.py     # Network traffic analysis
├── vulnerable-apps/          # Target vulnerable applications (Docker)
│   ├── web-app/              # OWASP Top 10 vulnerable web app
│   ├── database/             # Misconfigured database
│   ├── api/                  # REST API with security flaws
│   └── docker-compose.yml
├── dashboard/                # Web-based monitoring dashboard
│   ├── app.py                # Flask/FastAPI application
│   ├── templates/
│   └── static/
├── reports/                  # Generated security reports
├── config/                   # Configuration files
├── docs/                     # Documentation
├── tests/                    # Unit tests
└── database/                 # Database models and schema
```

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/security-analyst-lab.git
cd security-analyst-lab

# Install dependencies
pip install -r requirements.txt

# Start vulnerable environment (Docker)
cd vulnerable-apps
docker-compose up -d

# Run a port scan
python audit-tools/port_scanner.py --target 127.0.0.1

# Start the dashboard
cd dashboard
python app.py
```

## 📦 Core Audit Tools

### 1. 🔍 Port Scanner ([`port_scanner.py`](audit-tools/port_scanner.py))
Multi-threaded port scanner with service detection and JSON export.

```bash
python audit-tools/port_scanner.py -t 192.168.1.1 -p 1-1000 --threads 50
```

### 2. 📊 Log Analyzer ([`log_analyzer.py`](audit-tools/log_analyzer.py))
Advanced log analysis with ML-based anomaly detection for SOC operations.

```bash
python audit-tools/log_analyzer.py -f /var/log/auth.log --anomaly-detection
```

### 3. 🛡️ Vulnerability Scanner ([`vuln_scanner.py`](audit-tools/vuln_scanner.py))
OWASP Top 10 vulnerability scanner for web applications.

```bash
python audit-tools/vuln_scanner.py -u http://localhost:8080 --owasp-top-10
```

### 4. 💉 SQL Injection Tester ([`sql_injection_tester.py`](audit-tools/sql_injection_tester.py))
Automated SQL injection detection and exploitation.

```bash
python audit-tools/sql_injection_tester.py -u "http://localhost/api/users?id=1"
```

### 5. 🌐 Network Enumeration ([`network_enumeration.py`](audit-tools/network_enumeration.py))
Comprehensive network discovery and enumeration.

```bash
python audit-tools/network_enumeration.py -t 192.168.1.0/24 --discover
```

### 6. 📋 Report Generator ([`report_generator.py`](audit-tools/report_generator.py))
Professional security report generation with PDF export.

```bash
python audit-tools/report_generator.py -i scan_results.json -o report.pdf
```

### 7. 📡 Packet Sniffer ([`packet_sniffer.py`](audit-tools/packet_sniffer.py))
Network traffic capture and analysis for threat detection.

```bash
python audit-tools/packet_sniffer.py -i eth0 --filter "port 80"
```

## 🎓 Skills Demonstrated

This project demonstrates expertise in:

| Skill | Technologies |
|-------|--------------|
| **Python Advanced** | Multi-threading, AsyncIO, OOP, Security Modules |
| **Network Security** | TCP/IP, DNS, HTTP/HTTPS, Packet Analysis (Scapy) |
| **Web Security** | OWASP Top 10, SQL Injection, XSS, CSRF |
| **SOC Operations** | Log Analysis, Anomaly Detection, Incident Response |
| **DevOps** | Docker, Docker Compose, CI/CD, Infrastructure-as-Code |
| **Database** | SQL, PostgreSQL, SQLite, Database Security |
| **API Development** | Flask, FastAPI, RESTful Services |
| **Documentation** | Technical Reports, User Guides, Security Documentation |

## 🔧 Installation

### Prerequisites
- Python 3.8+
- Docker & Docker Compose
- Git
- Network connectivity

### Full Installation

```bash
# Clone repository
git clone https://github.com/yourusername/security-analyst-lab.git
cd security-analyst-lab

# Install Python dependencies
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate   # Windows

pip install -r requirements.txt

# Setup vulnerable environment
cd vulnerable-apps
docker-compose up -d

# Verify services
docker-compose ps
```

## 📖 Documentation

- [Installation Guide](docs/installation.md)
- [Usage Instructions](docs/usage.md)
- [Vulnerabilities Reference](docs/vulnerabilities.md)
- [API Documentation](docs/api.md)
- [Contributing Guide](docs/contributing.md)

## 🐳 Vulnerable Applications

The lab includes pre-configured vulnerable applications for testing:

| Service | Port | Description |
|---------|------|-------------|
| Web App | 8080 | OWASP Top 10 vulnerable web application |
| Database | 3306 | MySQL with weak credentials |
| API | 5000 | REST API with security flaws |
| FTP | 2121 | Unsecured FTP server |
| SSH | 2222 | SSH with weak authentication |

```bash
# Access vulnerable web app
curl http://localhost:8080

# Connect to database
mysql -h localhost -P 3306 -u root -p
```

## 📊 Dashboard

The monitoring dashboard provides real-time visibility:

- **Security Metrics**: Vulnerabilities discovered, severity distribution
- **Scan History**: Timeline of all security assessments
- **Alert System**: Real-time notifications for critical findings
- **Report Generation**: Export detailed security reports

Access the dashboard at: `http://localhost:5000`

## 🧪 Testing

```bash
# Run unit tests
pytest tests/ -v

# Run integration tests
pytest tests/ -v --integration

# Generate coverage report
pytest tests/ --cov=audit_tools --cov-report=html
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](docs/contributing.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY.** This lab environment contains intentionally vulnerable applications for security testing and training. Never deploy these vulnerable configurations in production environments. Always obtain proper authorization before conducting security assessments.

---

## 👨‍💻 Author

**Your Name** - SOC Analyst | Security Researcher | Penetration Tester

- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/yourusername)
- Email: security@example.com

---

**⭐ Star this repository if you find it useful!**
