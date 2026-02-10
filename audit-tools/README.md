# 🔍 Audit Tools

This directory contains all the core security auditing tools developed for the Security Audit Lab project. These tools are designed for SOC analysts, penetration testers, and security researchers.

## 📁 Available Tools

| Tool | File | Description |
|------|------|-------------|
| Port Scanner | [`port_scanner.py`](port_scanner.py) | Multi-threaded port scanner with service detection |
| Log Analyzer | [`log_analyzer.py`](log_analyzer.py) | Advanced log analysis with anomaly detection |
| Vulnerability Scanner | [`vuln_scanner.py`](vuln_scanner.py) | OWASP Top 10 web vulnerability scanner |
| SQL Injection Tester | [`sql_injection_tester.py`](sql_injection_tester.py) | Automated SQL injection detection |
| Network Enumeration | [`network_enumeration.py`](network_enumeration.py) | Comprehensive network discovery |
| Report Generator | [`report_generator.py`](report_generator.py) | Professional security report generation |
| Packet Sniffer | [`packet_sniffer.py`](packet_sniffer.py) | Network traffic capture and analysis |

## 🚀 Quick Usage

### Port Scanner
```bash
python port_scanner.py -t 192.168.1.1 -p 1-1000 --threads 50 -o results.json
```

### Log Analyzer
```bash
python log_analyzer.py -f /var/log/auth.log --anomaly-detection --severity high
```

### Vulnerability Scanner
```bash
python vuln_scanner.py -u http://localhost:8080 --owasp-top-10 -v
```

### SQL Injection Tester
```bash
python sql_injection_tester.py -u "http://localhost/api/users?id=1" --test-all
```

### Network Enumeration
```bash
python network_enumeration.py -t 192.168.1.0/24 --discover --verbose
```

### Report Generator
```bash
python report_generator.py -i scan_results.json -o report.pdf --format pdf
```

### Packet Sniffer
```bash
python packet_sniffer.py -i eth0 --filter "port 80" --save capture.pcap
```

## 📋 Common Options

All tools support the following common options:

- `-h, --help`: Show help message
- `-o, --output`: Output file path (JSON by default)
- `-v, --verbose`: Enable verbose output
- `-q, --quiet`: Suppress non-critical output
- `--log-file`: Log file path for debugging

## 🔧 Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install scapy for packet sniffer (may require root)
pip install scapy

# For PDF report generation
pip install reportlab weasyprint
```

## 🧪 Testing

```bash
# Run all tool tests
python -m pytest tests/ -v

# Test specific tool
python -m pytest tests/test_port_scanner.py -v
```

## 📊 Output Formats

All tools support JSON output for integration with other systems:

```json
{
  "tool": "port_scanner",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "target": "192.168.1.1",
  "results": {
    "open_ports": [22, 80, 443, 3306],
    "services": {
      "22": "ssh",
      "80": "http",
      "443": "https",
      "3306": "mysql"
    }
  },
  "scan_duration": "12.34s"
}
```

## ⚠️ Legal Notice

These tools are provided for authorized security testing and educational purposes only. Always ensure you have proper authorization before scanning or testing any system you do not own.

## 📝 License

MIT License - See root README.md for details.
