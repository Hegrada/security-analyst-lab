# 📖 Usage Guide

Learn how to use the Security Audit Lab tools and components.

## 🔧 Command-Line Tools

### Port Scanner

Scan a target for open ports:

```bash
# Basic scan
python port_scanner.py -t 192.168.1.1

# Scan specific port range
python port_scanner.py -t 192.168.1.1 -p 1-1000

# Multi-threaded scan with verbose output
python port_scanner.py -t 192.168.1.1 -p 1-65535 --threads 100 -v

# Save results to JSON
python port_scanner.py -t localhost -o results.json
```

**Options:**
| Option | Description |
|--------|-------------|
| `-t, --target` | Target IP or hostname (required) |
| `-p, --ports` | Port range (default: 1-1024) |
| `--threads` | Number of threads (default: 100) |
| `--timeout` | Connection timeout (default: 2s) |
| `-o, --output` | Output JSON file |
| `-v, --verbose` | Verbose output |

### Vulnerability Scanner

Scan a web application for OWASP Top 10 vulnerabilities:

```bash
# Basic scan
python vuln_scanner.py -t http://localhost:8080

# Verbose output
python vuln_scanner.py -t http://localhost:8080 -v

# Scan with multiple threads
python vuln_scanner.py -t https://example.com --threads 20
```

### SQL Injection Tester

Test endpoints for SQL injection vulnerabilities:

```bash
# Test a URL with parameters
python sql_injection_tester.py -u "http://localhost/api/users?id=1"

# Verbose output
python sql_injection_tester.py -u "http://localhost/search.php?q=test" -v

# Save results
python sql_injection_tester.py -u "http://localhost/api" -o sqli_results.json
```

### Log Analyzer

Analyze log files for security events:

```bash
# Analyze a log file
python log_analyzer.py -f /var/log/auth.log

# Analyze directory recursively
python log_analyzer.py -d /var/log/ -r

# Anomaly detection enabled
python log_analyzer.py -f auth.log --anomaly-detection

# Filter by severity
python log_analyzer.py -f auth.log --severity high
```

### Network Enumerator

Discover hosts and enumerate network services:

```bash
# Scan a network range
python network_enumeration.py -t 192.168.1.0/24

# Scan specific IP range
python network_enumeration.py -t 192.168.1.1-50 -p 1-1000

# Verbose output
python network_enumeration.py -t 10.0.0.0/24 -v
```

### Report Generator

Generate security reports from scan results:

```bash
# Generate HTML report
python report_generator.py -i scan_results.json -o report.html --format html

# Generate Markdown report
python report_generator.py -i vuln_results.json -o report.md --format markdown

# Generate JSON report
python report_generator.py -i scan_results.json -o report.json --format json
```

### Packet Sniffer

Capture and analyze network traffic:

```bash
# Capture on default interface (60 seconds)
python packet_sniffer.py -d 60

# Capture on specific interface
python packet_sniffer.py -i eth0 -d 30

# Verbose capture
python packet_sniffer.py -i eth0 -v

# Save capture to file
python packet_sniffer.py -i eth0 -o capture.json
```

## 🐳 Docker Services

### Starting Services

```bash
cd vulnerable-apps

# Start all services
docker-compose up -d

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Accessing Services

| Service | URL | Credentials |
|---------|-----|--------------|
| Web App | http://localhost:8080 | - |
| API | http://localhost:5000/api | - |
| MySQL | localhost:3306 | root/toor |
| FTP | localhost:21 | anonymous |
| SSH | localhost:2222 | root/toor |

### Testing Vulnerable Applications

```bash
# SQL Injection Test
curl "http://localhost:8080/users?id=1' OR '1'='1"

# XSS Test
curl "http://localhost:8080/search?q=<script>alert('XSS')</script>"

# API Test
curl http://localhost:5000/api/users

# SSH Test
ssh root@localhost -p 2222
# Password: toor
```

## 📊 Dashboard

### Starting the Dashboard

```bash
cd dashboard
python app.py
```

Access the dashboard at: http://localhost:5000

### Dashboard Features

1. **Overview**: Statistics and charts
2. **Scans**: List of all scans
3. **Vulnerabilities**: Filter by severity
4. **Reports**: Generate and download reports

## 🔄 Integration Examples

### Running a Complete Security Assessment

```bash
#!/bin/bash

TARGET="localhost"
OUTPUT_DIR="results/$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR

# 1. Port Scan
echo "Running port scan..."
python port_scanner.py -t $TARGET -o $OUTPUT_DIR/port_scan.json

# 2. Vulnerability Scan
echo "Running vulnerability scan..."
python vuln_scanner.py -t http://$TARGET:8080 -o $OUTPUT_DIR/vuln_scan.json

# 3. SQL Injection Test
echo "Running SQL injection tests..."
python sql_injection_tester.py -u "http://$TARGET:8080/api/users?id=1" -o $OUTPUT_DIR/sqli_test.json

# 4. Generate Report
echo "Generating report..."
python report_generator.py -i $OUTPUT_DIR/vuln_scan.json -o $OUTPUT_DIR/report --format html

echo "Assessment complete! Results in $OUTPUT_DIR"
```

### API Integration

```python
import requests

# Submit scan results to dashboard
def submit_scan(scan_data):
    url = "http://localhost:5000/add_scan"
    response = requests.post(url, json=scan_data)
    return response.json()

# Get vulnerabilities
def get_vulnerabilities(severity=None):
    url = "http://localhost:5000/api/vulnerabilities"
    if severity:
        url += f"?severity={severity}"
    response = requests.get(url)
    return response.json()
```

## ⚠️ Best Practices

1. **Always get authorization** before scanning systems
2. **Use in isolated environments** for testing
3. **Don't run in production** without proper safeguards
4. **Review results carefully** before taking action
5. **Keep tools updated** for accuracy

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Nmap Documentation](https://nmap.org/book/man.html)
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)
