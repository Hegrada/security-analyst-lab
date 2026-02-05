# PCAP Investigation Tool

A professional-grade Python tool for analyzing network traffic captured in PCAP files. Designed for security analysts to investigate potential attacks, anomalies, and extract Indicators of Compromise (IoCs).

## Features

- **Multi-Protocol Analysis**: Supports TCP, UDP, ICMP, HTTP, DNS, and more
- **Automatic Anomaly Detection**: Identifies port scanning, SYN floods, data exfiltration
- **IoC Extraction**: Automatically extracts IPs, domains, URLs, and hashes
- **Professional Reports**: Generates Markdown investigation reports
- **Integration Ready**: Export IoCs in JSON format for SIEM integration
- **High Performance**: Handles large PCAP files efficiently

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

```bash
# Navigate to the tool directory
cd log-analyzer-parser/PCAPInvestigation

# Install dependencies
pip install -r requirements.txt

# Verify installation
python pcap_analyzer.py --help
```

## Quick Start

### Basic Analysis

```bash
# Analyze a PCAP file and generate a report
python pcap_analyzer.py capture.pcap -o investigation_report

# Analyze with verbose output
python pcap_analyzer.py capture.pcap -v -o full_analysis

# Export only IoCs in JSON format
python pcap_analyzer.py capture.pcap --ioc-only -o ioc_export
```

### Advanced Usage

```bash
# Generate both Markdown and JSON outputs
python pcap_analyzer.py capture.pcap --format both -o complete_report

# Specify custom output directory
python pcap_analyzer.py capture.pcap --output-dir ./investigation_results -o report
```

## Command Line Options

```bash
positional arguments:
  input                 Input PCAP file

options:
  -o OUTPUT, --output OUTPUT
                        Output filename base (default: investigation_report)
  --output-dir OUTPUT_DIR
                        Output directory (default: ./reports)
  --format {markdown,json,both}
                        Output format (default: markdown)
  --ioc-only           Only export IoCs
  -v, --verbose        Increase verbosity
  -q, --quiet         Suppress output
```

## Output Files

### Markdown Report

The tool generates comprehensive Markdown reports containing:

1. **Executive Summary** - High-level overview of findings
2. **Attack Timeline** - Chronological sequence of detected events
3. **Network Statistics** - Protocol distribution, top talkers
4. **IoC Summary** - Extracted Indicators of Compromise
5. **HTTP/DNS Analysis** - Web and DNS traffic details
6. **Detailed Findings** - In-depth analysis of each alert
7. **Recommendations** - Actionable security recommendations

### JSON IoC Export

Structured IoC data for SIEM integration:

```json
{
  "exported_at": "2024-01-15T14:30:00Z",
  "ioc_count": 15,
  "iocs": [
    {
      "type": "ip",
      "value": "203.0.113.42",
      "context": "Source of suspicious connections",
      "confidence": 85
    },
    {
      "type": "domain",
      "value": "malicious-domain.xyz",
      "context": "DNS query detected",
      "confidence": 70
    }
  ]
}
```

## Detected Anomalies

The analyzer automatically detects:

| Category | Description | Severity |
|----------|-------------|----------|
| Port Scanning | Multiple connection attempts to different ports | High |
| SYN Flood | Excessive SYN packets without ACK responses | Critical |
| Brute Force | Repeated failed authentication attempts | High |
| Data Exfiltration | Sensitive data in outbound traffic | Critical |
| DNS Tunneling | Unusually long DNS queries | Medium |
| C2 Communication | Suspicious beaconing patterns | Critical |

## IoC Types Extracted

- **IP Addresses**: Malicious or suspicious source/destination IPs
- **Domains**: Suspicious DNS queries and responses
- **URLs**: Malicious or suspicious HTTP URIs
- **Email Addresses**: Potential phishing indicators
- **Hashes**: File hashes from HTTP transfers

## Integration with Security Tools

### Import IoCs to Firewall

```bash
# Extract IPs and create firewall rules
python pcap_analyzer.py capture.pcap --ioc-only -o iocs
jq -r '.iocs[] | select(.type=="ip") | .value' iocs.json >> blocklist.txt
```

### SIEM Integration

```bash
# Generate JSON for Splunk/ELK
python pcap_analyzer.py capture.pcap --format json -o pcap_iocs
# Import pcap_iocs.json into your SIEM
```

## Sample PCAP Files

For testing, use these publicly available datasets:

1. **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
2. **Stratosphere IPS Datasets**: https://www.stratosphereips.org/datasets-overview
3. **CTU-13 Dataset**: https://www.stratosphereips.org/datasets/ctu-13
4. **PCAP-ATTACK**: https://github.com/OTRF/PCAP-ATTACK

## Report Structure

```
investigation_report/
├── investigation_report.md          # Full Markdown report
├── investigation_report_iocs.json   # IoC data for integration
└── README.md                         # This file
```

## Best Practices

### 1. Pre-Analysis Preparation
- Verify PCAP file integrity before analysis
- Note the capture time and duration
- Identify the capture location (edge, internal, host-based)

### 2. During Analysis
- Cross-reference IoCs with threat intelligence feeds
- Look for patterns across multiple alerts
- Document any unexpected findings

### 3. Post-Analysis
- Prioritize findings by severity
- Include contextual information in reports
- Follow up on high-confidence IoCs

## Troubleshooting

### No Packets Detected
- Verify PCAP file format (should be libpcap/tcpdump compatible)
- Check file permissions
- Try with a smaller test PCAP

### Scapy Import Error
```bash
# Install scapy
pip install scapy
```

### Memory Issues with Large Files
```bash
# Process in chunks (feature coming soon)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add detection rules or analysis modules
4. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues and feature requests:
- Create a GitHub issue
- Contact the Security Operations Team

## Acknowledgments

- Scapy project (https://scapy.net/)
- Malware Traffic Analysis website
- Security researcher community

---

**Note**: Always verify findings from multiple sources before taking action. This tool is an aid to human analysis, not a replacement.
