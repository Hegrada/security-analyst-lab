# SentinelLog - Threat Intelligence Log Parser

A comprehensive Python security tool for analyzing web server and SSH logs, extracting IP addresses, and querying threat intelligence APIs to identify potential security threats.

## Features

- **Multi-Format Log Parsing**: Supports Apache (Common/Combined), Nginx (Default/Upstream), and SSH (Failed/Accepted) log formats
- **Automatic Format Detection**: Auto-detects log format when configured
- **Threat Intelligence Integration**: Queries AbuseIPDB and VirusTotal APIs
- **Multiple Output Formats**: Generates reports in JSON and Markdown formats
- **Real-Time Monitoring**: Watch mode for continuous log analysis
- **IP Deduplication**: Efficiently handles large log files
- **Rate Limiting**: Built-in API rate limiting to prevent throttling
- **Zero Dependencies**: Uses only Python standard library

## Quick Start

### Basic Usage

```bash
# Analyze an Apache access log
python analyzer.py --log-file access.log --format apache

# Analyze SSH authentication logs
python analyzer.py --log-file /var/log/auth.log --format ssh

# Analyze Nginx logs with threat intelligence
python analyzer.py --log-file nginx.log --format nginx \
    --api abuseipdb --api-key YOUR_ABUSEIPDB_KEY
```

### Real-Time Monitoring

```bash
# Watch a log file for new entries
python analyzer.py --watch --log-file /var/log/apache2/access.log
```

## Installation

### Prerequisites

- Python 3.8 or higher
- No external dependencies required

### Setup

1. Clone or navigate to the SentinelLog directory:
   ```bash
   cd log-analyzer-parser/SentinelLog
   ```

2. (Optional) Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. The script is ready to use - no installation required!

## Configuration

### Environment Variables

Set these variables for API authentication:

| Variable | Description |
|----------|-------------|
| `ABUSEIPDB_API_KEY` | Your AbuseIPDB API key |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API key |
| `API_REQUEST_DELAY` | Seconds between API requests (default: 1.5) |
| `API_TIMEOUT` | Request timeout in seconds (default: 30) |
| `LOG_FORMAT` | Default log format (auto, apache, nginx, ssh) |
| `OUTPUT_FORMAT` | Default output format (json, markdown, both) |
| `MIN_CONFIDENCE` | Minimum abuse score to flag (default: 50) |

### Command-Line Arguments

```bash
python analyzer.py --help

usage: analyzer.py [-h] --log-file LOG_FILE [-F FORMAT] [-o OUTPUT]
                   [--output-format {json,markdown,both}] [--output-dir OUTPUT_DIR]
                   [--api {abuseipdb,virustotal,all}]
                   [--api-key-abuseipdb API_KEY_ABUSEIPDB]
                   [--api-key-virustotal API_KEY_VIRUSTOTAL]
                   [--min-confidence MIN_CONFIDENCE] [-w] [-v | -v | -v] [-q]

Threat Intelligence Log Parser - Analyze logs and query threat intelligence APIs

required arguments:
  --log-file LOG_FILE, -f LOG_FILE
                        Path to the log file to analyze

optional arguments:
  -h, --help            show this help message and exit
  --format FORMAT, -F FORMAT
                        Log format (default: auto)
  --output OUTPUT, -o OUTPUT
                        Base name for output files (default: threat_report)
  --output-format {json,markdown,both}
                        Output format (default: json)
  --output-dir OUTPUT_DIR
                        Output directory for reports (default: ./reports)
  --api {abuseipdb,virustotal,all}
                        Which API to query (default: all)
  --api-key-abuseipdb API_KEY_ABUSEIPDB
                        AbuseIPDB API key
  --api-key-virustotal API_KEY_VIRUSTOTAL
                        VirusTotal API key
  --min-confidence MIN_CONFIDENCE
                        Minimum abuse confidence score to flag (default: 50)
  --watch, -w           Enable real-time file monitoring
  --verbose, -v         Increase verbosity (can be used multiple times)
  --quiet, -q           Suppress all output except errors
```

## Supported Log Formats

### Apache Combined Log Format

```
192.168.1.1 - - [10/Jan/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"
```

### Nginx Default Format

```
192.168.1.1 - - [10/Jan/2024:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 512 "-" "curl/7.68.0"
```

### SSH Failed Login

```
Jan 10 13:55:36 server sshd[1234]: Failed password for root from 203.0.113.42 port 22 ssh2
```

### SSH Accepted Login

```
Jan 10 13:55:36 server sshd[1234]: Accepted publickey for admin from 198.51.100.25 port 22 ssh2
```

## Output Reports

### JSON Output

```json
{
  "report_metadata": {
    "analysis_id": "a1b2c3d4e5f6",
    "generated_at": "2024-01-15T14:30:00.000Z",
    "tool_version": "1.0.0",
    "tool_name": "Threat Intelligence Log Parser"
  },
  "summary": {
    "total_entries": 1500,
    "unique_ips": 45,
    "flagged_ips": 8,
    "malicious_ips": 3,
    "high_risk_ips": 2
  },
  "threat_intelligence": {
    "185.220.101.46": {
      "abuseipdb": {
        "abuse_confidence_score": 100,
        "country_name": "Germany",
        "total_reports": 156
      }
    }
  },
  "log_entries": [...]
}
```

### Markdown Output

Includes:
- Executive Summary
- Threat Indicators Table
- Detailed Findings per IP
- Security Recommendations
- Status Code Distribution

## API Setup

### AbuseIPDB

1. Sign up at https://www.abuseipdb.com/
2. Generate an API key from your account settings
3. Use the key with `--api-key-abuseipdb` or set `ABUSEIPDB_API_KEY`

### VirusTotal

1. Sign up at https://www.virustotal.com/
2. Get your API key from https://www.virustotal.com/gui/user-apikey
3. Use the key with `--api-key-virustotal` or set `VIRUSTOTAL_API_KEY`

**Note**: VirusTotal requires a paid subscription for API access.

## Directory Structure

```
SentinelLog/
├── analyzer.py           # Main Python script
├── requirements.txt      # Dependencies (standard library only)
├── README.md            # This file
└── reports/             # Output directory for reports
    ├── example_report.json
    └── example_report.md
```

## Security Considerations

- **API Keys**: Never commit API keys to version control
- **Log Files**: Ensure log files have appropriate permissions
- **Output Security**: Reports may contain sensitive information
- **Rate Limiting**: Respect API rate limits to avoid being blocked

## Troubleshooting

### No IPs Flagged

- Ensure API keys are correctly configured
- Check API rate limits haven't been exceeded
- Verify the minimum confidence threshold (`--min-confidence`)

### Parsing Errors

- Check log format matches expected pattern
- Try `--format auto` for automatic detection
- Use `--verbose` for detailed error messages

### API Errors

- Verify API keys are valid
- Check network connectivity
- Review rate limiting settings

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues and feature requests, please contact the security team.

---

**Security Tip**: Always verify findings from multiple sources before taking action on flagged IPs.
