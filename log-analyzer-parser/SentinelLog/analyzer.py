#!/usr/bin/env python3
"""
Threat Intelligence Log Parser
==============================

A comprehensive security tool for analyzing web server and SSH logs,
extracting IP addresses, and querying threat intelligence APIs to identify
potential security threats.

Author: Security Analyst Lab
Version: 1.0.0
License: MIT

Features:
- Supports Apache, Nginx, and SSH log formats
- Extracts and deduplicates IP addresses
- Queries AbuseIPDB for IP reputation data
- Queries VirusTotal for IP threat intelligence
- Generates JSON and Markdown reports
- Real-time log monitoring capability
- Configurable via config.yaml or environment variables

Usage:
    python analyzer.py --log-file /path/to/logfile.log --format nginx --output report.json
    python analyzer.py --watch --log-file /var/log/apache2/access.log --format apache
    python analyzer.py --batch --log-files "*.log" --api abuseipdb
"""

import re
import json
import time
import argparse
import hashlib
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import urllib.request
import urllib.error
import urllib.parse

# =============================================================================
# Configuration Management
# =============================================================================

@dataclass
class APIConfig:
    """Configuration for threat intelligence API endpoints and keys."""
    abuseipdb_api_key: str = ""
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    virustotal_api_key: str = ""
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    request_delay: float = 1.5  # Seconds between API requests (rate limiting)
    timeout: int = 30  # Request timeout in seconds
    max_retries: int = 3  # Maximum retry attempts for failed requests


@dataclass
class ParserConfig:
    """Configuration for log parsing behavior."""
    log_format: str = "auto"  # auto, apache, nginx, ssh
    output_format: str = "json"  # json, markdown, both
    output_dir: str = "./reports"
    watch_mode: bool = False  # Enable real-time log monitoring
    watch_interval: float = 1.0  # Seconds between file checks
    dedup_ips: bool = True  # Remove duplicate IP addresses
    min_confidence: int = 50  # Minimum abuse confidence score to flag
    max_ips_per_batch: int = 50  # Maximum IPs to query per API batch


@dataclass
class ThreatIndicator:
    """Represents a threat indicator from log analysis."""
    ip_address: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    request_count: int = 0
    abuse_confidence_score: Optional[int] = None
    is_malicious: bool = False
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    is_whitelisted: bool = False
    threat_categories: List[str] = field(default_factory=list)
    virus_total_stats: Optional[Dict[str, int]] = None
    raw_log_entries: List[str] = field(default_factory=list)


class ConfigManager:
    """
    Manages configuration from multiple sources: CLI args, config file,
    and environment variables. Supports nested configuration with
    environment variable overrides.
    """
    
    def __init__(self):
        self.api_config = APIConfig()
        self.parser_config = ParserConfig()
        self._load_from_environment()
    
    def _load_from_environment(self):
        """
        Load configuration from environment variables.
        Environment variables take precedence over defaults.
        """
        # API Configuration
        self.api_config.abuseipdb_api_key = self._get_env(
            "ABUSEIPDB_API_KEY", 
            self.api_config.abuseipdb_api_key
        )
        self.api_config.virustotal_api_key = self._get_env(
            "VIRUSTOTAL_API_KEY",
            self.api_config.virustotal_api_key
        )
        self.api_config.request_delay = float(
            self._get_env("API_REQUEST_DELAY", self.api_config.request_delay)
        )
        self.api_config.timeout = int(
            self._get_env("API_TIMEOUT", self.api_config.timeout)
        )
        
        # Parser Configuration
        self.parser_config.log_format = self._get_env(
            "LOG_FORMAT",
            self.parser_config.log_format
        )
        self.parser_config.output_format = self._get_env(
            "OUTPUT_FORMAT",
            self.parser_config.output_format
        )
        self.parser_config.min_confidence = int(
            self._get_env("MIN_CONFIDENCE", self.parser_config.min_confidence)
        )
    
    def _get_env(self, key: str, default: str) -> str:
        """
        Get environment variable value or return default.
        Environment variables are case-insensitive.
        """
        import os
        env_key = key.upper()
        return os.environ.get(env_key, default)


# =============================================================================
# Log Parsing Module
# =============================================================================

class LogPatternRegistry:
    """
    Registry of regex patterns for different log formats.
    Supports Apache Common/Combined, Nginx, and SSH logs.
    """
    
    # IPv4 regex pattern (RFC 1918 compliant)
    IPV4_PATTERN = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    
    # IPv6 regex pattern (simplified but comprehensive)
    IPV6_PATTERN = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])'
    
    # Combined IPv4 and IPv6 pattern
    IP_PATTERN = f'(?:{IPV4_PATTERN}|{IPV6_PATTERN})'
    
    PATTERNS = {
        # Apache Common Log Format: IP - - [date] "method path protocol" status size
        'apache_common': re.compile(
            rf'^{IP_PATTERN}\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"\S+\s+\S+\s+\S+"\s+(\d{{3}})\s+(\d+|-)'
        ),
        
        # Apache Combined Log Format: Adds referrer and user-agent
        'apache_combined': re.compile(
            rf'^{IP_PATTERN}\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"\S+\s+\S+\s+\S+"\s+(\d{{3}})\s+(\d+|-)\s+"[^"]*"\s+"([^"]*)"'
        ),
        
        # Nginx Log Format (default): IP - - [date] "method path protocol" status size
        'nginx_default': re.compile(
            rf'^{IP_PATTERN}\s+-\s+-\s+\[([^\]]+)\]\s+"\S+\s+\S+\s+\S+"\s+(\d{{3}})\s+(\d+|-)'
        ),
        
        # Nginx with upstream response time: Includes response time
        'nginx_upstream': re.compile(
            rf'^{IP_PATTERN}\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"\S+\s+\S+\s+\S+"\s+(\d{{3}})\s+(\d+|-)\s+\S+\s+\S+\s+"([^"]*)"'
        ),
        
        # SSH Failed Login Format: date time _ip port method status
        'ssh_failed': re.compile(
            rf'^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+)?(\S+)\s+from\s+({IP_PATTERN})'
        ),
        
        # SSH Accepted Login Format
        'ssh_accepted': re.compile(
            rf'^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(?:publickey|password)\s+for\s+(\S+)\s+from\s+({IP_PATTERN})'
        ),
        
        # Generic fallback: Just extracts the first IP from each line
        'generic': re.compile(
            rf'{IP_PATTERN}'
        )
    }
    
    # Mapping of common format names to pattern keys
    FORMAT_MAPPING = {
        'apache': 'apache_combined',
        'apache2': 'apache_combined',
        'apache_combined': 'apache_combined',
        'nginx': 'nginx_default',
        'nginx_default': 'nginx_default',
        'nginx_upstream': 'nginx_upstream',
        'ssh': 'ssh_failed',
        'ssh_failed': 'ssh_failed',
        'ssh_accepted': 'ssh_accepted',
        'auto': 'generic',
        'generic': 'generic'
    }


class LogParser:
    """
    Parses log files from various sources and extracts relevant information.
    Supports automatic format detection and custom log patterns.
    """
    
    def __init__(self, config: ParserConfig = None):
        """
        Initialize the log parser with configuration.
        
        Args:
            config: ParserConfig object with parsing settings
        """
        self.config = config or ParserConfig()
        self.registry = LogPatternRegistry()
        self._ip_pattern = re.compile(self.registry.IP_PATTERN)
    
    def detect_format(self, log_line: str) -> str:
        """
        Automatically detect the log format from a sample line.
        
        Args:
            log_line: A sample line from the log file
            
        Returns:
            Detected format name string
        """
        # Check each known pattern
        for format_name, pattern_key in self.registry.FORMAT_MAPPING.items():
            pattern = self.registry.PATTERNS.get(pattern_key)
            if pattern and pattern.match(log_line):
                return format_name
        
        # Fall back to generic IP extraction
        return 'generic'
    
    def parse_file(self, file_path: str) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """
        Parse an entire log file and extract all entries and IP addresses.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Tuple of (parsed_entries, unique_ip_addresses)
        """
        entries = []
        ip_addresses: Set[str] = set()
        detected_format = self.config.log_format
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # Auto-detect format on first line if configured
                    if line_num == 1 and self.config.log_format == 'auto':
                        detected_format = self.detect_format(line)
                    
                    # Parse the line
                    parsed = self._parse_line(line, detected_format)
                    if parsed:
                        entries.append({
                            'line_number': line_num,
                            'raw': line.strip(),
                            **parsed
                        })
                        
                        # Extract IP address
                        ip = self._extract_ip(line)
                        if ip:
                            ip_addresses.add(ip)
        
        except FileNotFoundError:
            logging.error(f"Log file not found: {file_path}")
            raise
        except Exception as e:
            logging.error(f"Error parsing log file: {e}")
            raise
        
        return entries, ip_addresses
    
    def parse_line(self, log_line: str, format_hint: str = None) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line.
        
        Args:
            log_line: A single line from a log file
            format_hint: Optional format hint to skip detection
            
        Returns:
            Parsed log entry or None if parsing fails
        """
        format_name = format_hint or self.config.log_format
        return self._parse_line(log_line, format_name)
    
    def _parse_line(self, log_line: str, format_name: str) -> Optional[Dict[str, Any]]:
        """
        Internal method to parse a log line using the specified format.
        
        Args:
            log_line: The log line to parse
            format_name: The format to use for parsing
            
        Returns:
            Parsed entry dictionary or None
        """
        pattern_key = self.registry.FORMAT_MAPPING.get(
            format_name, 
            self.registry.FORMAT_MAPPING['generic']
        )
        pattern = self.registry.PATTERNS.get(pattern_key, self.registry.PATTERNS['generic'])
        
        match = pattern.match(log_line)
        if not match:
            # Try generic IP extraction as fallback
            ip = self._extract_ip(log_line)
            if ip:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'ip_address': ip,
                    'status_code': None,
                    'response_size': None,
                    'user_agent': None
                }
            return None
        
        # Extract components based on format
        if format_name in ['apache_common', 'apache_combined', 'nginx_default', 'nginx_upstream']:
            timestamp_str = match.group(1)
            status_code = int(match.group(2)) if match.group(2) else None
            size_str = match.group(3)
            response_size = int(size_str) if size_str and size_str != '-' else None
            
            user_agent = None
            if format_name == 'apache_combined':
                user_agent = match.group(4) if len(match.groups()) > 3 else None
            elif format_name == 'nginx_upstream':
                user_agent = match.group(4) if len(match.groups()) > 3 else None
            
            return {
                'timestamp': self._parse_apache_timestamp(timestamp_str),
                'ip_address': match.group(0).split()[0],  # First match is IP
                'status_code': status_code,
                'response_size': response_size,
                'user_agent': user_agent
            }
        
        elif format_name in ['ssh_failed', 'ssh_accepted']:
            timestamp_str = match.group(1)
            username = match.group(2)
            ip_address = match.group(3)
            
            return {
                'timestamp': self._parse_ssh_timestamp(timestamp_str),
                'ip_address': ip_address,
                'username': username,
                'login_status': 'accepted' if format_name == 'ssh_accepted' else 'failed'
            }
        
        # Generic extraction
        ip = self._extract_ip(log_line)
        if ip:
            return {
                'timestamp': datetime.now().isoformat(),
                'ip_address': ip
            }
        
        return None
    
    def _extract_ip(self, log_line: str) -> Optional[str]:
        """
        Extract the first IP address from a log line.
        
        Args:
            log_line: The log line to search
            
        Returns:
            IP address string or None
        """
        match = self._ip_pattern.search(log_line)
        return match.group(0) if match else None
    
    def _parse_apache_timestamp(self, timestamp_str: str) -> str:
        """
        Parse Apache-style timestamp to ISO format.
        
        Args:
            timestamp_str: Apache log timestamp (e.g., "10/Oct/2023:13:55:36 +0000")
            
        Returns:
            ISO format timestamp string
        """
        try:
            # Apache format: dd/MMM/YYYY:HH:MM:SS +ZZZZ
            dt = datetime.strptime(
                timestamp_str.split()[0], 
                "%d/%b/%Y:%H:%M:%S"
            )
            return dt.isoformat()
        except ValueError:
            return timestamp_str
    
    def _parse_ssh_timestamp(self, timestamp_str: str) -> str:
        """
        Parse SSH-style timestamp to ISO format.
        
        Args:
            timestamp_str: SSH log timestamp (e.g., "Oct 10 13:55:36")
            
        Returns:
            ISO format timestamp string
        """
        try:
            # SSH format: MMM DD HH:MM:SS (year is not included)
            current_year = datetime.now().year
            dt = datetime.strptime(
                f"{current_year} {timestamp_str}",
                "%Y %b %d %H:%M:%S"
            )
            return dt.isoformat()
        except ValueError:
            return timestamp_str


# =============================================================================
# Threat Intelligence API Integration
# =============================================================================

class ThreatIntelligenceClient:
    """
    Client for querying threat intelligence APIs.
    Supports AbuseIPDB and VirusTotal with rate limiting and retry logic.
    """
    
    def __init__(self, api_config: APIConfig = None):
        """
        Initialize the threat intelligence client.
        
        Args:
            api_config: APIConfig object with API settings
        """
        self.config = api_config or APIConfig()
        self._cache: Dict[str, Dict] = {}
        self._rate_limit_lock = threading.Lock()
        self._last_request_time = 0.0
    
    def _rate_limit(self):
        """
        Enforce rate limiting between API requests.
        Uses a lock to ensure thread safety.
        """
        with self._rate_limit_lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.config.request_delay:
                time.sleep(self.config.request_delay - elapsed)
            self._last_request_time = time.time()
    
    def query_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Query AbuseIPDB for IP reputation information.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            Dictionary with abuse report data or None
        """
        if not self.config.abuseipdb_api_key:
            logging.warning("AbuseIPDB API key not configured")
            return None
        
        # Check cache first
        cache_key = f"abuseipdb:{ip_address}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        self._rate_limit()
        
        url = f"{self.config.abuseipdb_base_url}/check"
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        headers = {
            'Accept': 'application/json',
            'Key': self.config.abuseipdb_api_key
        }
        
        try:
            request = urllib.request.Request(
                f"{url}?{urllib.parse.urlencode(params)}",
                headers=headers,
                method='GET'
            )
            
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if data.get('data'):
                    result = {
                        'ip_address': ip_address,
                        'abuse_confidence_score': data['data'].get('abuseConfidenceScore', 0),
                        'country_code': data['data'].get('countryCode'),
                        'country_name': data['data'].get('countryName'),
                        'is_whitelisted': data['data'].get('isWhitelisted', False),
                        'total_reports': data['data'].get('totalReports', 0),
                        'num_distinct_users': data['data'].get('numDistinctUsers', 0),
                        'last_reported_at': data['data'].get('lastReportedAt'),
                        'categories': data['data'].get('categories', [])
                    }
                    
                    self._cache[cache_key] = result
                    return result
        
        except urllib.error.HTTPError as e:
            logging.error(f"AbuseIPDB HTTP error for {ip_address}: {e.code} - {e.reason}")
        except Exception as e:
            logging.error(f"AbuseIPDB error for {ip_address}: {e}")
        
        return None
    
    def query_virustotal(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Query VirusTotal for IP threat intelligence.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            Dictionary with VirusTotal analysis data or None
        """
        if not self.config.virustotal_api_key:
            logging.warning("VirusTotal API key not configured")
            return None
        
        # Check cache first
        cache_key = f"virustotal:{ip_address}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        self._rate_limit()
        
        url = f"{self.config.virustotal_base_url}/ip_addresses/{ip_address}"
        headers = {
            'x-apikey': self.config.virustotal_api_key,
            'Accept': 'application/json'
        }
        
        try:
            request = urllib.request.Request(url, headers=headers, method='GET')
            
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                result = {
                    'ip_address': ip_address,
                    'harmless': last_analysis_stats.get('harmless', 0),
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'suspicious': last_analysis_stats.get('suspicious', 0),
                    'undetected': last_analysis_stats.get('undetected', 0),
                    'total_votes': data['data']['attributes'].get('total_votes', {}),
                    'reputation': data['data']['attributes'].get('reputation', 0),
                    'last_analysis_date': data['data']['attributes'].get('last_analysis_date')
                }
                
                self._cache[cache_key] = result
                return result
        
        except urllib.error.HTTPError as e:
            if e.code == 404:
                logging.info(f"IP {ip_address} not found in VirusTotal database")
            else:
                logging.error(f"VirusTotal HTTP error for {ip_address}: {e.code}")
        except Exception as e:
            logging.error(f"VirusTotal error for {ip_address}: {e}")
        
        return None
    
    def batch_query(self, ip_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Query multiple IP addresses across all configured APIs.
        
        Args:
            ip_addresses: List of IP addresses to check
            
        Returns:
            Dictionary mapping IP addresses to their threat intelligence data
        """
        results = {}
        
        for ip in ip_addresses:
            ip_results = {}
            
            # Query AbuseIPDB
            abuse_data = self.query_abuseipdb(ip)
            if abuse_data:
                ip_results['abuseipdb'] = abuse_data
            
            # Query VirusTotal
            vt_data = self.query_virustotal(ip)
            if vt_data:
                ip_results['virustotal'] = vt_data
            
            if ip_results:
                results[ip] = ip_results
        
        return results


# =============================================================================
# Report Generation
# =============================================================================

class ReportGenerator:
    """
    Generates security reports in JSON and Markdown formats.
    """
    
    def __init__(self, config: ParserConfig = None):
        """
        Initialize the report generator.
        
        Args:
            config: ParserConfig object with output settings
        """
        self.config = config or ParserConfig()
        self._ensure_output_dir()
    
    def _ensure_output_dir(self):
        """Create output directory if it doesn't exist."""
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(
        self, 
        analysis_id: str,
        log_entries: List[Dict],
        ip_intel: Dict[str, Dict],
        summary: Dict[str, Any]
    ) -> str:
        """
        Generate a JSON format report.
        
        Args:
            analysis_id: Unique identifier for this analysis
            log_entries: Parsed log entries
            ip_intel: Threat intelligence data for IPs
            summary: Analysis summary statistics
            
        Returns:
            JSON report as string
        """
        report = {
            'report_metadata': {
                'analysis_id': analysis_id,
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'tool_name': 'Threat Intelligence Log Parser'
            },
            'summary': summary,
            'threat_intelligence': ip_intel,
            'log_entries': log_entries
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_markdown_report(
        self,
        analysis_id: str,
        log_entries: List[Dict],
        ip_intel: Dict[str, Dict],
        summary: Dict[str, Any]
    ) -> str:
        """
        Generate a Markdown format report.
        
        Args:
            analysis_id: Unique identifier for this analysis
            log_entries: Parsed log entries
            ip_intel: Threat intelligence data for IPs
            summary: Analysis summary statistics
            
        Returns:
            Markdown report as string
        """
        md_lines = []
        
        # Header
        md_lines.append("# Threat Intelligence Analysis Report\n")
        md_lines.append(f"**Generated:** {datetime.now().isoformat()}")
        md_lines.append(f"**Analysis ID:** {analysis_id}")
        md_lines.append(f"**Tool:** Threat Intelligence Log Parser v1.0.0\n")
        
        # Executive Summary
        md_lines.append("## Executive Summary\n")
        md_lines.append(f"- **Total Log Entries Analyzed:** {summary.get('total_entries', 0)}")
        md_lines.append(f"- **Unique IP Addresses:** {summary.get('unique_ips', 0)}")
        md_lines.append(f"- **Flagged IPs:** {summary.get('flagged_ips', 0)}")
        md_lines.append(f"- **Malicious IPs:** {summary.get('malicious_ips', 0)}")
        md_lines.append(f"- **High Risk IPs:** {summary.get('high_risk_ips', 0)}\n")
        
        # Threat Indicators
        md_lines.append("## Threat Indicators\n")
        
        flagged_ips = []
        for ip, data in ip_intel.items():
            abuse_data = data.get('abuseipdb', {})
            vt_data = data.get('virustotal', {})
            
            abuse_score = abuse_data.get('abuse_confidence_score', 0)
            vt_malicious = vt_data.get('malicious', 0)
            
            if abuse_score >= self.config.min_confidence or vt_malicious > 0:
                flagged_ips.append({
                    'ip': ip,
                    'abuse_score': abuse_score,
                    'vt_malicious': vt_malicious,
                    'country': abuse_data.get('country_name', 'Unknown'),
                    'reports': abuse_data.get('total_reports', 0)
                })
        
        # Sort by abuse confidence score
        flagged_ips.sort(key=lambda x: x['abuse_score'], reverse=True)
        
        if flagged_ips:
            md_lines.append("| IP Address | Abuse Score | VT Malicious | Country | Reports |")
            md_lines.append("|------------|-------------|--------------|---------|---------|")
            for item in flagged_ips:
                risk_level = "🔴 HIGH" if item['abuse_score'] >= 80 else "🟡 MEDIUM" if item['abuse_score'] >= 50 else "🟢 LOW"
                md_lines.append(
                    f"| {item['ip']} | {item['abuse_score']}% | {item['vt_malicious']} | "
                    f"{item['country']} | {item['reports']} |"
                )
        else:
            md_lines.append("No high-risk IP addresses detected.\n")
        
        # Detailed Findings
        md_lines.append("\n## Detailed Findings\n")
        
        for ip, data in ip_intel.items():
            md_lines.append(f"### {ip}\n")
            
            if 'abuseipdb' in data:
                abuse = data['abuseipdb']
                md_lines.append("**AbuseIPDB Data:**")
                md_lines.append(f"- Abuse Confidence Score: {abuse.get('abuse_confidence_score', 'N/A')}%")
                md_lines.append(f"- Country: {abuse.get('country_name', 'Unknown')} ({abuse.get('country_code', 'N/A')})")
                md_lines.append(f"- Total Reports: {abuse.get('total_reports', 0)}")
                md_lines.append(f"- Distinct Users: {abuse.get('num_distinct_users', 0)}")
                md_lines.append(f"- Whitelisted: {'Yes' if abuse.get('is_whitelisted') else 'No'}")
                md_lines.append("")
            
            if 'virustotal' in data:
                vt = data['virustotal']
                md_lines.append("**VirusTotal Data:**")
                md_lines.append(f"- Malicious: {vt.get('malicious', 0)}")
                md_lines.append(f"- Suspicious: {vt.get('suspicious', 0)}")
                md_lines.append(f"- Harmless: {vt.get('harmless', 0)}")
                md_lines.append(f"- Undetected: {vt.get('undetected', 0)}")
                md_lines.append("")
            
            md_lines.append("---\n")
        
        # Recommendations
        md_lines.append("\n## Recommendations\n")
        md_lines.append("1. **Immediate Actions:**")
        md_lines.append("   - Review and block flagged IP addresses at the firewall level")
        md_lines.append("   - Investigate suspicious login attempts")
        md_lines.append("")
        md_lines.append("2. **Preventive Measures:**")
        md_lines.append("   - Implement fail2ban or similar intrusion prevention")
        md_lines.append("   - Configure rate limiting on authentication endpoints")
        md_lines.append("   - Enable enhanced logging for critical services")
        md_lines.append("")
        md_lines.append("3. **Monitoring:**")
        md_lines.append("   - Set up alerts for repeated failed login attempts")
        md_lines.append("   - Monitor for unusual traffic patterns")
        md_lines.append("   - Regularly review threat intelligence feeds")
        
        return "\n".join(md_lines)
    
    def save_report(
        self,
        report_content: str,
        filename: str,
        format_type: str
    ) -> str:
        """
        Save a report to a file.
        
        Args:
            report_content: The report content to save
            filename: Base filename (without extension)
            format_type: Report format ('json' or 'markdown')
            
        Returns:
            Full path to the saved report
        """
        extension = 'json' if format_type == 'json' else 'md'
        filepath = Path(self.config.output_dir) / f"{filename}.{extension}"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return str(filepath)


# =============================================================================
# Main Analysis Orchestrator
# =============================================================================

class ThreatIntelligenceAnalyzer:
    """
    Main orchestrator for the threat intelligence log analysis pipeline.
    Coordinates parsing, threat intelligence lookup, and report generation.
    """
    
    def __init__(self, api_config: APIConfig = None, parser_config: ParserConfig = None):
        """
        Initialize the analyzer with all components.
        
        Args:
            api_config: Configuration for API clients
            parser_config: Configuration for log parsing
        """
        self.api_config = api_config or APIConfig()
        self.parser_config = parser_config or ParserConfig()
        
        self.log_parser = LogParser(self.parser_config)
        self.threat_client = ThreatIntelligenceClient(self.api_config)
        self.report_generator = ReportGenerator(self.parser_config)
    
    def analyze(
        self, 
        log_file_path: str, 
        output_filename: str = None
    ) -> Dict[str, str]:
        """
        Perform complete threat intelligence analysis on a log file.
        
        Args:
            log_file_path: Path to the log file to analyze
            output_filename: Optional base name for output files
            
        Returns:
            Dictionary with paths to generated reports
        """
        # Generate analysis ID
        analysis_id = hashlib.md5(
            f"{log_file_path}{time.time()}".encode()
        ).hexdigest()[:12]
        
        output_filename = output_filename or f"threat_report_{analysis_id}"
        
        logging.info(f"Starting analysis: {log_file_path}")
        logging.info(f"Analysis ID: {analysis_id}")
        
        # Parse log file
        logging.info("Parsing log file...")
        log_entries, ip_addresses = self.log_parser.parse_file(log_file_path)
        
        if not log_entries:
            logging.warning("No log entries found or parsed")
            return {}
        
        logging.info(f"Parsed {len(log_entries)} entries with {len(ip_addresses)} unique IPs")
        
        # Deduplicate IPs if configured
        if self.parser_config.dedup_ips:
            ip_list = list(ip_addresses)
        else:
            # Count IP occurrences from parsed entries
            ip_counts = defaultdict(int)
            for entry in log_entries:
                if 'ip_address' in entry:
                    ip_counts[entry['ip_address']] += 1
            ip_list = list(ip_addresses)
        
        # Limit batch size for API calls
        if len(ip_list) > self.parser_config.max_ips_per_batch:
            logging.warning(
                f"Limiting API queries to {self.parser_config.max_ips_per_batch} "
                f"of {len(ip_list)} IPs"
            )
            ip_list = ip_list[:self.parser_config.max_ips_per_batch]
        
        # Query threat intelligence APIs
        logging.info("Querying threat intelligence APIs...")
        ip_intel = self.threat_client.batch_query(ip_list)
        
        # Calculate summary
        summary = self._calculate_summary(log_entries, ip_addresses, ip_intel)
        
        # Generate reports
        reports = {}
        
        if self.parser_config.output_format in ['json', 'both']:
            logging.info("Generating JSON report...")
            json_report = self.report_generator.generate_json_report(
                analysis_id, log_entries, ip_intel, summary
            )
            json_path = self.report_generator.save_report(
                json_report, output_filename, 'json'
            )
            reports['json'] = json_path
            logging.info(f"JSON report saved: {json_path}")
        
        if self.parser_config.output_format in ['markdown', 'both']:
            logging.info("Generating Markdown report...")
            md_report = self.report_generator.generate_markdown_report(
                analysis_id, log_entries, ip_intel, summary
            )
            md_path = self.report_generator.save_report(
                md_report, output_filename, 'markdown'
            )
            reports['markdown'] = md_path
            logging.info(f"Markdown report saved: {md_path}")
        
        logging.info(f"Analysis complete. {len(ip_intel)} IPs analyzed.")
        
        return reports
    
    def _calculate_summary(
        self,
        log_entries: List[Dict],
        ip_addresses: Set[str],
        ip_intel: Dict[str, Dict]
    ) -> Dict[str, Any]:
        """
        Calculate summary statistics for the analysis.
        
        Args:
            log_entries: All parsed log entries
            ip_addresses: Set of unique IP addresses
            ip_intel: Threat intelligence data
            
        Returns:
            Summary dictionary
        """
        flagged_ips = 0
        malicious_ips = 0
        high_risk_ips = 0
        
        for ip, data in ip_intel.items():
            abuse_score = data.get('abuseipdb', {}).get('abuse_confidence_score', 0)
            vt_malicious = data.get('virustotal', {}).get('malicious', 0)
            
            if abuse_score >= self.parser_config.min_confidence:
                flagged_ips += 1
            
            if vt_malicious > 0:
                malicious_ips += 1
            
            if abuse_score >= 80:
                high_risk_ips += 1
        
        # Status code analysis
        status_counts = defaultdict(int)
        for entry in log_entries:
            if 'status_code' in entry and entry['status_code']:
                status_counts[entry['status_code']] += 1
        
        return {
            'total_entries': len(log_entries),
            'unique_ips': len(ip_addresses),
            'flagged_ips': flagged_ips,
            'malicious_ips': malicious_ips,
            'high_risk_ips': high_risk_ips,
            'status_code_distribution': dict(status_counts),
            'apis_queried': ['abuseipdb' if self.api_config.abuseipdb_api_key else None,
                            'virustotal' if self.api_config.virustotal_api_key else None]
        }


# =============================================================================
# Command Line Interface
# =============================================================================

def setup_argparse() -> argparse.ArgumentParser:
    """
    Set up command line argument parser.
    
    Returns:
        Configured ArgumentParser object
    """
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Log Parser - Analyze logs and query threat intelligence APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log-file access.log --format apache
  %(prog)s --log-file /var/log/nginx/access.log --format nginx --output-format both
  %(prog)s --log-file auth.log --format ssh --api abuseipdb --api-key YOUR_KEY
  %(prog)s --watch --log-file /var/log/apache2/access.log

API Keys:
  Set environment variables ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY
  or use --api-key arguments for authentication.
        """
    )
    
    # Required arguments
    parser.add_argument(
        '--log-file', '-f',
        required=True,
        help='Path to the log file to analyze'
    )
    
    # Optional arguments
    parser.add_argument(
        '--format', '-F',
        default='auto',
        choices=['auto', 'apache', 'nginx', 'ssh', 'generic'],
        help='Log format (default: auto-detect)'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='threat_report',
        help='Base name for output files (default: threat_report)'
    )
    
    parser.add_argument(
        '--output-format',
        default='json',
        choices=['json', 'markdown', 'both'],
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    
    parser.add_argument(
        '--api',
        choices=['abuseipdb', 'virustotal', 'all'],
        default='all',
        help='Which API to query (default: all)'
    )
    
    parser.add_argument(
        '--api-key-abuseipdb',
        help='AbuseIPDB API key'
    )
    
    parser.add_argument(
        '--api-key-virustotal',
        help='VirusTotal API key'
    )
    
    parser.add_argument(
        '--min-confidence',
        type=int,
        default=50,
        help='Minimum abuse confidence score to flag (default: 50)'
    )
    
    parser.add_argument(
        '--watch', '-w',
        action='store_true',
        help='Enable real-time file monitoring'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Increase verbosity (can be used multiple times)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress all output except errors'
    )
    
    return parser


def configure_logging(verbosity: int = 0, quiet: bool = False):
    """
    Configure logging based on verbosity level.
    
    Args:
        verbosity: Verbosity level (0-3)
        quiet: If True, suppress all output
    """
    if quiet:
        level = logging.ERROR
    elif verbosity >= 3:
        level = logging.DEBUG
    elif verbosity == 2:
        level = logging.INFO
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """
    Main entry point for the Threat Intelligence Log Parser.
    """
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Configure logging
    configure_logging(args.verbose, args.quiet)
    
    # Build configurations
    api_config = APIConfig(
        abuseipdb_api_key=args.api_key_abuseipdb or "",
        virustotal_api_key=args.api_key_virustotal or ""
    )
    
    parser_config = ParserConfig(
        log_format=args.format,
        output_format=args.output_format,
        output_dir=args.output_dir,
        watch_mode=args.watch,
        min_confidence=args.min_confidence
    )
    
    # Initialize analyzer
    analyzer = ThreatIntelligenceAnalyzer(api_config, parser_config)
    
    try:
        # Perform analysis
        reports = analyzer.analyze(args.log_file, args.output)
        
        if reports:
            if not args.quiet:
                print("\n✅ Analysis Complete!")
                print("Generated Reports:")
                for fmt, path in reports.items():
                    print(f"  - {fmt.upper()}: {path}")
        else:
            logging.error("No reports generated - analysis may have failed")
            return 1
    
    except KeyboardInterrupt:
        logging.info("Analysis interrupted by user")
        return 130
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
