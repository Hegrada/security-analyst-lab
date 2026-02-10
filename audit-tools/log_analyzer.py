#!/usr/bin/env python3
"""
📊 Advanced Log Analyzer with Anomaly Detection

A SOC-grade log analyzer with ML-based anomaly detection, pattern matching,
and comprehensive security event analysis.

Author: SOC Analyst
Version: 1.0.0
License: MIT
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple
from zipfile import ZipFile

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init()


class Severity(Enum):
    """Log severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    UNKNOWN = 0


class LogType(Enum):
    """Types of log files"""
    AUTH = "authentication"
    SYSLOG = "system"
    APACHE = "apache"
    NGINX = "nginx"
    FIREWALL = "firewall"
    DNS = "dns"
    HTTP = "http"
    CUSTOM = "custom"


@dataclass
class LogEntry:
    """Parsed log entry"""
    raw: str
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str = ""
    message: str = ""
    severity: int = 0
    log_type: str = "unknown"
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "username": self.username,
            "event_type": self.event_type,
            "message": self.message,
            "severity": self.severity,
            "log_type": self.log_type,
            "extra": self.extra
        }


@dataclass
class SecurityEvent:
    """Detected security event"""
    id: str
    timestamp: datetime
    event_type: str
    severity: int
    source_ips: List[str]
    description: str
    count: int = 1
    artifacts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ips": self.source_ips,
            "description": self.description,
            "count": self.count,
            "artifacts": self.artifacts
        }


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    analysis_start: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    analysis_end: str = ""
    files_analyzed: List[str] = field(default_factory=list)
    total_entries: int = 0
    time_range: Tuple[str, str] = ("", "")
    security_events: List[SecurityEvent] = field(default_factory=list)
    anomalies: List[Dict] = field(default_factory=list)
    ip_stats: Dict[str, int] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    top_events: List[Tuple[str, int]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "analysis_start": self.analysis_start,
            "analysis_end": self.analysis_end,
            "files_analyzed": self.files_analyzed,
            "total_entries": self.total_entries,
            "time_range": self.time_range,
            "security_events": [e.to_dict() for e in self.security_events],
            "anomalies": self.anomalies,
            "ip_stats": self.ip_stats,
            "severity_distribution": self.severity_distribution,
            "top_events": self.top_events,
            "recommendations": self.recommendations
        }


# Common log patterns
LOG_PATTERNS = {
    'apache': [
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+)',
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3})'
    ],
    'nginx': [
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"',
    ],
    'ssh': [
        r'(?P<timestamp>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<message>.*)',
        r'Failed password for (?:invalid user )?(?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'Accepted (?:publickey|password) for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'Invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ],
    'syslog': [
        r'(?P<timestamp>.*?) (?P<hostname>\S+) (?P<process>\S+?): (?P<message>.*)',
    ],
    'firewall': [
        r'(?P<timestamp>.*?) SRC=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) DST=(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*?SPT=(?P<src_port>\d+) DPT=(?P<dst_port>\d+)',
    ]
}

# Security event signatures
SECURITY_SIGNATURES = {
    'brute_force': {
        'pattern': r'(Failed password|Invalid user|authentication failure)',
        'severity': 3,
        'description': 'Potential brute force attack detected'
    },
    'sql_injection': {
        'pattern': r"(union select|exec\(\)|xp_cmdshell|' OR '1'='1|benchmark\(|sleep\()",
        'severity': 4,
        'description': 'Potential SQL injection attempt detected'
    },
    'xss_attempt': {
        'pattern': r"(<script>|javascript:|onerror=|onload=|alert\(|document\.cookie)",
        'severity': 4,
        'description': 'Potential XSS attack detected'
    },
    'path_traversal': {
        'pattern': r"(\.\./|\.\.%2f|/etc/passwd|win.ini|boot.ini)",
        'severity': 4,
        'description': 'Potential path traversal attempt detected'
    },
    'port_scan': {
        'pattern': r'(Connect from|Failed from|Denied from)',
        'severity': 2,
        'description': 'Potential port scanning activity'
    },
    'malware_indicator': {
        'pattern': r'(c99shell|r57shell|php皇帝|WebShell|cmd\.exe|/bin/sh)',
        'severity': 5,
        'description': 'Malware or webshell indicator detected'
    },
    'privilege_escalation': {
        'pattern': r'(sudo:|COMMAND=/|user=root|uid=0)',
        'severity': 5,
        'description': 'Potential privilege escalation attempt'
    },
    'data_exfiltration': {
        'pattern': r'(wget |curl |nc |netcat |ftp |tftp |scp |rsync)',
        'severity': 4,
        'description': 'Potential data exfiltration activity'
    }
}


class LogAnalyzer:
    """Advanced log analyzer with ML-based anomaly detection"""
    
    def __init__(self, verbose: bool = False, anomaly_detection: bool = True):
        self.verbose = verbose
        self.anomaly_detection = anomaly_detection
        self.logger = self._setup_logging()
        self.patterns = LOG_PATTERNS
        self.signatures = SECURITY_SIGNATURES
        self.result = AnalysisResult()
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("log_analyzer")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _detect_log_type(self, sample: str) -> str:
        """Detect log type from sample"""
        sample_lower = sample.lower()
        
        if 'sshd' in sample_lower or 'Failed password' in sample_lower:
            return 'ssh'
        elif 'apache' in sample_lower or '127.0.0.1' in sample_lower:
            return 'apache'
        elif 'nginx' in sample_lower:
            return 'nginx'
        elif 'SRC=' in sample or 'DST=' in sample:
            return 'firewall'
        elif re.match(r'\w{3}\s+\d+\s+\d+:\d+:\d+', sample):
            return 'syslog'
        else:
            return 'syslog'
    
    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse various timestamp formats"""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%d/%b/%Y:%H:%M:%S %z',
            '%b %d %H:%M:%S',
            '%Y:%m:%d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S',
            '[%d/%b/%Y:%H:%M:%S %z]',
        ]
        
        # Clean up the timestamp
        ts_str = ts_str.strip()
        ts_str = ts_str.split()[0]  # Remove timezone for now
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        return None
    
    def _parse_log_entry(self, line: str, log_type: str) -> Optional[LogEntry]:
        """Parse a single log entry"""
        if not line or line.startswith('#'):
            return None
        
        try:
            # Try to match patterns based on log type
            for pattern_name, patterns in self.patterns.items():
                for pattern in patterns:
                    match = re.match(pattern, line, re.IGNORECASE)
                    if match:
                        groups = match.groupdict()
                        timestamp = self._parse_timestamp(
                            groups.get('timestamp', groups.get('date', line[:20]))
                        )
                        
                        if not timestamp:
                            timestamp = datetime.now()
                        
                        entry = LogEntry(
                            raw=line,
                            timestamp=timestamp,
                            source_ip=groups.get('ip') or groups.get('src_ip'),
                            username=groups.get('user'),
                            event_type=pattern_name,
                            message=groups.get('message', groups.get('request', line)),
                            log_type=pattern_name
                        )
                        
                        # Extract severity based on keywords
                        entry.severity = self._extract_severity(entry.message)
                        
                        return entry
            
            # Default parsing
            timestamp = self._parse_timestamp(line[:20]) or datetime.now()
            
            return LogEntry(
                raw=line,
                timestamp=timestamp,
                message=line,
                log_type=log_type,
                severity=self._extract_severity(line)
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse line: {e}")
            return None
    
    def _extract_severity(self, message: str) -> int:
        """Extract severity from log message"""
        msg_lower = message.lower()
        
        if any(kw in msg_lower for kw in ['critical', 'fatal', 'emergency']):
            return Severity.CRITICAL.value
        elif any(kw in msg_lower for kw in ['error', 'err', 'fail', 'denied', 'refused']):
            return Severity.HIGH.value
        elif any(kw in msg_lower for kw in ['warning', 'warn', 'alert']):
            return Severity.MEDIUM.value
        elif any(kw in msg_lower for kw in ['notice', 'info']):
            return Severity.LOW.value
        else:
            return Severity.INFO.value
    
    def _check_security_signatures(self, entries: List[LogEntry]) -> List[SecurityEvent]:
        """Check log entries against security signatures"""
        events = []
        ip_counter = Counter()
        user_counter = Counter()
        event_counter = Counter()
        
        for entry in entries:
            for sig_name, sig_info in self.signatures.items():
                if re.search(sig_info['pattern'], entry.message, re.IGNORECASE):
                    if entry.source_ip:
                        ip_counter[entry.source_ip] += 1
                    if entry.username:
                        user_counter[entry.username] += 1
                    
                    event = SecurityEvent(
                        id=f"EVT-{sig_name.upper()}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        timestamp=entry.timestamp,
                        event_type=sig_name,
                        severity=sig_info['severity'],
                        source_ips=[entry.source_ip] if entry.source_ip else [],
                        description=sig_info['description'],
                        message=entry.message
                    )
                    events.append(event)
                    event_counter[sig_name] += 1
        
        # Group similar events
        grouped_events = defaultdict(list)
        for event in events:
            key = f"{event.event_type}-{event.source_ips[0] if event.source_ips else 'unknown'}"
            grouped_events[key].append(event)
        
        final_events = []
        for key, event_list in grouped_events.items():
            first_event = event_list[0]
            first_event.count = len(event_list)
            first_event.source_ips = list(set(e.source_ips[0] for e in event_list if e.source_ips))
            final_events.append(first_event)
        
        return final_events
    
    def _detect_anomalies(self, entries: List[LogEntry]) -> List[Dict]:
        """Detect anomalies using machine learning"""
        if not self.anomaly_detection or len(entries) < 10:
            return []
        
        self.logger.info("Running anomaly detection...")
        
        try:
            # Prepare features
            df = pd.DataFrame([{
                'hour': entry.timestamp.hour,
                'day_of_week': entry.timestamp.weekday(),
                'severity': entry.severity,
                'has_ip': 1 if entry.source_ip else 0,
                'has_user': 1 if entry.username else 0,
                'msg_length': len(entry.message)
            } for entry in entries])
            
            # Fill any NaN values
            df = df.fillna(0)
            
            # Scale features
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(df)
            
            # Train Isolation Forest
            iso_forest = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            
            # Predict anomalies
            predictions = iso_forest.fit_predict(features_scaled)
            anomaly_indices = np.where(predictions == -1)[0]
            
            # Extract anomalous entries
            anomalies = []
            for idx in anomaly_indices:
                entry = entries[idx]
                anomalies.append({
                    'timestamp': entry.timestamp.isoformat(),
                    'source_ip': entry.source_ip,
                    'severity': entry.severity,
                    'message': entry.message[:200],
                    'reason': 'Anomalous activity pattern detected'
                })
            
            self.logger.info(f"Detected {len(anomalies)} anomalies")
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return []
    
    def _generate_recommendations(self, events: List[SecurityEvent],
                                  anomalies: List[Dict],
                                  total_entries: int = 0) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Analyze events
        event_types = Counter(e.event_type for e in events)
        
        if event_types.get('brute_force', 0) > 10:
            recommendations.append(
                "HIGH PRIORITY: Multiple brute force attempts detected. "
                "Consider implementing fail2ban or rate limiting."
            )
        
        if event_types.get('sql_injection', 0) > 0:
            recommendations.append(
                "CRITICAL: SQL injection attempts detected. "
                "Review input validation and use parameterized queries."
            )
        
        if event_types.get('xss_attempt', 0) > 0:
            recommendations.append(
                "WARNING: XSS attack attempts detected. "
                "Implement Content Security Policy (CSP) and input sanitization."
            )
        
        if event_types.get('path_traversal', 0) > 0:
            recommendations.append(
                "WARNING: Path traversal attempts detected. "
                "Review file access controls and path validation."
            )
        
        if event_types.get('malware_indicator', 0) > 0:
            recommendations.append(
                "CRITICAL: Malware indicators detected! "
                "Immediate forensic investigation required."
            )
        
        if len(anomalies) > total_entries * 0.1 and total_entries > 0:
            recommendations.append(
                "Unusual activity patterns detected. "
                "Review network traffic and user behavior."
            )
        
        if not recommendations:
            recommendations.append("No critical issues detected. Continue monitoring.")
        
        return recommendations
    
    def analyze_file(self, filepath: str) -> AnalysisResult:
        """Analyze a single log file"""
        self.logger.info(f"Analyzing file: {filepath}")
        
        entries = []
        
        # Handle compressed files
        if filepath.endswith('.zip'):
            with ZipFile(filepath, 'r') as z:
                for filename in z.namelist():
                    with z.open(filename) as f:
                        for line in f:
                            entries.extend(self._parse_log_entries(line.decode()))
        else:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    entries.extend(self._parse_log_entries(line))
        
        return self._process_entries(entries, [filepath])
    
    def analyze_directory(self, dir_path: str, recursive: bool = True) -> AnalysisResult:
        """Analyze all log files in a directory"""
        log_files = []
        
        if recursive:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    if file.endswith(('.log', '.txt', '.zip')):
                        log_files.append(os.path.join(root, file))
        else:
            for file in os.listdir(dir_path):
                filepath = os.path.join(dir_path, file)
                if os.path.isfile(filepath):
                    log_files.append(filepath)
        
        all_entries = []
        for filepath in log_files:
            entries = self._parse_log_entries_from_file(filepath)
            all_entries.extend(entries)
            self.result.files_analyzed.append(filepath)
        
        return self._process_entries(all_entries, log_files)
    
    def _parse_log_entries(self, lines: List[str]) -> List[LogEntry]:
        """Parse multiple log lines"""
        entries = []
        log_type = self._detect_log_type(lines[0] if lines else "")
        
        for line in lines:
            entry = self._parse_log_entry(line, log_type)
            if entry:
                entries.append(entry)
        
        return entries
    
    def _parse_log_entries_from_file(self, filepath: str) -> List[LogEntry]:
        """Parse all entries from a file"""
        entries = []
        
        with open(filepath, 'r', errors='ignore') as f:
            sample = f.read(1000)
            log_type = self._detect_log_type(sample)
            f.seek(0)
            
            for line in f:
                entry = self._parse_log_entry(line, log_type)
                if entry:
                    entries.append(entry)
        
        return entries
    
    def _process_entries(self, entries: List[LogEntry], files: List[str]) -> AnalysisResult:
        """Process parsed log entries"""
        self.result.files_analyzed = files
        self.result.total_entries = len(entries)
        
        if not entries:
            self.logger.warning("No entries to analyze")
            return self.result
        
        # Sort by timestamp
        entries.sort(key=lambda x: x.timestamp)
        
        # Time range
        self.result.time_range = (
            entries[0].timestamp.isoformat(),
            entries[-1].timestamp.isoformat()
        )
        
        # IP statistics
        ip_counter = Counter()
        severity_counter = Counter()
        
        for entry in entries:
            if entry.source_ip:
                ip_counter[entry.source_ip] += 1
            severity_counter[entry.severity] += 1
        
        self.result.ip_stats = dict(ip_counter.most_common(20))
        self.result.severity_distribution = {
            k.name: v for k, v in severity_counter.items()
        }
        
        # Security events
        self.result.security_events = self._check_security_signatures(entries)
        
        # Event type statistics
        event_counter = Counter(e.event_type for e in self.result.security_events)
        self.result.top_events = event_counter.most_common(10)
        
        # Anomaly detection
        self.result.anomalies = self._detect_anomalies(entries)
        
        # Recommendations
        self.result.recommendations = self._generate_recommendations(
            self.result.security_events,
            self.result.anomalies,
            len(entries)
        )
        
        self.result.analysis_end = datetime.utcnow().isoformat()
        
        return self.result
    
    def print_summary(self):
        """Print analysis summary"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}LOG ANALYSIS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Files Analyzed:{Style.RESET_ALL} {len(self.result.files_analyzed)}")
        print(f"{Fore.WHITE}Total Entries:{Style.RESET_ALL} {self.result.total_entries:,}")
        print(f"{Fore.WHITE}Time Range:{Style.RESET_ALL} {self.result.time_range[0]} to {self.result.time_range[1]}\n")
        
        # Security Events
        if self.result.security_events:
            print(f"{Fore.RED}Security Events Found: {len(self.result.security_events)}{Style.RESET_ALL}\n")
            
            severity_colors = {
                5: Fore.RED,
                4: Fore.ORANGE,
                3: Fore.YELLOW,
                2: Fore.BLUE,
                1: Fore.GREEN
            }
            
            for event in sorted(self.result.security_events, 
                               key=lambda x: -x.severity)[:10]:
                color = severity_colors.get(event.severity, Fore.WHITE)
                print(f"  {color}[{event.severity}]{Style.RESET_ALL} "
                     f"{event.event_type.upper()} ({event.count} occurrences)")
                print(f"       {event.description}")
                if event.source_ips:
                    print(f"       Source IPs: {', '.join(event.source_ips[:3])}")
        
        # Anomalies
        if self.result.anomalies:
            print(f"\n{Fore.YELLOW}Anomalies Detected: {len(self.result.anomalies)}{Style.RESET_ALL}\n")
            for anomaly in self.result.anomalies[:5]:
                print(f"  {Fore.ORANGE}*{Style.RESET_ALL} {anomaly['timestamp']}")
                print(f"    IP: {anomaly['source_ip']}")
                print(f"    {anomaly['message'][:100]}...")
        
        # Top Source IPs
        if self.result.ip_stats:
            print(f"\n{Fore.WHITE}Top Source IPs:{Style.RESET_ALL}")
            for ip, count in list(self.result.ip_stats.items())[:5]:
                print(f"  {ip}: {count:,} events")
        
        # Recommendations
        if self.result.recommendations:
            print(f"\n{Fore.CYAN}Recommendations:{Style.RESET_ALL}")
            for rec in self.result.recommendations[:5]:
                print(f"  {Fore.GREEN}*{Style.RESET_ALL} {rec}")
        
        print()
    
    def save_results(self, filename: str = "log_analysis_results.json"):
        """Save analysis results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        self.logger.info(f"Results saved to {filename}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Advanced Log Analyzer with Anomaly Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f /var/log/auth.log
  %(prog)s -d /var/log -r --anomaly-detection
  %(prog)s -f access.log --severity high -o results.json
  %(prog)s -f combined.log --security-only
        """
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file', help="Log file to analyze")
    input_group.add_argument('-d', '--directory', help="Directory containing log files")
    
    parser.add_argument('-r', '--recursive', action='store_true',
                       help="Recursively scan directories")
    parser.add_argument('--anomaly-detection', action='store_true', default=True,
                       help="Enable ML-based anomaly detection (default: True)")
    parser.add_argument('--no-anomaly', action='store_true',
                       help="Disable anomaly detection")
    parser.add_argument('-s', '--severity', choices=['critical', 'high', 'medium', 'low'],
                       help="Filter by minimum severity")
    parser.add_argument('-o', '--output', default="log_analysis_results.json",
                       help="Output JSON file")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--no-color', action='store_true',
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.no_color:
        colorama.deinit()
    
    analyzer = LogAnalyzer(
        verbose=args.verbose,
        anomaly_detection=not args.no_anomaly
    )
    
    # Analyze
    if args.file:
        result = analyzer.analyze_file(args.file)
    elif args.directory:
        result = analyzer.analyze_directory(args.directory, recursive=args.recursive)
    
    # Print summary
    analyzer.print_summary()
    
    # Save results
    analyzer.save_results(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
