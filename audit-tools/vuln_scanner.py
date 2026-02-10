#!/usr/bin/env python3
"""
🛡️ OWASP Top 10 Vulnerability Scanner

A comprehensive web application vulnerability scanner that checks for OWASP Top 10
vulnerabilities including SQL injection, XSS, CSRF, and more.

Author: SOC Analyst
Version: 1.0.0
License: MIT
"""

import argparse
import json
import logging
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import colorama
from colorama import Fore, Style
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama
colorama.init()


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    UNKNOWN = 0


class VulnerabilityCategory(Enum):
    """OWASP Top 10 vulnerability categories"""
    A1_INJECTION = "A1-Injection"
    A2_BROKEN_AUTH = "A2-BrokenAuthentication"
    A3_SENSITIVE_DATA = "A3-SensitiveDataExposure"
    A4_XML_EXTERNAL_ENTITIES = "A4-XMLExternalEntities"
    A5_BROKEN_ACCESS_CONTROL = "A5-BrokenAccessControl"
    A6_SECURITY_MISCONFIGURATION = "A6-SecurityMisconfiguration"
    A7_XSS = "A7-CrossSiteScripting"
    A8_INSECURE_DESERIALIZATION = "A8-InsecureDeserialization"
    A9_VULNERABLE_COMPONENTS = "A9-UsingComponentsWithKnownVulnerabilities"
    A10_INSUFFICIENT_LOGGING = "A10-InsufficientLogging"


@dataclass
class Vulnerability:
    """Discovered vulnerability"""
    id: str
    name: str
    category: str
    severity: int
    description: str
    proof: str
    remediation: str
    url: str
    parameter: Optional[str] = None
    cvss: float = 0.0
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "severity_name": VulnerabilitySeverity(self.severity).name,
            "description": self.description,
            "proof": self.proof,
            "remediation": self.remediation,
            "url": self.url,
            "parameter": self.parameter,
            "cvss": self.cvss,
            "references": self.references
        }


@dataclass
class ScanResult:
    """Complete vulnerability scan result"""
    target: str
    scan_start: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_end: str = ""
    scan_duration: float = 0.0
    target_url: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_stats: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "scan_duration": f"{self.scan_duration:.2f}s",
            "target_url": self.target_url,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_stats": self.scan_stats,
            "summary": {
                "total": len(self.vulnerabilities),
                "critical": len([v for v in self.vulnerabilities if v.severity == 5]),
                "high": len([v for v in self.vulnerabilities if v.severity == 4]),
                "medium": len([v for v in self.vulnerabilities if v.severity == 3]),
                "low": len([v for v in self.vulnerabilities if v.severity == 2]),
                "info": len([v for v in self.vulnerabilities if v.severity == 1])
            }
        }


# SQL Injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
    "1; DROP TABLE users--",
    "1' OR '1'='1",
    "OR 1=1",
    "OR true--",
    "admin' OR '1'='1",
    "' OR ''='",
    "') OR ('1'='1",
    "\" OR \"1\"=\"1",
    "1=1",
    "1=1--",
    "1=1#",
    "1=1/*",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<video src=x onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "'; alert('XSS');//",
    "\"><script>alert('XSS')</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<object data='javascript:alert(\"XSS\")'>",
]

# Command injection payloads
CMDI_PAYLOADS = [
    "; whoami",
    "| whoami",
    "`whoami`",
    "$(whoami)",
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

# Directory traversal payloads
DIR_TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "....//....//etc//passwd",
    "/etc/passwd",
    "..\\..\\etc\\passwd",
    "%2e%2e/etc/passwd",
    "etc/passwd",
    "..%252f..%252fetc%252fpasswd",
]


class VulnerabilityScanner:
    """OWASP Top 10 Vulnerability Scanner"""
    
    def __init__(self, target: str, verbose: bool = False, threads: int = 10):
        self.target = target
        self.verbose = verbose
        self.threads = threads
        self.logger = self._setup_logging()
        self.result = ScanResult(target=target)
        self.session = None
        self.cookies = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                         'AppleWebKit/537.36 (KHTML, like Gecko) '
                         'Chrome/91.0.4472.124 Safari/537.36'
        }
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("vuln_scanner")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistency"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        if not parsed.netloc:
            url = 'http://' + url
        
        return url.rstrip('/')
    
    def _make_request(self, url: str, method: str = 'GET', data: Dict = None,
                     cookies: Dict = None, headers: Dict = None) -> Tuple[Optional[str], int]:
        """Make HTTP request and return response"""
        try:
            req_headers = self.headers.copy()
            if headers:
                req_headers.update(headers)
            
            req = Request(url, headers=req_headers)
            
            if data:
                if method == 'GET':
                    url += '?' + urlencode(data)
                else:
                    req.data = urlencode(data).encode()
                req = Request(url, headers=req_headers)
            
            if cookies:
                req.add_header('Cookie', '; '.join(f'{k}={v}' for k, v in cookies.items()))
            
            with urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                status = response.status
                return content, status
                
        except HTTPError as e:
            return None, e.code
        except URLError as e:
            self.logger.debug(f"Request failed: {e}")
            return None, 0
        except Exception as e:
            self.logger.debug(f"Request error: {e}")
            return None, 0
    
    def _get_all_urls(self, base_url: str, max_pages: int = 50) -> List[str]:
        """Crawl website to discover URLs"""
        urls = set([base_url])
        urls_to_visit = [base_url]
        visited = set()
        
        while urls_to_visit and len(visited) < max_pages:
            url = urls_to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            content, _ = self._make_request(url)
            
            if content:
                # Extract links
                soup = BeautifulSoup(content, 'lxml')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    
                    if parsed.netloc == urlparse(base_url).netloc:
                        urls.add(full_url)
                        if full_url not in visited and len(urls_to_visit) < max_pages:
                            urls_to_visit.append(full_url)
                
                # Extract forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    form_url = urljoin(base_url, action)
                    urls.add(form_url)
        
        return list(urls)
    
    def _extract_params(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    
    def _check_sql_injection(self, url: str, param: str) -> Optional[Vulnerability]:
        """Check for SQL injection vulnerability"""
        for payload in SQLI_PAYLOADS[:10]:  # Limit payloads
            params = self._extract_params(url)
            if param in params:
                params[param] = params[param] + payload
            else:
                params[param] = payload
            
            test_url = url.split('?')[0] + '?' + urlencode(params)
            content, status = self._make_request(test_url)
            
            if content:
                # Check for error indicators
                error_patterns = [
                    r'sql syntax|mysql error|ora-\\d+|postgresql error|sqlite error',
                    r'you have an error in your sql syntax',
                    r'warning.*mysql',
                    r'unexpected end of sql command',
                    r'argument of .* is not numeric',
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return Vulnerability(
                            id=f"SQLI-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                            name="SQL Injection",
                            category=VulnerabilityCategory.A1_INJECTION.value,
                            severity=VulnerabilitySeverity.CRITICAL.value,
                            description="SQL injection vulnerability detected in parameter '{}'".format(param),
                            proof=f"Payload: {payload}",
                            remediation="Use parameterized queries or prepared statements. "
                                       "Never concatenate user input directly into SQL queries.",
                            url=url,
                            parameter=param,
                            cvss=9.8,
                            references=["https://owasp.org/www-project-web-security-testing-guide/"]
                        )
                
                # Boolean-based detection
                original_params = self._extract_params(url)
                if original_params:
                    # Check if responses differ significantly
                    true_params = original_params.copy()
                    true_params[param] = "1 OR 1=1"
                    false_params = original_params.copy()
                    false_params[param] = "1 AND 1=0"
                    
                    true_content, _ = self._make_request(
                        url.split('?')[0] + '?' + urlencode(true_params)
                    )
                    false_content, _ = self._make_request(
                        url.split('?')[0] + '?' + urlencode(false_params)
                    )
                    
                    if true_content and false_content:
                        if len(true_content) != len(false_content):
                            return Vulnerability(
                                id=f"SQLI-BOOL-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                                name="SQL Injection (Boolean-based)",
                                category=VulnerabilityCategory.A1_INJECTION.value,
                                severity=VulnerabilitySeverity.HIGH.value,
                                description="Potential SQL injection detected using boolean-based techniques",
                                proof=f"Different response lengths with boolean conditions",
                                remediation="Use parameterized queries. Validate and sanitize all user input.",
                                url=url,
                                parameter=param,
                                cvss=7.5,
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                            )
        
        return None
    
    def _check_xss(self, url: str, param: str) -> List[Vulnerability]:
        """Check for XSS vulnerabilities"""
        vulnerabilities = []
        
        for payload in XSS_PAYLOADS[:5]:  # Limit payloads
            params = self._extract_params(url)
            if param in params:
                original = params[param]
                params[param] = original + payload
            else:
                params[param] = payload
            
            test_url = url.split('?')[0] + '?' + urlencode(params)
            content, status = self._make_request(test_url)
            
            if content and payload in content:
                vulnerabilities.append(
                    Vulnerability(
                        id=f"XSS-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                        name="Cross-Site Scripting (XSS)",
                        category=VulnerabilityCategory.A7_XSS.value,
                        severity=VulnerabilitySeverity.HIGH.value,
                        description="Reflected XSS vulnerability in parameter '{}'".format(param),
                        proof=f"Payload reflected in response: {payload[:50]}...",
                        remediation="Implement output encoding. Use Content Security Policy (CSP). "
                                   "Validate and sanitize user input.",
                        url=test_url,
                        parameter=param,
                        cvss=6.1,
                        references=["https://owasp.org/www-community/attacks/xss/"]
                    )
                )
                break
        
        return vulnerabilities
    
    def _check_directory_traversal(self, url: str, param: str) -> Optional[Vulnerability]:
        """Check for directory traversal vulnerability"""
        for payload in DIR_TRAVERSAL_PAYLOADS[:5]:
            params = self._extract_params(url)
            if param in params:
                params[param] = params[param] + payload
            else:
                params[param] = payload
            
            test_url = url.split('?')[0] + '?' + urlencode(params)
            content, status = self._make_request(test_url)
            
            if content and 'root:x:' in content:
                return Vulnerability(
                    id=f"DIR-TRAV-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                    name="Path Traversal",
                    category=VulnerabilityCategory.A5_BROKEN_ACCESS_CONTROL.value,
                    severity=VulnerabilitySeverity.HIGH.value,
                    description="Directory traversal vulnerability in parameter '{}'".format(param),
                    proof=f"Access to /etc/passwd successful",
                    remediation="Use allowlist for file paths. Never use user input directly in file operations. "
                               "Implement proper access controls.",
                    url=test_url,
                    parameter=param,
                    cvss=7.5,
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"]
                )
        
        return None
    
    def _check_security_headers(self, url: str) -> List[Vulnerability]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        content, status = self._make_request(url)
        if not content:
            return vulnerabilities
        
        # Check for missing headers
        missing_headers = []
        
        if not content.__contains__('X-Content-Type-Options'):
            missing_headers.append('X-Content-Type-Options')
        if not content.__contains__('X-Frame-Options'):
            missing_headers.append('X-Frame-Options')
        if not content.__contains__('X-XSS-Protection'):
            missing_headers.append('X-XSS-Protection')
        if not content.__contains__('Strict-Transport-Security'):
            missing_headers.append('Strict-Transport-Security')
        if not content.__contains__('Content-Security-Policy'):
            missing_headers.append('Content-Security-Policy')
        
        for header in missing_headers:
            vulnerabilities.append(
                id=f"SECH-{header.upper()}-{datetime.now().strftime('%H%M%S')}",
                name=f"Missing Security Header: {header}",
                category=VulnerabilityCategory.A6_SECURITY_MISCONFIGURATION.value,
                severity=VulnerabilitySeverity.LOW.value,
                description=f"Security header '{header}' is missing",
                proof=f"Header check on {url}",
                remediation=f"Add '{header}' header to all HTTP responses.",
                url=url,
                references=["https://owasp.org/www-project-secure-coding-quick-reference-guide/"]
            )
        
        return vulnerabilities
    
    def _check_clickjacking(self, url: str) -> Optional[Vulnerability]:
        """Check for clickjacking vulnerability"""
        content, status = self._make_request(url)
        
        if content:
            if not content.__contains__('X-Frame-Options') and \
               not content.__contains__('Content-Security-Policy'):
                return Vulnerability(
                    id=f"CLICK-{datetime.now().strftime('%H%M%S')}",
                    name="Clickjacking",
                    category=VulnerabilityCategory.A6_SECURITY_MISCONFIGURATION.value,
                    severity=VulnerabilitySeverity.MEDIUM.value,
                    description="Application may be vulnerable to clickjacking attacks",
                    proof="Missing X-Frame-Options and CSP headers",
                    remediation="Implement X-Frame-Options: DENY or SAMEORIGIN. "
                               "Use Content-Security-Policy to restrict framing.",
                    url=url,
                    cvss=6.1,
                    references=["https://owasp.org/www-community/attacks/Clickjacking"]
                )
        
        return None
    
    def _check_info_disclosure(self, url: str) -> List[Vulnerability]:
        """Check for information disclosure"""
        vulnerabilities = []
        
        content, status = self._make_request(url)
        
        if content:
            # Check for common info disclosures
            patterns = [
                (r'PHP/\\d+\\.\\d+\\.\\d+', 'PHP Version Disclosure'),
                (r'Apache/\\d+\\.\\d+', 'Apache Version Disclosure'),
                (r'Microsoft IIS/\\d+\\.\\d+', 'IIS Version Disclosure'),
                (r'X-Powered-By:.*', 'X-Powered-By Header'),
                (r'Server:.*', 'Server Banner'),
                (r'Debug.*Trace.*Enabled', 'Debug Mode Enabled'),
                (r'SQLSTATE|ODBC', 'Database Error Disclosure'),
            ]
            
            for pattern, name in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerabilities.append(
                        Vulnerability(
                            id=f"INFO-{name.upper().replace(' ', '-')}-{datetime.now().strftime('%H%M%S')}",
                            name=f"Information Disclosure: {name}",
                            category=VulnerabilityCategory.A6_SECURITY_MISCONFIGURATION.value,
                            severity=VulnerabilitySeverity.LOW.value,
                            description=f"Sensitive information disclosure: {name}",
                            proof=f"Pattern found: {pattern}",
                            remediation="Remove version banners and unnecessary headers. "
                                       "Disable debug mode in production.",
                            url=url,
                            references=["https://owasp.org/www-community/attacks/Information_Disclosure"]
                        )
                    )
        
        return vulnerabilities
    
    def scan(self, urls: List[str] = None) -> ScanResult:
        """Perform vulnerability scan"""
        self.logger.info(f"Starting vulnerability scan for {self.target}")
        start_time = time.time()
        
        # Normalize target
        target_url = self._normalize_url(self.target)
        self.result.target_url = target_url
        
        # Get URLs to scan
        if urls:
            urls_to_scan = urls
        else:
            self.logger.info("Crawling target website...")
            urls_to_scan = self._get_all_urls(target_url)
        
        self.logger.info(f"Found {len(urls_to_scan)} URLs to scan")
        
        # Scan each URL
        all_vulnerabilities = []
        
        for url in urls_to_scan[:50]:  # Limit to 50 URLs
            if self.verbose:
                self.logger.info(f"Scanning: {url}")
            
            # Extract parameters
            params = self._extract_params(url)
            
            # Skip URLs without parameters
            if not params:
                continue
            
            # Check each parameter
            for param in params:
                # SQL Injection check
                sqli = self._check_sql_injection(url, param)
                if sqli:
                    all_vulnerabilities.append(sqli)
                
                # XSS check
                xss_list = self._check_xss(url, param)
                all_vulnerabilities.extend(xss_list)
                
                # Directory traversal check
                dti = self._check_directory_traversal(url, param)
                if dti:
                    all_vulnerabilities.append(dti)
            
            # Check headers
            all_vulnerabilities.extend(self._check_security_headers(url))
            
            # Check clickjacking
            click = self._check_clickjacking(url)
            if click:
                all_vulnerabilities.append(click)
            
            # Check info disclosure
            all_vulnerabilities.extend(self._check_info_disclosure(url))
        
        self.result.vulnerabilities = all_vulnerabilities
        
        # Calculate statistics
        self.result.scan_stats = {
            'urls_scanned': len(urls_to_scan),
            'parameters_tested': sum(1 for url in urls_to_scan for _ in self._extract_params(url).keys())
        }
        
        end_time = time.time()
        self.result.scan_end = datetime.utcnow().isoformat()
        self.result.scan_duration = end_time - start_time
        
        self.logger.info(
            f"Scan completed in {self.result.scan_duration:.2f}s. "
            f"Found {len(all_vulnerabilities)} vulnerabilities."
        )
        
        return self.result
    
    def print_results(self):
        """Print scan results"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}VULNERABILITY SCAN RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Target: {self.result.target_url}")
        print(f"Scan Duration: {self.result.scan_duration:.2f}s")
        print(f"URLs Scanned: {self.result.scan_stats.get('urls_scanned', 0)}\n")
        
        # Summary
        summary = self.result.to_dict()['summary']
        print(f"{Fore.RED}Critical: {summary['critical']}{Style.RESET_ALL} | "
              f"{Fore.ORANGE}High: {summary['high']}{Style.RESET_ALL} | "
              f"{Fore.YELLOW}Medium: {summary['medium']}{Style.RESET_ALL} | "
              f"{Fore.BLUE}Low: {summary['low']}{Style.RESET_ALL} | "
              f"{Fore.GREEN}Info: {summary['info']}{Style.RESET_ALL}\n")
        
        # Detailed results
        severity_colors = {
            5: Fore.RED,
            4: Fore.ORANGE,
            3: Fore.YELLOW,
            2: Fore.BLUE,
            1: Fore.GREEN
        }
        
        if self.result.vulnerabilities:
            print(f"{Fore.CYAN}Detected Vulnerabilities:{Style.RESET_ALL}\n")
            
            for vuln in sorted(self.result.vulnerabilities, 
                              key=lambda x: -x.severity):
                color = severity_colors.get(vuln.severity, Fore.WHITE)
                print(f"{color}[{VulnerabilitySeverity(vuln.severity).name}]{Style.RESET_ALL} "
                      f"{vuln.name}")
                print(f"  ID: {vuln.id}")
                print(f"  URL: {vuln.url}")
                if vuln.parameter:
                    print(f"  Parameter: {vuln.parameter}")
                print(f"  Description: {vuln.description}")
                print(f"  Remediation: {vuln.remediation}\n")
        else:
            print(f"{Fore.GREEN}No vulnerabilities detected.{Style.RESET_ALL}\n")
    
    def save_results(self, filename: str = "vuln_scan_results.json"):
        """Save scan results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        self.logger.info(f"Results saved to {filename}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t http://localhost:8080
  %(prog)s -t http://example.com --owasp-top-10 -v
  %(prog)s -t http://example.com -o results.json
  %(prog)s -t https://target.com --threads 20
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help="Target URL to scan")
    parser.add_argument('-o', '--output', default="vuln_scan_results.json",
                       help="Output JSON file (default: vuln_scan_results.json)")
    parser.add_argument('--threads', type=int, default=10,
                       help="Number of threads (default: 10)")
    parser.add_argument('--owasp-top-10', action='store_true',
                       help="Focus on OWASP Top 10 vulnerabilities")
    parser.add_argument('--urls', help="File containing URLs to scan (one per line)")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--no-color', action='store_true',
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.no_color:
        colorama.deinit()
    
    # Initialize scanner
    scanner = VulnerabilityScanner(
        target=args.target,
        verbose=args.verbose,
        threads=args.threads
    )
    
    # Get URLs
    urls = None
    if args.urls:
        with open(args.urls, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    
    # Run scan
    result = scanner.scan(urls=urls)
    
    # Print results
    scanner.print_results()
    
    # Save results
    scanner.save_results(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
