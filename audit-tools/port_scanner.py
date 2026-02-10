#!/usr/bin/env python3
"""
🔍 Advanced Multi-Threaded Port Scanner

A professional-grade port scanner with service detection, banner grabbing,
and JSON output for security auditing.

Author: SOC Analyst
Version: 1.0.0
License: MIT
"""

import argparse
import concurrent.futures
import json
import logging
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set
from urllib.request import urlopen
from urllib.error import URLError

import colorama
from colorama import Fore, Style
import tqdm

# Initialize colorama
colorama.init()


class PortState(Enum):
    """Enumeration of possible port states"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


@dataclass
class PortInfo:
    """Information about a scanned port"""
    port: int
    state: str
    service: str = "unknown"
    banner: str = ""
    version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    """Complete scan result for a target"""
    target: str
    ports: List[PortInfo] = field(default_factory=list)
    scan_start: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_end: str = ""
    scan_duration: float = 0.0
    total_ports_scanned: int = 0
    open_ports_count: int = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "scan_duration": f"{self.scan_duration:.2f}s",
            "total_ports_scanned": self.total_ports_scanned,
            "open_ports_count": self.open_ports_count,
            "open_ports": [p.to_dict() for p in self.ports if p.state == "open"]
        }


# Common port to service mappings
COMMON_PORTS: Dict[int, str] = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    523: "IBM DB2",
    554: "RTSP",
    587: "SMTP Submission",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2181: "ZooKeeper",
    2222: "SSH Alt",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4369: "Erlang Port Mapper",
    5060: "SIP",
    5061: "SIP TLS",
    5222: "XMPP Client",
    5269: "XMPP Server",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    7001: "WebLogic",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
    9000: "PHP-FPM",
    9042: "Cassandra",
    9090: "Prometheus",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB Shard",
    50000: "SAP"
}

# Timeout for connections (seconds)
DEFAULT_TIMEOUT = 2
BANNER_TIMEOUT = 3


class PortScanner:
    """Advanced multi-threaded port scanner with service detection"""
    
    def __init__(self, target: str, ports: str = "1-1024", threads: int = 100, 
                 timeout: float = DEFAULT_TIMEOUT, verbose: bool = False):
        self.target = target
        self.ports = self._parse_ports(ports)
        self.threads = min(threads, 500)
        self.timeout = timeout
        self.verbose = verbose
        self.logger = self._setup_logging()
        self.result = ScanResult(target=target)
        
    def _parse_ports(self, port_spec: str) -> List[int]:
        """Parse port specification (e.g., '1-1024,8080,443')"""
        ports = []
        parts = port_spec.split(',')
        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))
    
    def _setup_logging(self) -> logging.Logger:
        """Configure logging for the scanner"""
        logger = logging.getLogger(f"port_scanner_{self.target}")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _resolve_target(self) -> str:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return self.target
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for a port"""
        return COMMON_PORTS.get(port, "unknown")
    
    def _grab_banner(self, ip: str, port: int, timeout: float) -> Optional[str]:
        """Attempt to grab service banner from a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Try to receive initial banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner[:256]  # Limit banner length
            except:
                pass
            
            # Try to send HTTP HEAD request for web ports
            if port in [80, 443, 8080, 8443]:
                try:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if "HTTP" in response:
                        return response.split('\r\n')[0]
                except:
                    pass
            
            sock.close()
        except Exception as e:
            self.logger.debug(f"Banner grab failed on port {port}: {e}")
        return None
    
    def _grab_https_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from HTTPS services"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    banner = ssock.version()
                    if cert:
                        subject = dict(x[0] for x in cert['subject'])
                        issuer = dict(x[0] for x in cert['issuer'])
                        return f"{banner}, CN: {subject.get('commonName', 'Unknown')}"
                    return banner
        except Exception as e:
            self.logger.debug(f"HTTPS banner grab failed on port {port}: {e}")
        return None
    
    def _check_port(self, ip: str, port: int) -> PortInfo:
        """Check if a single port is open"""
        state = PortState.UNKNOWN
        banner = ""
        service = self._get_service_name(port)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                state = PortState.OPEN
                # Grab banner for open ports
                if port == 443 or port == 8443:
                    banner = self._grab_https_banner(ip, port) or ""
                else:
                    banner = self._grab_banner(ip, port, BANNER_TIMEOUT) or ""
            else:
                state = PortState.CLOSED
                
        except socket.timeout:
            state = PortState.FILTERED
        except Exception as e:
            self.logger.debug(f"Error checking port {port}: {e}")
            state = PortState.UNKNOWN
        
        return PortInfo(
            port=port,
            state=state.value,
            service=service,
            banner=banner
        )
    
    def scan(self) -> ScanResult:
        """Perform the port scan using multi-threading"""
        self.logger.info(f"Starting scan of {len(self.ports)} ports")
        start_time = time.time()
        
        ip = self._resolve_target()
        self.logger.info(f"Resolved {self.target} to {ip}")
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create progress bar
            with tqdm.tqdm(total=len(self.ports), desc="Scanning ports", 
                          unit="port", ncols=100) as pbar:
                
                # Submit all port scan tasks
                future_to_port = {
                    executor.submit(self._check_port, ip, port): port 
                    for port in self.ports
                }
                
                # Process completed futures
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        port_info = future.result()
                        self.result.ports.append(port_info)
                        
                        if port_info.state == "open":
                            open_ports.append(port)
                            if self.verbose:
                                self.logger.info(
                                    f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} "
                                    f"Port {port}/tcp - {port_info.service}"
                                )
                            pbar.set_postfix({"open": len(open_ports)})
                        
                    except Exception as e:
                        self.logger.error(f"Error processing port {port}: {e}")
                    finally:
                        pbar.update(1)
        
        end_time = time.time()
        self.result.scan_end = datetime.utcnow().isoformat()
        self.result.scan_duration = end_time - start_time
        self.result.total_ports_scanned = len(self.ports)
        self.result.open_ports_count = len(open_ports)
        
        self.logger.info(
            f"{Fore.CYAN}Scan completed in {self.result.scan_duration:.2f}s{Style.RESET_ALL}"
        )
        self.logger.info(
            f"Found {Fore.GREEN}{len(open_ports)}{Style.RESET_ALL} open ports"
        )
        
        return self.result
    
    def print_results(self):
        """Print scan results to console"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Port Scan Results for {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        open_ports = [p for p in self.result.ports if p.state == "open"]
        
        if not open_ports:
            print(f"{Fore.YELLOW}No open ports found{Style.RESET_ALL}")
            return
        
        print(f"{'Port':<8}{'State':<10}{'Service':<20}{'Banner'}")
        print(f"{'-'*80}")
        
        for port in sorted(open_ports, key=lambda x: x.port):
            banner = port.banner[:50] if port.banner else ""
            print(
                f"{Fore.GREEN}{port.port:<8}{Style.RESET_ALL}"
                f"{port.state:<10}"
                f"{port.service:<20}"
                f"{banner}"
            )
        
        print(f"\n{Fore.CYAN}Total open ports: {len(open_ports)}{Style.RESET_ALL}")
    
    def save_results(self, filename: str = "scan_results.json"):
        """Save scan results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        self.logger.info(f"Results saved to {filename}")


def main():
    """Main entry point for the port scanner"""
    parser = argparse.ArgumentParser(
        description="Advanced Multi-Threaded Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1
  %(prog)s -t 192.168.1.1 -p 1-1024 --threads 50
  %(prog)s -t example.com -p 80,443,8080 -o results.json
  %(prog)s -t 10.0.0.1 -p 1-65535 --verbose
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help="Target IP or hostname")
    parser.add_argument('-p', '--ports', default="1-1024", 
                       help="Port range to scan (default: 1-1024)")
    parser.add_argument('--threads', type=int, default=100, 
                       help="Number of threads (default: 100)")
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT,
                       help="Connection timeout in seconds (default: 2)")
    parser.add_argument('-o', '--output', default="port_scan_results.json",
                       help="Output JSON file (default: port_scan_results.json)")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--no-color', action='store_true',
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        colorama.deinit()
        # Remove color codes from output
        import re
        original_print = print
        def colored_print(*args, **kwargs):
            text = ' '.join(str(a) for a in args)
            text = re.sub(r'\x1b\[[0-9;]*m', '', text)
            original_print(text, **kwargs)
        globals()['print'] = colored_print
    
    # Create scanner and run
    scanner = PortScanner(
        target=args.target,
        ports=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Perform scan
    result = scanner.scan()
    
    # Print results
    scanner.print_results()
    
    # Save results
    scanner.save_results(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
