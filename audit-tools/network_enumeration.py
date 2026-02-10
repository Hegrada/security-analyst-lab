#!/usr/bin/env python3
"""
🌐 Network Enumeration Tool

Comprehensive network discovery and enumeration tool for security auditing.
Performs host discovery, port scanning, service enumeration, and OS detection.

Author: SOC Analyst
Version: 1.0.0
License: MIT
"""

import argparse
import ipaddress
import json
import logging
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import colorama
from colorama import Fore, Style

colorama.init()


class Protocol(Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


@dataclass
class Host:
    """Discovered host information"""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    ports: Dict[int, Dict] = field(default_factory=dict)
    services: List[str] = field(default_factory=list)
    alive: bool = True
    response_time: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "ports": self.ports,
            "services": self.services,
            "alive": self.alive,
            "response_time": f"{self.response_time:.2f}ms"
        }


@dataclass
class Service:
    """Enumerated service information"""
    port: int
    protocol: str
    name: str
    version: str = ""
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "name": self.name,
            "version": self.version,
            "banner": self.banner,
            "vulnerabilities": self.vulnerabilities
        }


@dataclass
class EnumerationResult:
    """Complete enumeration result"""
    target: str
    scan_start: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_end: str = ""
    duration: float = 0.0
    hosts: List[Host] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "duration": f"{self.duration:.2f}s",
            "hosts": [h.to_dict() for h in self.hosts],
            "services": [s.to_dict() for s in self.services],
            "summary": self.summary
        }


# Common services and their ports
SERVICE_DB = {
    20: {"name": "FTP Data", "protocol": "tcp"},
    21: {"name": "FTP Control", "protocol": "tcp"},
    22: {"name": "SSH", "protocol": "tcp"},
    23: {"name": "Telnet", "protocol": "tcp"},
    25: {"name": "SMTP", "protocol": "tcp"},
    53: {"name": "DNS", "protocol": "tcp"},
    53: {"name": "DNS", "protocol": "udp"},
    67: {"name": "DHCP", "protocol": "udp"},
    69: {"name": "TFTP", "protocol": "udp"},
    80: {"name": "HTTP", "protocol": "tcp"},
    110: {"name": "POP3", "protocol": "tcp"},
    119: {"name": "NNTP", "protocol": "tcp"},
    123: {"name": "NTP", "protocol": "udp"},
    135: {"name": "MS RPC", "protocol": "tcp"},
    137: {"name": "NetBIOS Name", "protocol": "udp"},
    138: {"name": "NetBIOS Datagram", "protocol": "udp"},
    139: {"name": "NetBIOS Session", "protocol": "tcp"},
    143: {"name": "IMAP", "protocol": "tcp"},
    161: {"name": "SNMP", "protocol": "udp"},
    162: {"name": "SNMP Trap", "protocol": "udp"},
    389: {"name": "LDAP", "protocol": "tcp"},
    443: {"name": "HTTPS", "protocol": "tcp"},
    445: {"name": "SMB", "protocol": "tcp"},
    465: {"name": "SMTPS", "protocol": "tcp"},
    514: {"name": "Syslog", "protocol": "udp"},
    515: {"name": "LPD", "protocol": "tcp"},
    523: {"name": "IBM DB2", "protocol": "tcp"},
    554: {"name": "RTSP", "protocol": "tcp"},
    587: {"name": "SMTP Submission", "protocol": "tcp"},
    631: {"name": "IPP", "protocol": "tcp"},
    636: {"name": "LDAPS", "protocol": "tcp"},
    993: {"name": "IMAPS", "protocol": "tcp"},
    995: {"name": "POP3S", "protocol": "tcp"},
    1080: {"name": "SOCKS", "protocol": "tcp"},
    1194: {"name": "OpenVPN", "protocol": "tcp"},
    1433: {"name": "MSSQL", "protocol": "tcp"},
    1434: {"name": "MSSQL Browser", "protocol": "udp"},
    1521: {"name": "Oracle DB", "protocol": "tcp"},
    1723: {"name": "PPTP", "protocol": "tcp"},
    2049: {"name": "NFS", "protocol": "tcp"},
    2082: {"name": "cPanel", "protocol": "tcp"},
    2083: {"name": "cPanel SSL", "protocol": "tcp"},
    2181: {"name": "ZooKeeper", "protocol": "tcp"},
    2222: {"name": "SSH Alt", "protocol": "tcp"},
    3306: {"name": "MySQL", "protocol": "tcp"},
    3389: {"name": "RDP", "protocol": "tcp"},
    3690: {"name": "SVN", "protocol": "tcp"},
    4369: {"name": "Erlang Port Mapper", "protocol": "tcp"},
    5060: {"name": "SIP", "protocol": "tcp"},
    5061: {"name": "SIP TLS", "protocol": "tcp"},
    5222: {"name": "XMPP", "protocol": "tcp"},
    5269: {"name": "XMPP Server", "protocol": "tcp"},
    5432: {"name": "PostgreSQL", "protocol": "tcp"},
    5672: {"name": "RabbitMQ", "protocol": "tcp"},
    5900: {"name": "VNC", "protocol": "tcp"},
    5984: {"name": "CouchDB", "protocol": "tcp"},
    6379: {"name": "Redis", "protocol": "tcp"},
    6443: {"name": "Kubernetes API", "protocol": "tcp"},
    7001: {"name": "WebLogic", "protocol": "tcp"},
    8000: {"name": "HTTP Alt", "protocol": "tcp"},
    8080: {"name": "HTTP Proxy", "protocol": "tcp"},
    8443: {"name": "HTTPS Alt", "protocol": "tcp"},
    8888: {"name": "HTTP Alt", "protocol": "tcp"},
    9000: {"name": "PHP-FPM", "protocol": "tcp"},
    9042: {"name": "Cassandra", "protocol": "tcp"},
    9090: {"name": "Prometheus", "protocol": "tcp"},
    9092: {"name": "Kafka", "protocol": "tcp"},
    9200: {"name": "Elasticsearch", "protocol": "tcp"},
    9300: {"name": "Elasticsearch Cluster", "protocol": "tcp"},
    11211: {"name": "Memcached", "protocol": "tcp"},
    27017: {"name": "MongoDB", "protocol": "tcp"},
    50000: {"name": "SAP", "protocol": "tcp"},
}


class NetworkEnumerator:
    """Network Discovery and Enumeration Tool"""
    
    def __init__(self, target: str, verbose: bool = False, threads: int = 50):
        self.target = target
        self.verbose = verbose
        self.threads = threads
        self.logger = self._setup_logging()
        self.result = EnumerationResult(target=target)
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("network_enumeration")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _is_valid_ip(self, target: str) -> bool:
        """Check if target is a valid IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _expand_network(self, target: str) -> List[str]:
        """Expand network range to list of IPs"""
        ips = []
        
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            for ip in network:
                ips.append(str(ip))
        elif '-' in target:
            parts = target.split('-')
            start = ipaddress.ip_address(parts[0])
            end = ipaddress.ip_address(parts[1])
            current = start
            while current <= end:
                ips.append(str(current))
                current = ipaddress.ip_address(int(current) + 1)
        else:
            ips.append(target)
        
        return ips
    
    def _ping_host(self, ip: str, timeout: int = 1) -> Tuple[bool, float]:
        """Ping a host to check if it's alive"""
        try:
            import subprocess
            start_time = time.time()
            
            # Try ping with timeout
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), ip],
                capture_output=True,
                timeout=timeout + 1
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if result.returncode == 0:
                return True, response_time
            
            # Try with Windows
            result = subprocess.run(
                ['ping', '-n', '1', '-w', str(timeout * 1000), ip],
                capture_output=True,
                timeout=timeout + 1
            )
            
            if result.returncode == 0:
                return True, response_time
            
            return False, 0.0
            
        except Exception as e:
            self.logger.debug(f"Ping failed for {ip}: {e}")
            return False, 0.0
    
    def _tcp_port_scan(self, ip: str, port: int, timeout: int = 2) -> Tuple[bool, str]:
        """Scan a single TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Try to get banner
                banner = self._get_banner(ip, port, timeout)
                return True, banner
            
            return False, ""
            
        except Exception:
            return False, ""
    
    def _get_banner(self, ip: str, port: int, timeout: int = 3) -> str:
        """Grab service banner from a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:200]
            
        except Exception:
            return ""
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve hostname for an IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None
    
    def discover_hosts(self, targets: List[str]) -> List[Host]:
        """Discover alive hosts"""
        self.logger.info(f"Discovering hosts in {len(targets)} targets...")
        hosts = []
        
        for ip in targets:
            if self.verbose:
                self.logger.info(f"Checking host: {ip}")
            
            alive, response_time = self._ping_host(ip)
            
            if alive:
                hostname = self._resolve_hostname(ip)
                
                host = Host(
                    ip=ip,
                    hostname=hostname,
                    response_time=response_time
                )
                hosts.append(host)
                
                self.logger.info(
                    f"{Fore.GREEN}[+]{Style.RESET_ALL} Host found: {ip}"
                    + (f" ({hostname})" if hostname else "")
                )
        
        return hosts
    
    def enumerate_ports(self, host: Host, ports: List[int] = None, 
                       timeout: int = 2) -> Host:
        """Enumerate ports on a host"""
        if not ports:
            ports = list(SERVICE_DB.keys())
        
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._tcp_port_scan, host.ip, port, timeout): port
                for port in ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, banner = future.result()
                    
                    if is_open:
                        service_info = SERVICE_DB.get(port, {"name": "unknown", "protocol": "tcp"})
                        
                        open_ports[port] = {
                            "state": "open",
                            "service": service_info["name"],
                            "protocol": service_info["protocol"],
                            "banner": banner
                        }
                        
                        if self.verbose:
                            self.logger.info(
                                f"  {Fore.GREEN}[OPEN]{Style.RESET_ALL} "
                                f"Port {port}/tcp - {service_info['name']}"
                            )
                        
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {e}")
        
        host.ports = open_ports
        host.services = list(set(s for p, d in open_ports.items() for s in [d.get("service")] if s))
        
        return host
    
    def detect_operating_system(self, host: Host) -> Host:
        """Detect potential operating system"""
        # OS detection based on open ports and TTL
        os_indicators = {
            "Linux": {22, 80, 443, 3306, 5432, 6379, 8080},
            "Windows": {135, 139, 445, 3389, 1433, 1434},
            "Network Device": {22, 23, 80, 161, 443},
            "Database Server": {3306, 5432, 1433, 1521, 27017},
            "Web Server": {80, 443, 8080, 8443},
        }
        
        open_port_set = set(host.ports.keys())
        
        for os_name, indicators in os_indicators.items():
            if open_port_set & indicators:
                # Check if this is the best match
                matched = len(open_port_set & indicators)
                total = len(indicators)
                
                if matched / total >= 0.3:
                    host.os_guess = os_name
                    break
        
        return host
    
    def scan(self, port_range: str = "1-1024") -> EnumerationResult:
        """Perform complete network enumeration"""
        start_time = time.time()
        
        self.logger.info(f"Starting network enumeration for {self.target}")
        
        # Expand targets
        targets = self._expand_network(self.target)
        self.logger.info(f"Targets to scan: {len(targets)}")
        
        # Parse port range
        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            ports = list(range(start_port, end_port + 1))
        else:
            ports = list(map(int, port_range.split(',')))
        
        # Discover hosts
        hosts = self.discover_hosts(targets)
        
        # Enumerate ports on each host
        all_services = []
        
        for host in hosts:
            self.logger.info(f"Enumerating ports on {host.ip}...")
            host = self.enumerate_ports(host, ports)
            host = self.detect_operating_system(host)
            self.result.hosts.append(host)
            
            # Collect services
            for port, info in host.ports.items():
                service = Service(
                    port=port,
                    protocol=info["protocol"],
                    name=info["service"],
                    banner=info.get("banner", "")
                )
                all_services.append(service)
        
        self.result.services = all_services
        
        # Generate summary
        self.result.summary = {
            "hosts_up": len([h for h in self.result.hosts if h.alive]),
            "hosts_down": len(self.result.hosts) - len([h for h in self.result.hosts if h.alive]),
            "total_hosts": len(self.result.hosts),
            "open_ports": len(all_services),
            "unique_services": len(set(s.name for s in all_services))
        }
        
        end_time = time.time()
        self.result.scan_end = datetime.utcnow().isoformat()
        self.result.duration = end_time - start_time
        
        self.logger.info(
            f"Enumeration completed in {self.result.duration:.2f}s. "
            f"Found {len(hosts)} alive hosts."
        )
        
        return self.result
    
    def print_results(self):
        """Print enumeration results"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}NETWORK ENUMERATION RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Target: {self.target}")
        print(f"Duration: {self.result.duration:.2f}s\n")
        
        # Summary
        summary = self.result.summary
        print(f"{Fore.GREEN}Hosts Discovered: {summary['hosts_up']}{Style.RESET_ALL}")
        print(f"Total Hosts: {summary['total_hosts']}")
        print(f"Open Ports: {summary['open_ports']}")
        print(f"Unique Services: {summary['unique_services']}\n")
        
        # Host details
        for host in self.result.hosts:
            print(f"{Fore.CYAN}--- Host: {host.ip}{Style.RESET_ALL}")
            if host.hostname:
                print(f"  Hostname: {host.hostname}")
            if host.os_guess:
                print(f"  OS: {host.os_guess}")
            print(f"  Response Time: {host.response_time:.2f}ms")
            
            if host.ports:
                print(f"  Open Ports:")
                for port, info in sorted(host.ports.items()):
                    banner = f" - {info['banner'][:50]}" if info.get('banner') else ""
                    print(f"    {port}/tcp - {info['service']}{banner}")
            print()
    
    def save_results(self, filename: str = "network_enumeration_results.json"):
        """Save results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        self.logger.info(f"Results saved to {filename}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Network Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.0/24
  %(prog)s -t 192.168.1.1-50 -p 1-1000
  %(prog)s -t 10.0.0.1 -v
  %(prog)s -t 192.168.1.1 -o results.json
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help="Target IP, range (192.168.1.1-10), or CIDR (192.168.1.0/24)")
    parser.add_argument('-p', '--ports', default="1-1024",
                       help="Port range to scan (default: 1-1024)")
    parser.add_argument('-o', '--output', default="network_enumeration_results.json",
                       help="Output JSON file")
    parser.add_argument('--threads', type=int, default=50,
                       help="Number of threads (default: 50)")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--no-color', action='store_true',
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.no_color:
        colorama.deinit()
    
    enumerator = NetworkEnumerator(
        target=args.target,
        verbose=args.verbose,
        threads=args.threads
    )
    
    result = enumerator.scan(port_range=args.ports)
    
    enumerator.print_results()
    enumerator.save_results(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
