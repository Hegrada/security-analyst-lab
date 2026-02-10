#!/usr/bin/env python3
"""
📡 Network Packet Sniffer

Network traffic capture and analysis tool for threat detection and network forensics.
Captures packets and analyzes them for suspicious activity.

Author: SOC Analyst
Version: 1.0.0
License: MIT
"""

import argparse
import json
import logging
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter

import colorama
from colorama import Fore, Style

colorama.init()


class Protocol(Enum):
    """Network protocols"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"
    TELNET = "TELNET"
    FTP = "FTP"
    SMTP = "SMTP"
    UNKNOWN = "UNKNOWN"


@dataclass
class Packet:
    """Captured packet"""
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "UNKNOWN"
    length: int = 0
    payload: str = ""
    flags: str = ""
    info: str = ""
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "length": self.length,
            "payload": self.payload[:100] if self.payload else "",
            "flags": self.flags,
            "info": self.info
        }


@dataclass
class TrafficStats:
    """Traffic statistics"""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    top_source_ips: Dict[str, int] = field(default_factory=dict)
    top_destination_ips: Dict[str, int] = field(default_factory=dict)
    top_ports: Dict[int, int] = field(default_factory=dict)
    suspicious_packets: int = 0
    
    def to_dict(self) -> dict:
        return {
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": f"{self.duration:.2f}s",
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocol_distribution": self.protocol_distribution,
            "top_source_ips": dict(self.top_source_ips.most_common(10)),
            "top_destination_ips": dict(self.top_destination_ips.most_common(10)),
            "top_ports": dict(self.top_ports.most_common(10)),
            "suspicious_packets": self.suspicious_packets
        }


@dataclass
class Alert:
    """Security alert"""
    id: str
    timestamp: str
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    description: str
    evidence: str = ""
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "evidence": self.evidence
        }


class PacketSniffer:
    """Network Packet Sniffer and Analyzer"""
    
    PROTOCOL_MAP = {
        6: Protocol.TCP,
        17: Protocol.UDP,
        1: Protocol.ICMP,
        0x0806: Protocol.ARP,
    }
    
    COMMON_PORTS = {
        80: Protocol.HTTP,
        443: Protocol.HTTPS,
        53: Protocol.DNS,
        22: Protocol.SSH,
        23: Protocol.TELNET,
        21: Protocol.FTP,
        25: Protocol.SMTP,
    }
    
    def __init__(self, interface: str = None, verbose: bool = False, 
                 capture_filter: str = None, save_file: str = None):
        self.interface = interface
        self.verbose = verbose
        self.capture_filter = capture_filter
        self.save_file = save_file
        self.logger = self._setup_logging()
        self.packets: List[Packet] = []
        self.alerts: List[Alert] = []
        self.stats = TrafficStats()
        self.running = False
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("packet_sniffer")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _parse_packet(self, raw_packet: bytes) -> Optional[Packet]:
        """Parse raw packet data"""
        try:
            eth_header = raw_packet[:14]
            eth_type = int.from_bytes(raw_packet[12:14], 'big')
            
            if eth_type == 0x0800:  # IPv4
                ip_header_start = 14
                ip_header_length = (raw_packet[ip_header_start] & 0x0F) * 4
                
                source_ip = socket.inet_ntoa(raw_packet[ip_header_start+12:ip_header_start+16])
                dest_ip = socket.inet_ntoa(raw_packet[ip_header_start+16:ip_header_start+20])
                
                protocol_num = raw_packet[ip_header_start + 9]
                protocol = self.PROTOCOL_MAP.get(protocol_num, Protocol.UNKNOWN).value
                
                src_port = 0
                dst_port = 0
                flags = ""
                payload = ""
                
                if protocol_num == 6:  # TCP
                    tcp_start = ip_header_start + ip_header_length
                    src_port = int.from_bytes(raw_packet[tcp_start:tcp_start+2], 'big')
                    dst_port = int.from_bytes(raw_packet[tcp_start+2:tcp_start+4], 'big')
                    
                    flags_byte = raw_packet[tcp_start+13]
                    flag_list = []
                    if flags_byte & 0x02: flag_list.append("SYN")
                    if flags_byte & 0x10: flag_list.append("ACK")
                    flags = ','.join(flag_list)
                    
                    payload_start = tcp_start + ((raw_packet[tcp_start+12] & 0xF0) >> 4) * 4
                    if len(raw_packet) > payload_start:
                        payload = raw_packet[payload_start:payload_start+100].decode('utf-8', errors='ignore')
                
                elif protocol_num == 17:  # UDP
                    udp_start = ip_header_start + ip_header_length
                    src_port = int.from_bytes(raw_packet[udp_start:udp_start+2], 'big')
                    dst_port = int.from_bytes(raw_packet[udp_start+2:udp_start+4], 'big')
                    
                    payload_start = udp_start + 8
                    if len(raw_packet) > payload_start:
                        payload = raw_packet[payload_start:payload_start+100].decode('utf-8', errors='ignore')
                
                if dst_port in self.COMMON_PORTS:
                    protocol = self.COMMON_PORTS[dst_port].value
                
                packet = Packet(
                    timestamp=datetime.now().isoformat(),
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=protocol,
                    length=len(raw_packet),
                    payload=payload,
                    flags=flags,
                    info=f"{protocol} {src_port} -> {dst_port}"
                )
                
                return packet
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")
            return None
    
    def _check_suspicious_activity(self, packet: Packet):
        """Check for suspicious activity patterns"""
        alert_id = f"ALERT-{datetime.now().strftime('%H%M%S')}"
        
        if packet.payload:
            payload_lower = packet.payload.lower()
            
            if any(kw in payload_lower for kw in ['password', 'passwd', 'pwd=', 'user=', 'login']):
                if 'http' in packet.protocol.lower() or packet.destination_port == 80:
                    self.alerts.append(Alert(
                        id=alert_id,
                        timestamp=packet.timestamp,
                        alert_type="cleartext_credentials",
                        severity="HIGH",
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        description="Cleartext credentials detected in HTTP traffic",
                        evidence=packet.payload[:100]
                    ))
                    self.stats.suspicious_packets += 1
            
            if any(kw in payload_lower for kw in ['union select', 'or 1=1', '--', 'sleep(']):
                self.alerts.append(Alert(
                    id=alert_id,
                    timestamp=packet.timestamp,
                    alert_type="sql_injection_attempt",
                    severity="CRITICAL",
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    description="Potential SQL injection attempt detected",
                    evidence=packet.payload[:100]
                ))
                self.stats.suspicious_packets += 1
        
        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9999}
        if packet.destination_port in suspicious_ports:
            self.alerts.append(Alert(
                id=alert_id,
                timestamp=packet.timestamp,
                alert_type="suspicious_port",
                severity="MEDIUM",
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                description=f"Traffic to suspicious port {packet.destination_port}",
                evidence=f"Destination port: {packet.destination_port}"
            ))
            self.stats.suspicious_packets += 1
    
    def _update_stats(self, packet: Packet):
        """Update traffic statistics"""
        self.stats.total_packets += 1
        self.stats.total_bytes += packet.length
        
        self.stats.protocol_distribution[packet.protocol] = \
            self.stats.protocol_distribution.get(packet.protocol, 0) + 1
        
        self.stats.top_source_ips[packet.source_ip] = \
            self.stats.top_source_ips.get(packet.source_ip, 0) + 1
        self.stats.top_destination_ips[packet.destination_ip] = \
            self.stats.top_destination_ips.get(packet.destination_ip, 0) + 1
        
        if packet.destination_port > 0:
            self.stats.top_ports[packet.destination_port] = \
                self.stats.top_ports.get(packet.destination_port, 0) + 1
    
    def _print_packet_summary(self, packet: Packet):
        """Print brief packet summary"""
        color_map = {
            "TCP": Fore.BLUE,
            "UDP": Fore.GREEN,
            "ICMP": Fore.YELLOW,
            "HTTP": Fore.CYAN,
            "HTTPS": Fore.CYAN,
            "DNS": Fore.MAGENTA,
        }
        
        color = color_map.get(packet.protocol, Fore.WHITE)
        
        print(f"{color}{packet.timestamp.split('T')[1][:12]}{Style.RESET_ALL} "
              f"{packet.source_ip}:{packet.source_port} -> "
              f"{packet.destination_ip}:{packet.destination_port} "
              f"[{packet.protocol}]")
    
    def start_capture(self, duration: int = 60):
        """Start packet capture"""
        self.logger.info(f"Starting packet capture on interface: {self.interface or 'all'}")
        self.logger.info(f"Capture filter: {self.capture_filter or 'none'}")
        self.logger.info(f"Duration: {duration}s")
        
        self.stats.start_time = datetime.now().isoformat()
        self.running = True
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(1.0)
        except OSError:
            self.logger.warning("Raw socket access denied. Running in simulation mode.")
            self._simulate_capture(duration)
            return
        
        start_time = time.time()
        packet_count = 0
        
        try:
            while self.running and (time.time() - start_time) < duration:
                try:
                    raw_packet, addr = sock.recvfrom(65535)
                    packet = self._parse_packet(raw_packet)
                    
                    if packet:
                        self.packets.append(packet)
                        self._update_stats(packet)
                        self._check_suspicious_activity(packet)
                        
                        if self.verbose:
                            self._print_packet_summary(packet)
                        
                        packet_count += 1
                        
                        if self.save_file and packet_count % 100 == 0:
                            self._save_capture()
                
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.debug(f"Error capturing packet: {e}")
            
        finally:
            sock.close()
        
        self.stats.end_time = datetime.now().isoformat()
        self.stats.duration = time.time() - start_time
        
        self.logger.info(f"Capture completed. Total packets: {packet_count}")
    
    def _simulate_capture(self, duration: int):
        """Simulate packet capture for testing/demo"""
        import random
        
        self.logger.info("Running simulation mode...")
        
        start_time = time.time()
        source_ips = [f"192.168.1.{i}" for i in range(2, 100)]
        dest_ips = ["10.0.0.5", "10.0.0.10", "8.8.8.8", "1.1.1.1"]
        protocols = ["TCP", "UDP", "HTTP", "DNS", "HTTPS"]
        
        while self.running and (time.time() - start_time) < duration:
            if random.random() < 0.3:
                packet = Packet(
                    timestamp=datetime.now().isoformat(),
                    source_ip=random.choice(source_ips),
                    destination_ip=random.choice(dest_ips),
                    source_port=random.randint(1024, 65000),
                    destination_port=random.choice([80, 443, 53, 22, 8080]),
                    protocol=random.choice(protocols),
                    length=random.randint(64, 1500),
                    payload="" if random.random() < 0.7 else "test data",
                    flags="SYN" if random.random() < 0.1 else "",
                    info=f"TCP {random.randint(1024, 65000)} -> {random.choice([80, 443, 53])}"
                )
                
                self.packets.append(packet)
                self._update_stats(packet)
                
                if self.verbose:
                    self._print_packet_summary(packet)
            
            time.sleep(0.1)
        
        self.stats.end_time = datetime.now().isoformat()
        self.stats.duration = time.time() - start_time
        
        self.logger.info(f"Simulation completed. Packets: {len(self.packets)}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        self.logger.info("Stopping packet capture...")
        
        if self.save_file:
            self._save_capture()
    
    def _save_capture(self):
        """Save captured packets to file"""
        if not self.save_file:
            return
        
        data = {
            "capture_info": {
                "start_time": self.stats.start_time,
                "end_time": self.stats.end_time,
                "total_packets": len(self.packets),
                "interface": self.interface,
                "filter": self.capture_filter
            },
            "statistics": self.stats.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "packets": [p.to_dict() for p in self.packets]
        }
        
        with open(self.save_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Capture saved to {self.save_file}")
    
    def analyze_capture(self, capture_file: str):
        """Analyze saved capture file"""
        self.logger.info(f"Analyzing capture file: {capture_file}")
        
        with open(capture_file, 'r') as f:
            data = json.load(f)
        
        self.packets = [Packet(**p) for p in data.get("packets", [])]
        self.alerts = [Alert(**a) for a in data.get("alerts", [])]
        
        for packet in self.packets:
            self._update_stats(packet)
        
        self.stats.start_time = data.get("capture_info", {}).get("start_time", "")
        self.stats.end_time = data.get("capture_info", {}).get("end_time", "")
        self.stats.total_packets = len(self.packets)
        self.stats.suspicious_packets = len(self.alerts)
        
        return self.stats, self.alerts
    
    def print_statistics(self):
        """Print capture statistics"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}CAPTURE STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Duration: {self.stats.duration:.2f}s")
        print(f"Total Packets: {self.stats.total_packets:,}")
        print(f"Total Bytes: {self.stats.total_bytes:,}")
        print(f"Suspicious Packets: {self.stats.suspicious_packets}\n")
        
        print("Protocol Distribution:")
        for proto, count in sorted(self.stats.protocol_distribution.items(), 
                                   key=lambda x: -x[1])[:5]:
            print(f"  {proto}: {count}")
        
        print("\nTop Source IPs:")
        for ip, count in list(self.stats.top_source_ips.items())[:5]:
            print(f"  {ip}: {count}")
        
        print("\nTop Destination Ports:")
        for port, count in sorted(self.stats.top_ports.items(), key=lambda x: -x[1])[:5]:
            print(f"  {port}: {count}")
        
        if self.alerts:
            print(f"\n{Fore.RED}Security Alerts: {len(self.alerts)}{Style.RESET_ALL}\n")
            
            for alert in sorted(self.alerts, 
                               key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)):
                severity_color = {
                    "CRITICAL": Fore.RED,
                    "HIGH": Fore.ORANGE,
                    "MEDIUM": Fore.YELLOW,
                    "LOW": Fore.BLUE,
                    "INFO": Fore.GREEN
                }.get(alert.severity, Fore.WHITE)
                
                print(f"{severity_color}[{alert.severity}]{Style.RESET_ALL} {alert.description}")
                print(f"  {alert.source_ip} -> {alert.destination_ip}")
                if alert.evidence:
                    print(f"  Evidence: {alert.evidence[:100]}")
                print()
    
    def save_results(self, filename: str = "capture_results.json"):
        """Save all results"""
        data = {
            "statistics": self.stats.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "packets": [p.to_dict() for p in self.packets[:1000]]  # Limit packets
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Results saved to {filename}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer and Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i eth0 -d 60
  %(prog)s -i eth0 --verbose -o capture.json
  %(prog)s --analyze capture.json
  %(prog)s -i wlan0 --filter "port 80"
        """
    )
    
    parser.add_argument('-i', '--interface', help="Network interface to capture on")
    parser.add_argument('-d', '--duration', type=int, default=60,
                       help="Capture duration in seconds (default: 60)")
    parser.add_argument('-o', '--output', help="Output file for saving capture")
    parser.add_argument('--filter', help="BPF filter expression")
    parser.add_argument('--analyze', help="Analyze existing capture file")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--no-color', action='store_true',
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.no_color:
        colorama.deinit()
    
    sniffer = PacketSniffer(
        interface=args.interface,
        verbose=args.verbose,
        capture_filter=args.filter,
        save_file=args.output
    )
    
    if args.analyze:
        stats, alerts = sniffer.analyze_capture(args.analyze)
        sniffer.print_statistics()
        sniffer.save_results()
    else:
        sniffer.start_capture(duration=args.duration)
        sniffer.print_statistics()
        if args.output:
            sniffer._save_capture()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
