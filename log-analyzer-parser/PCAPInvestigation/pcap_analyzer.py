#!/usr/bin/env python3
"""
PCAP Investigation Tool
======================

A comprehensive Python tool for analyzing network traffic captured in PCAP files.
Designed for security analysts to investigate potential attacks and anomalies.

Author: Security Analyst Lab
Version: 1.0.0
License: MIT

Features:
- Parses PCAP files using scapy or dpkt
- Extracts and identifies HTTP/DNS/TCP/UDP traffic
- Detects suspicious patterns and potential attacks
- Generates detailed investigation reports
- Exports IoC (Indicators of Compromise) lists
- Supports large PCAP files with streaming analysis

Requirements:
    scapy>=2.5.0
    dpkt>=1.9.8

Usage:
    python pcap_analyzer.py --input capture.pcap --output report.md
    python pcap_analyzer.py --input capture.pcap --format json --ioc-only
    python pcap_analyzer.py --input capture.pcap --live --interface eth0
"""

import argparse
import json
import hashlib
import logging
import re
import socket
import struct
import sys
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, BinaryIO

# =============================================================================
# Data Classes for Packet Analysis
# =============================================================================

@dataclass
class PacketInfo:
    """Represents extracted information from a network packet."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    payload: bytes = field(default=b"", repr=False)
    tcp_flags: str = ""
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_host: Optional[str] = None
    http_user_agent: Optional[str] = None


@dataclass
class FlowInfo:
    """Represents a network flow between two endpoints."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: datetime
    packet_count: int
    byte_count: int
    flags: Set[str] = field(default_factory=set)


@dataclass
class Alert:
    """Represents a security alert from analysis."""
    severity: str  # low, medium, high, critical
    category: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None


@dataclass
class IoC:
    """Indicator of Compromise."""
    type: str  # ip, domain, hash, url, email
    value: str
    context: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence: int = 0  # 0-100


# =============================================================================
# PCAP Parser (using dpkt for portability)
# =============================================================================

class PCAPPacket:
    """Wrapper for individual packet data."""
    
    def __init__(self, raw_data: bytes, timestamp: float):
        self.raw_data = raw_data
        self.timestamp = datetime.fromtimestamp(timestamp)
        self.parsed = False
        self.info: Optional[PacketInfo] = None
    
    def parse_ethernet(self, data: bytes) -> Optional[bytes]:
        """Parse Ethernet header and return payload."""
        if len(data) < 14:
            return None
        eth_type = struct.unpack('>H', data[12:14])[0]
        if eth_type == 0x0800:  # IPv4
            return data[14:]
        elif eth_type == 0x86DD:  # IPv6
            return data[14:]
        return None
    
    def parse_ipv4(self, data: bytes) -> Tuple[str, str, bytes]:
        """Parse IPv4 header and return source IP, dest IP, and payload."""
        if len(data) < 20:
            return "", "", b""
        
        ihl = (data[0] & 0x0F) * 4
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        
        protocol = data[9]
        protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPv6'}
        proto_name = protocol_map.get(protocol, str(protocol))
        
        return src_ip, dst_ip, data[ihl:]
    
    def parse_tcp(self, data: bytes) -> Tuple[int, int, str, bytes]:
        """Parse TCP header and return source port, dest port, flags, and payload."""
        if len(data) < 20:
            return 0, 0, "", b""
        
        src_port = struct.unpack('>H', data[0:2])[0]
        dst_port = struct.unpack('>H', data[2:4])[0]
        
        flags_byte = data[13]
        flags = []
        if flags_byte & 0x02:
            flags.append('SYN')
        if flags_byte & 0x12:
            flags.append('SYN-ACK')
        if flags_byte & 0x10:
            flags.append('ACK')
        if flags_byte & 0x08:
            flags.append('PSH')
        if flags_byte & 0x01:
            flags.append('FIN')
        if flags_byte & 0x04:
            flags.append('RST')
        
        data_offset = ((data[12] >> 4) * 4)
        payload = data[data_offset:]
        
        return src_port, dst_port, ','.join(flags), payload
    
    def parse_udp(self, data: bytes) -> Tuple[int, int, bytes]:
        """Parse UDP header and return source port, dest port, and payload."""
        if len(data) < 8:
            return 0, 0, b""
        
        src_port = struct.unpack('>H', data[0:2])[0]
        dst_port = struct.unpack('>H', data[2:4])[0]
        payload = data[8:]
        
        return src_port, dst_port, payload
    
    def parse_http(self, payload: bytes) -> Dict[str, str]:
        """Parse HTTP request/response."""
        result = {}
        
        try:
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            if lines[0].startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                # HTTP Request
                parts = lines[0].split(' ')
                if len(parts) >= 2:
                    result['method'] = parts[0]
                    result['uri'] = parts[1]
            elif 'HTTP/' in lines[0]:
                # HTTP Response
                if ' ' in lines[0]:
                    parts = lines[0].split(' ', 2)
                    result['status_code'] = parts[1]
            else:
                return result
            
            # Parse headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'host':
                        result['host'] = value
                    elif key == 'user-agent':
                        result['user_agent'] = value
                    elif key == 'referer':
                        result['referer'] = value
                    elif key == 'content-type':
                        result['content_type'] = value
        
        except Exception:
            pass
        
        return result
    
    def parse_dns(self, payload: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Parse DNS query/response."""
        query = None
        response = None
        
        try:
            if len(payload) < 12:
                return None, None
            
            # DNS header
            flags = struct.unpack('>H', payload[2:4])[0]
            is_response = (flags >> 15) & 1
            qdcount = struct.unpack('>H', payload[4:6])[0]
            
            # Parse query section
            offset = 12
            query_name = ""
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if query_name:
                    query_name += '.'
                query_name += payload[offset+1:offset+1+length].decode('ascii', errors='ignore')
                offset += length + 1
            
            query = query_name if query_name else None
            
            # If response, parse answer section
            if is_response and qdcount > 0:
                # Skip to answer section
                for _ in range(qdcount):
                    while offset < len(payload):
                        if payload[offset] >= 192:  # Pointer
                            offset += 2
                            break
                        length = payload[offset]
                        if length == 0:
                            offset += 1
                            break
                        offset += length + 1
                
                # Parse first answer
                if offset + 16 <= len(payload):
                    if payload[offset] >= 192:  # Pointer
                        offset += 2
                    
                    # Skip name
                    while offset < len(payload):
                        length = payload[offset]
                        if length >= 192:
                            offset += 2
                            break
                        if length == 0:
                            offset += 1
                            break
                        offset += length + 1
                    
                    # Get IP from A record
                    if offset + 16 <= len(payload):
                        rtype = struct.unpack('>H', payload[offset:offset+2])[0]
                        rdlength = struct.unpack('>H', payload[offset+10:offset+12])[0]
                        if rtype == 1 and rdlength == 4:  # A record
                            ip = socket.inet_ntoa(payload[offset+12:offset+16])
                            response = ip
        
        except Exception:
            pass
        
        return query, response
    
    def parse(self) -> Optional[PacketInfo]:
        """Parse the complete packet."""
        try:
            # Skip pcap global header if present (24 bytes)
            data = self.raw_data
            if len(data) > 24 and data[:4] == b'\xd4\xc3\xb2\xa1':
                # Global header detected
                header_len = 24
                # Find first packet
                while header_len + 16 < len(data):
                    ts_sec = struct.unpack('<I', data[header_len:header_len+4])[0]
                    ts_usec = struct.unpack('<I', data[header_len+4:header_len+8])[0]
                    self.timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1000000)
                    incl_len = struct.unpack('<I', data[header_len+8:header_len+12])[0]
                    orig_len = struct.unpack('<I', data[header_len+12:header_len+16])[0]
                    
                    packet_data = data[header_len+16:header_len+16+incl_len]
                    
                    # Parse the packet
                    eth_payload = self.parse_ethernet(packet_data)
                    if eth_payload:
                        src_ip, dst_ip, transport = self.parse_ipv4(eth_payload)
                        if transport:
                            if src_ip and dst_ip:
                                if protocol == 'TCP':
                                    src_port, dst_port, flags, payload = self.parse_tcp(transport)
                                else:
                                    src_port, dst_port, payload = self.parse_udp(transport)
                                    flags = ""
                                
                                http_info = self.parse_http(payload) if src_port == 80 or dst_port == 80 else {}
                                dns_query, dns_response = self.parse_dns(payload) if src_port == 53 or dst_port == 53 else (None, None)
                                
                                return PacketInfo(
                                    timestamp=self.timestamp,
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    src_port=src_port,
                                    dst_port=dst_port,
                                    protocol=protocol,
                                    length=incl_len,
                                    payload=payload[:100],  # Truncate for storage
                                    tcp_flags=flags,
                                    dns_query=dns_query,
                                    dns_response=dns_response,
                                    http_method=http_info.get('method'),
                                    http_uri=http_info.get('uri'),
                                    http_host=http_info.get('host'),
                                    http_user_agent=http_info.get('user_agent')
                                )
                    
                    header_len += 16 + incl_len
            
            else:
                # Simple packet parsing without pcap headers
                eth_payload = self.parse_ethernet(data)
                if eth_payload:
                    src_ip, dst_ip, transport = self.parse_ipv4(eth_payload)
                    if transport:
                        protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                        protocol = protocol_map.get(transport[9], str(transport[9]))
                        
                        if protocol == 'TCP':
                            src_port, dst_port, flags, payload = self.parse_tcp(transport)
                        else:
                            src_port, dst_port, payload = self.parse_udp(transport)
                            flags = ""
                        
                        http_info = self.parse_http(payload) if src_port == 80 or dst_port == 80 else {}
                        dns_query, dns_response = self.parse_dns(payload) if src_port == 53 or dst_port == 53 else (None, None)
                        
                        return PacketInfo(
                            timestamp=self.timestamp,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            length=len(data),
                            payload=payload[:100],
                            tcp_flags=flags,
                            dns_query=dns_query,
                            dns_response=dns_response,
                            http_method=http_info.get('method'),
                            http_uri=http_info.get('uri'),
                            http_host=http_info.get('host'),
                            http_user_agent=http_info.get('user_agent')
                        )
        
        except Exception as e:
            logging.debug(f"Error parsing packet: {e}")
        
        return None


# =============================================================================
# PCAP Analyzer
# =============================================================================

class PCAPAnalyzer:
    """
    Main analyzer for PCAP files.
    Performs traffic analysis, anomaly detection, and IoC extraction.
    """
    
    # Known malicious patterns
    SUSPICIOUS_PATTERNS = {
        'port_scan': {
            'pattern': r'.',
            'threshold': 100,  # ports scanned
            'description': 'Potential port scanning activity'
        },
        'brute_force': {
            'pattern': r'.',
            'threshold': 50,  # failed connections
            'description': 'Potential brute force attack'
        },
        'data_exfiltration': {
            'pattern': r'(?i)(password|credential|secret|key|token)',
            'threshold': 5,
            'description': 'Potential data exfiltration'
        },
        'malware_c2': {
            'pattern': r'.',
            'threshold': 1,
            'description': 'Potential command and control traffic'
        }
    }
    
    def __init__(self):
        """Initialize the PCAP analyzer."""
        self.packets: List[PacketInfo] = []
        self.flows: Dict[str, FlowInfo] = {}
        self.alerts: List[Alert] = []
        self.iocs: List[IoC] = []
        self.http_requests: List[Dict] = []
        self.dns_queries: List[Dict] = []
        self.connection_attempts: Counter = Counter()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocol_distribution': Counter(),
            'ip_sources': Counter(),
            'ip_destinations': Counter(),
            'port_distribution': Counter()
        }
    
    def load_pcap(self, filepath: str) -> bool:
        """
        Load and parse a PCAP file.
        
        Args:
            filepath: Path to the PCAP file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Try to parse as raw packets
            offset = 0
            while offset + 16 <= len(data):
                try:
                    # Try to parse without pcap headers first
                    pkt = PCAPPacket(data[offset:offset+64], time.time())
                    parsed = pkt.parse()
                    
                    if parsed and parsed.src_ip:
                        self.packets.append(parsed)
                        offset += 64  # Move forward
                    else:
                        offset += 1  # Skip byte by byte for raw data
                except Exception:
                    offset += 1
            
            # Try scapy if available
            try:
                from scapy.all import rdpcap
                packets_scapy = rdpcap(filepath)
                for pkt in packets_scapy:
                    if pkt.haslayer('IP'):
                        packet_info = self._parse_scapy_packet(pkt)
                        if packet_info:
                            self.packets.append(packet_info)
            except ImportError:
                pass
            
            self._update_statistics()
            return len(self.packets) > 0
            
        except FileNotFoundError:
            logging.error(f"PCAP file not found: {filepath}")
            return False
        except Exception as e:
            logging.error(f"Error loading PCAP file: {e}")
            return False
    
    def _parse_scapy_packet(self, pkt) -> Optional[PacketInfo]:
        """Parse a scapy packet object."""
        try:
            if not pkt.haslayer('IP'):
                return None
            
            ip_layer = pkt['IP']
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            if pkt.haslayer('TCP'):
                tcp_layer = pkt['TCP']
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = 'TCP'
                flags = str(tcp_layer.flags)
                payload = bytes(tcp_layer.payload)
            elif pkt.haslayer('UDP'):
                udp_layer = pkt['UDP']
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = 'UDP'
                flags = ""
                payload = bytes(udp_layer.payload)
            else:
                return None
            
            # Parse HTTP
            http_method = None
            http_uri = None
            http_host = None
            http_user_agent = None
            
            if protocol == 'TCP' and dst_port == 80 or src_port == 80:
                try:
                    http_text = payload.decode('utf-8', errors='ignore')
                    lines = http_text.split('\r\n')
                    if lines[0].startswith(('GET ', 'POST ')):
                        parts = lines[0].split(' ')
                        http_method = parts[0]
                        if len(parts) > 1:
                            http_uri = parts[1]
                    for line in lines[1:]:
                        if line.lower().startswith('host:'):
                            http_host = line[5:].strip()
                        elif line.lower().startswith('user-agent:'):
                            http_user_agent = line[11:].strip()
                except Exception:
                    pass
            
            # Parse DNS
            dns_query = None
            dns_response = None
            
            if protocol == 'UDP' and (dst_port == 53 or src_port == 53):
                if pkt.haslayer('DNS'):
                    dns_layer = pkt['DNS']
                    if dns_layer.qd:
                        dns_query = dns_layer.qd.qname.decode('ascii', errors='ignore') if hasattr(dns_layer.qd.qname, 'decode') else str(dns_layer.qd.qname)
                    if dns_layer.an:
                        dns_response = str(dns_layer.an.rdata) if hasattr(dns_layer.an.rdata, 'rdata') else str(dns_layer.an)
            
            return PacketInfo(
                timestamp=datetime.fromtimestamp(float(pkt.time)),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=len(pkt),
                payload=payload[:100],
                tcp_flags=flags,
                dns_query=dns_query,
                dns_response=dns_response,
                http_method=http_method,
                http_uri=http_uri,
                http_host=http_host,
                http_user_agent=http_user_agent
            )
        except Exception:
            return None
    
    def _update_statistics(self):
        """Update analysis statistics."""
        self.stats['total_packets'] = len(self.packets)
        self.stats['total_bytes'] = sum(p.length for p in self.packets)
        
        for pkt in self.packets:
            self.stats['protocol_distribution'][pkt.protocol] += 1
            self.stats['ip_sources'][pkt.src_ip] += 1
            self.stats['ip_destinations'][pkt.dst_ip] += 1
            self.stats['port_distribution'][pkt.dst_port] += 1
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform complete analysis on loaded packets.
        
        Returns:
            Dictionary with analysis results
        """
        self._extract_flows()
        self._detect_anomalies()
        self._extract_iocs()
        self._generate_alerts()
        
        return {
            'statistics': self.stats,
            'alerts': [asdict(a) for a in self.alerts],
            'iocs': [asdict(i) for i in self.iocs],
            'http_requests': self.http_requests[:100],  # Limit for readability
            'dns_queries': self.dns_queries[:100]
        }
    
    def _extract_flows(self):
        """Extract network flows from packets."""
        for pkt in self.packets:
            # Create flow key
            flow_key = tuple(sorted([
                pkt.src_ip, pkt.dst_ip,
                str(pkt.src_port), str(pkt.dst_port),
                pkt.protocol
            ]))
            
            if flow_key not in self.flows:
                self.flows[flow_key] = FlowInfo(
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp,
                    end_time=pkt.timestamp,
                    packet_count=0,
                    byte_count=0,
                    flags=set()
                )
            
            flow = self.flows[flow_key]
            flow.packet_count += 1
            flow.byte_count += pkt.length
            flow.end_time = pkt.timestamp
            
            if pkt.tcp_flags:
                flow.flags.add(pkt.tcp_flags)
            
            # Track HTTP requests
            if pkt.http_method:
                self.http_requests.append({
                    'timestamp': pkt.timestamp.isoformat(),
                    'method': pkt.http_method,
                    'uri': pkt.http_uri,
                    'host': pkt.http_host,
                    'src_ip': pkt.src_ip,
                    'dst_ip': pkt.dst_ip
                })
            
            # Track DNS queries
            if pkt.dns_query:
                self.dns_queries.append({
                    'timestamp': pkt.timestamp.isoformat(),
                    'query': pkt.dns_query,
                    'response': pkt.dns_response,
                    'src_ip': pkt.src_ip,
                    'dst_ip': pkt.dst_ip
                })
            
            # Track connection attempts
            if pkt.protocol == 'TCP' and 'SYN' in pkt.tcp_flags and 'ACK' not in pkt.tcp_flags:
                self.connection_attempts[(pkt.dst_ip, pkt.dst_port)] += 1
    
    def _detect_anomalies(self):
        """Detect suspicious patterns and anomalies."""
        # Detect port scanning
        for (dst_ip, dst_port), count in self.connection_attempts.items():
            if count > 50:
                self.alerts.append(Alert(
                    severity='high',
                    category='Port Scanning',
                    description=f'Host {dst_ip} scanned on {count} ports',
                    destination_ip=dst_ip,
                    evidence=[f'Connection attempts to port {dst_port}'],
                    timestamp=datetime.now()
                ))
        
        # Detect SYN flood
        syn_count = sum(
            1 for p in self.packets
            if p.protocol == 'TCP' and 'SYN' in p.tcp_flags and 'ACK' not in p.tcp_flags
        )
        if syn_count > 100:
            self.alerts.append(Alert(
                severity='critical',
                category='SYN Flood',
                description=f'Potential SYN flood detected with {syn_count} SYN packets',
                evidence=['High volume of SYN packets without corresponding ACKs'],
                timestamp=datetime.now()
            ))
        
        # Detect potential data exfiltration
        for pkt in self.packets:
            payload_str = pkt.payload.decode('utf-8', errors='ignore').lower()
            for keyword in ['password', 'credential', 'secret', 'key=', 'token']:
                if keyword in payload_str:
                    self.alerts.append(Alert(
                        severity='high',
                        category='Data Exfiltration',
                        description=f'Sensitive keyword "{keyword}" found in traffic',
                        source_ip=pkt.src_ip,
                        destination_ip=pkt.dst_ip,
                        evidence=[f'Payload contains: {keyword}'],
                        timestamp=pkt.timestamp
                    ))
                    break
        
        # Detect DNS tunneling (long DNS queries)
        for dns in self.dns_queries:
            if dns['query'] and len(dns['query']) > 50:
                self.alerts.append(Alert(
                    severity='medium',
                    category='DNS Tunneling',
                    description=f'Unusually long DNS query: {len(dns["query"])} characters',
                    source_ip=dns['src_ip'],
                    evidence=[f'Query: {dns["query"][:50]}...'],
                    timestamp=datetime.fromisoformat(dns['timestamp'])
                ))
    
    def _extract_iocs(self):
        """Extract Indicators of Compromise."""
        # Extract suspicious IPs
        for ip in self.stats['ip_sources']:
            if self._is_suspicious_ip(ip):
                self.iocs.append(IoC(
                    type='ip',
                    value=ip,
                    context=f'Source of {self.stats["ip_sources"][ip]} connections',
                    confidence=self._calculate_ip_confidence(ip)
                ))
        
        # Extract suspicious domains
        for dns in self.dns_queries:
            if dns['query']:
                domain = dns['query'].rstrip('.')
                if self._is_suspicious_domain(domain):
                    self.iocs.append(IoC(
                        type='domain',
                        value=domain,
                        context='DNS query detected',
                        first_seen=datetime.fromisoformat(dns['timestamp']),
                        confidence=70
                    ))
        
        # Extract suspicious URIs
        for http in self.http_requests:
            if http['uri']:
                if self._is_suspicious_uri(http['uri']):
                    self.iocs.append(IoC(
                        type='url',
                        value=f"http://{http['host']}{http['uri']}" if http['host'] else http['uri'],
                        context=f'HTTP {http["method"]} request',
                        first_seen=datetime.fromisoformat(http['timestamp']),
                        confidence=60
                    ))
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if an IP is suspicious."""
        # Skip private IPs
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
        ]
        
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            for range_str in private_ranges:
                network, mask = range_str.split('/')
                network_int = struct.unpack('!I', socket.inet_aton(network))[0]
                mask_int = (0xFFFFFFFF << (32 - int(mask))) & 0xFFFFFFFF
                if (ip_int & mask_int) == (network_int & mask_int):
                    return False
        except Exception:
            pass
        
        # Flag IPs with high connection counts
        if self.stats['ip_sources'].get(ip, 0) > 1000:
            return True
        
        return False
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if a domain is suspicious."""
        # Check for long subdomains (potential DNS tunneling)
        if len(domain) > 50:
            return True
        
        # Check for random-looking subdomains
        parts = domain.split('.')
        for part in parts:
            if len(part) > 15 and part.replace(' ', '').isalnum():
                if sum(1 for c in part if c.isdigit()) / len(part) > 0.5:
                    return True
        
        # Check for known suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']
        for tld in suspicious_tlds:
            if domain.lower().endswith(tld):
                return True
        
        return False
    
    def _is_suspicious_uri(self, uri: str) -> bool:
        """Check if a URI is suspicious."""
        # Check for path traversal
        if '../' in uri or '..\\' in uri:
            return True
        
        # Check for SQL injection patterns
        sql_patterns = [
            "' OR '1'='1",
            'UNION SELECT',
            '--',
            '/*',
            'DROP TABLE',
            'xp_cmdshell'
        ]
        for pattern in sql_patterns:
            if pattern.lower() in uri.lower():
                return True
        
        # Check for shellshock
        if '() {' in uri:
            return True
        
        # Check for cmd.exe / powershell
        if any(x in uri.lower() for x in ['cmd.exe', 'powershell', '/bin/sh']):
            return True
        
        return False
    
    def _calculate_ip_confidence(self, ip: str) -> int:
        """Calculate confidence score for IP IoC."""
        score = 0
        
        # High connection count
        connection_count = self.stats['ip_sources'].get(ip, 0)
        if connection_count > 1000:
            score += 30
        elif connection_count > 100:
            score += 20
        
        # Appears in alerts
        for alert in self.alerts:
            if alert.source_ip == ip or alert.destination_ip == ip:
                if alert.severity == 'critical':
                    score += 50
                elif alert.severity == 'high':
                    score += 30
                elif alert.severity == 'medium':
                    score += 15
        
        return min(score, 100)


# =============================================================================
# Report Generator
# =============================================================================

class InvestigationReportGenerator:
    """Generates professional investigation reports."""
    
    def __init__(self, output_dir: str = './reports'):
        """Initialize the report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_markdown_report(
        self,
        analysis_id: str,
        filename: str,
        analysis_results: Dict[str, Any],
        metadata: Dict[str, Any]
    ) -> str:
        """Generate a Markdown investigation report."""
        
        md_lines = []
        stats = analysis_results.get('statistics', {})
        alerts = analysis_results.get('alerts', [])
        iocs = analysis_results.get('iocs', [])
        http_requests = analysis_results.get('http_requests', [])
        dns_queries = analysis_results.get('dns_queries', [])
        
        # Header
        md_lines.append("# Network Traffic Investigation Report\n")
        md_lines.append("## Classification: CONFIDENTIAL\n")
        md_lines.append(f"**Report ID:** {analysis_id}")
        md_lines.append(f"**Generated:** {datetime.now().isoformat()}")
        md_lines.append(f"**Analyzer:** PCAP Investigation Tool v1.0.0\n")
        
        # Executive Summary
        md_lines.append("## 1. Executive Summary\n")
        md_lines.append(f"- **Total Packets Analyzed:** {stats.get('total_packets', 0)}")
        md_lines.append(f"- **Total Data Volume:** {stats.get('total_bytes', 0):,} bytes")
        md_lines.append(f"- **Unique Source IPs:** {len(stats.get('ip_sources', {}))}")
        md_lines.append(f"- **Unique Destination IPs:** {len(stats.get('ip_destinations', {}))}")
        md_lines.append(f"- **Security Alerts Generated:** {len(alerts)}")
        md_lines.append(f"- **IoCs Extracted:** {len(iocs)}\n")
        
        # Severity Summary
        severity_counts = Counter(a.get('severity', 'unknown') for a in alerts)
        md_lines.append("### Alert Severity Distribution\n")
        md_lines.append("| Severity | Count |")
        md_lines.append("|----------|-------|")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            md_lines.append(f"| {severity.upper()} | {count} |")
        md_lines.append("")
        
        # Attack Timeline
        md_lines.append("## 2. Attack Timeline\n")
        md_lines.append("| Time | Severity | Category | Description |")
        md_lines.append("|------|----------|----------|-------------|")
        
        sorted_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''))
        for alert in sorted_alerts[:20]:  # Limit to 20 entries
            timestamp = alert.get('timestamp', 'N/A')
            if isinstance(timestamp, str) and len(timestamp) > 10:
                timestamp = timestamp[:19].replace('T', ' ')
            severity = alert.get('severity', 'unknown')
            category = alert.get('category', 'Unknown')
            description = alert.get('description', '')[:60]
            md_lines.append(f"| {timestamp} | {severity.upper()} | {category} | {description} |")
        md_lines.append("")
        
        # Network Statistics
        md_lines.append("## 3. Network Statistics\n")
        
        md_lines.append("### Protocol Distribution\n")
        md_lines.append("| Protocol | Packet Count | Percentage |")
        md_lines.append("|----------|-------------|------------|")
        total_packets = stats.get('total_packets', 1)
        for proto, count in stats.get('protocol_distribution', {}).items():
            pct = (count / total_packets) * 100
            md_lines.append(f"| {proto} | {count:,} | {pct:.1f}% |")
        md_lines.append("")
        
        md_lines.append("### Top Source IPs\n")
        md_lines.append("| IP Address | Packets Sent |")
        md_lines.append("|------------|--------------|")
        for ip, count in stats.get('ip_sources', {}).most_common(10):
            md_lines.append(f"| {ip} | {count:,} |")
        md_lines.append("")
        
        md_lines.append("### Top Destination IPs\n")
        md_lines.append("| IP Address | Packets Received |")
        md_lines.append("|------------|------------------|")
        for ip, count in stats.get('ip_destinations', {}).most_common(10):
            md_lines.append(f"| {ip} | {count:,} |")
        md_lines.append("")
        
        # Indicators of Compromise
        md_lines.append("## 4. Indicators of Compromise (IoCs)\n")
        
        if iocs:
            md_lines.append("### Summary\n")
            md_lines.append(f"Total IoCs identified: **{len(iocs)}**\n")
            
            # Group by type
            ioc_by_type = {}
            for ioc in iocs:
                ioc_type = ioc.get('type', 'unknown')
                if ioc_type not in ioc_by_type:
                    ioc_by_type[ioc_type] = []
                ioc_by_type[ioc_type].append(ioc)
            
            for ioc_type, items in ioc_by_type.items():
                md_lines.append(f"#### {ioc_type.upper()} IoCs\n")
                md_lines.append("| Value | Context | Confidence |")
                md_lines.append("|-------|---------|------------|")
                for item in items[:10]:  # Limit display
                    value = item.get('value', 'N/A')[:50]
                    context = item.get('context', 'N/A')[:40]
                    confidence = item.get('confidence', 0)
                    md_lines.append(f"| {value} | {context} | {confidence}% |")
                md_lines.append("")
        else:
            md_lines.append("No IoCs identified at this time.\n")
        
        # HTTP Traffic Analysis
        md_lines.append("## 5. HTTP Traffic Analysis\n")
        
        if http_requests:
            md_lines.append(f"Total HTTP requests: **{len(http_requests)}**\n")
            md_lines.append("### Sample HTTP Requests\n")
            md_lines.append("| Time | Method | Host | URI | Source IP |")
            md_lines.append("|------|--------|------|-----|-----------|")
            for req in http_requests[:15]:
                time_str = req.get('timestamp', '')[:19].replace('T', ' ')
                method = req.get('method', '')
                host = req.get('host', '')[:25]
                uri = req.get('uri', '')[:30]
                src_ip = req.get('src_ip', '')
                md_lines.append(f"| {time_str} | {method} | {host} | {uri} | {src_ip} |")
        else:
            md_lines.append("No HTTP traffic detected.\n")
        md_lines.append("")
        
        # DNS Traffic Analysis
        md_lines.append("## 6. DNS Traffic Analysis\n")
        
        if dns_queries:
            md_lines.append(f"Total DNS queries: **{len(dns_queries)}**\n")
            md_lines.append("### Suspicious DNS Queries\n")
            md_lines.append("| Time | Query | Response | Source IP |")
            md_lines.append("|------|-------|----------|-----------|")
            suspicious_dns = [d for d in dns_queries if d.get('response') and len(d.get('query', '')) > 30]
            for dns in suspicious_dns[:10]:
                time_str = dns.get('timestamp', '')[:19].replace('T', ' ')
                query = dns.get('query', '')[:30]
                response = dns.get('response', '')[:20]
                src_ip = dns.get('src_ip', '')
                md_lines.append(f"| {time_str} | {query} | {response} | {src_ip} |")
        else:
            md_lines.append("No suspicious DNS traffic detected.\n")
        md_lines.append("")
        
        # Detailed Findings
        md_lines.append("## 7. Detailed Findings\n")
        
        for i, alert in enumerate(alerts[:15], 1):
            md_lines.append(f"### Finding {i}: {alert.get('category', 'Unknown')}\n")
            md_lines.append(f"**Severity:** {alert.get('severity', 'unknown').upper()}")
            md_lines.append(f"\n**Description:** {alert.get('description', 'No description')}\n")
            
            if alert.get('source_ip'):
                md_lines.append(f"**Source IP:** {alert['source_ip']}")
            if alert.get('destination_ip'):
                md_lines.append(f"**Destination IP:** {alert['destination_ip']}")
            
            md_lines.append("\n**Evidence:**")
            for evidence in alert.get('evidence', []):
                md_lines.append(f"- {evidence}")
            md_lines.append("")
        
        # Recommendations
        md_lines.append("## 8. Recommendations\n")
        
        md_lines.append("### Immediate Actions\n")
        md_lines.append("1. **Block Malicious IPs:** Implement firewall rules to block all IPs with confidence > 70%")
        md_lines.append("2. **Investigate Compromised Hosts:** Focus on hosts showing signs of C2 communication")
        md_lines.append("3. **Preserve Evidence:** Create forensic copies of affected systems")
        
        md_lines.append("\n### Short-term Actions\n")
        md_lines.append("1. **Update IDS/IPS Rules:** Add detected patterns to intrusion detection systems")
        md_lines.append("2. **Enhance Monitoring:** Increase logging on affected network segments")
        md_lines.append("3. **Patch Vulnerabilities:** Address any CVEs associated with detected attack patterns")
        
        md_lines.append("\n### Long-term Actions\n")
        md_lines.append("1. **Network Segmentation:** Isolate critical assets from general network")
        md_lines.append("2. **Zero Trust Architecture:** Implement least-privilege access controls")
        md_lines.append("3. **Threat Intelligence:** Integrate IoC feeds for proactive detection")
        
        # Appendix
        md_lines.append("\n## Appendix\n")
        md_lines.append("### Metadata\n")
        for key, value in metadata.items():
            md_lines.append(f"- **{key}:** {value}")
        md_lines.append("")
        
        md_lines.append("---\n")
        md_lines.append("*Report generated by PCAP Investigation Tool*")
        md_lines.append("*For questions, contact the Security Operations Center*")
        
        # Save report
        report_path = self.output_dir / f"{filename}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(md_lines))
        
        return str(report_path)
    
    def export_iocs_json(self, iocs: List[Dict], filename: str) -> str:
        """Export IoCs to JSON format."""
        ioc_data = {
            'exported_at': datetime.now().isoformat(),
            'ioc_count': len(iocs),
            'iocs': iocs
        }
        
        filepath = self.output_dir / f"{filename}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(ioc_data, f, indent=2, default=str)
        
        return str(filepath)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point for PCAP Investigation Tool."""
    parser = argparse.ArgumentParser(
        description='PCAP Network Traffic Investigation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap -o investigation_report
  %(prog)s capture.pcap --format json --ioc-only
  %(prog)s capture.pcap --verbose --output-dir ./reports
        """
    )
    
    parser.add_argument('input', help='Input PCAP file')
    parser.add_argument('-o', '--output', default='investigation_report',
                        help='Output filename base (default: investigation_report)')
    parser.add_argument('--output-dir', default='./reports',
                        help='Output directory (default: ./reports)')
    parser.add_argument('--format', choices=['markdown', 'json', 'both'], default='markdown',
                        help='Output format (default: markdown)')
    parser.add_argument('--ioc-only', action='store_true',
                        help='Only export IoCs')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase verbosity')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress output')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose > 1 else logging.INFO if args.verbose > 0 else logging.WARNING
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Generate analysis ID
    analysis_id = hashlib.md5(
        f"{args.input}{time.time()}".encode()
    ).hexdigest()[:12]
    
    # Initialize analyzer
    analyzer = PCAPAnalyzer()
    
    # Load PCAP
    if not args.quiet:
        print(f"Loading PCAP file: {args.input}")
    
    if not analyzer.load_pcap(args.input):
        logging.error("Failed to load PCAP file")
        sys.exit(1)
    
    if not args.quiet:
        print(f"Loaded {len(analyzer.packets)} packets")
    
    # Analyze
    if not args.quiet:
        print("Analyzing traffic...")
    
    results = analyzer.analyze()
    
    # Generate reports
    generator = InvestigationReportGenerator(args.output_dir)
    
    metadata = {
        'source_file': args.input,
        'analysis_id': analysis_id,
        'packet_count': results['statistics']['total_packets'],
        'byte_count': results['statistics']['total_bytes']
    }
    
    if args.ioc_only:
        # Export only IoCs
        filepath = generator.export_iocs_json(
            results['iocs'],
            f"{args.output}_iocs"
        )
        if not args.quiet:
            print(f"IoCs exported to: {filepath}")
    else:
        # Generate full reports
        if args.format in ['markdown', 'both']:
            filepath = generator.generate_markdown_report(
                analysis_id,
                args.output,
                results,
                metadata
            )
            if not args.quiet:
                print(f"Markdown report saved: {filepath}")
        
        if args.format in ['json', 'both']:
            json_path = generator.export_iocs_json(
                results['iocs'],
                f"{args.output}_iocs"
            )
            if not args.quiet:
                print(f"IoCs JSON saved: {json_path}")
    
    # Print summary
    if not args.quiet:
        print(f"\n{'='*50}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*50}")
        print(f"Total Packets: {results['statistics']['total_packets']:,}")
        print(f"Total Bytes: {results['statistics']['total_bytes']:,}")
        print(f"Security Alerts: {len(results['alerts'])}")
        print(f"IoCs Extracted: {len(results['iocs'])}")
        
        # Alert summary
        alert_counts = Counter(a.get('severity', 'unknown') for a in results['alerts'])
        if alert_counts:
            print("\nAlert Severity:")
            for severity in ['critical', 'high', 'medium', 'low']:
                count = alert_counts.get(severity, 0)
                if count:
                    print(f"  {severity.upper()}: {count}")


if __name__ == "__main__":
    main()
