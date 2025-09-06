#!/usr/bin/env python3
"""
Network Packet Analyzer
A tool for capturing and analyzing network traffic for educational and security testing purposes.
"""

import sys
import socket
import struct
import time
from datetime import datetime
from collections import defaultdict
import argparse

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

class NetworkAnalyzer:
    def __init__(self, interface=None, filter_expr=None, packet_count=0):
        self.interface = interface
        self.filter_expr = filter_expr
        self.packet_count = packet_count
        self.captured_packets = []
        self.stats = defaultdict(int)
        self.start_time = None
        
    def packet_handler(self, packet):
        """Process captured packets"""
        if self.start_time is None:
            self.start_time = time.time()
            
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Basic packet info
        packet_info = {
            'timestamp': timestamp,
            'length': len(packet),
            'protocol': 'Unknown'
        }
        
        # Update statistics
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += len(packet)
        
        if IP in packet:
            ip_layer = packet[IP]
            packet_info.update({
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'ttl': ip_layer.ttl
            })
            
            # Protocol-specific analysis
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info.update({
                    'protocol': 'TCP',
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': self.get_tcp_flags(tcp_layer.flags),
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack
                })
                self.stats['tcp_packets'] += 1
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info.update({
                    'protocol': 'UDP',
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'length': udp_layer.len
                })
                self.stats['udp_packets'] += 1
                
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'protocol': 'ICMP',
                    'type': icmp_layer.type,
                    'code': icmp_layer.code
                })
                self.stats['icmp_packets'] += 1
                
        elif ARP in packet:
            arp_layer = packet[ARP]
            packet_info.update({
                'protocol': 'ARP',
                'operation': 'Request' if arp_layer.op == 1 else 'Reply',
                'src_mac': arp_layer.hwsrc,
                'dst_mac': arp_layer.hwdst,
                'src_ip': arp_layer.psrc,
                'dst_ip': arp_layer.pdst
            })
            self.stats['arp_packets'] += 1
        
        self.captured_packets.append(packet_info)
        self.print_packet_summary(packet_info)
        
    def get_tcp_flags(self, flags):
        """Convert TCP flags to readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ','.join(flag_names)
        
    def print_packet_summary(self, packet_info):
        """Print a summary of the packet"""
        protocol = packet_info.get('protocol', 'Unknown')
        timestamp = packet_info['timestamp']
        length = packet_info['length']
        
        if protocol in ['TCP', 'UDP']:
            src = f"{packet_info.get('src_ip', 'Unknown')}:{packet_info.get('src_port', '?')}"
            dst = f"{packet_info.get('dst_ip', 'Unknown')}:{packet_info.get('dst_port', '?')}"
            print(f"[{timestamp}] {protocol:4} {src:21} -> {dst:21} ({length:4} bytes)")
            
            if protocol == 'TCP' and packet_info.get('flags'):
                print(f"                    Flags: {packet_info['flags']}")
                
        elif protocol == 'ICMP':
            src = packet_info.get('src_ip', 'Unknown')
            dst = packet_info.get('dst_ip', 'Unknown')
            icmp_type = packet_info.get('type', '?')
            icmp_code = packet_info.get('code', '?')
            print(f"[{timestamp}] {protocol:4} {src:21} -> {dst:21} Type:{icmp_type} Code:{icmp_code}")
            
        elif protocol == 'ARP':
            operation = packet_info.get('operation', 'Unknown')
            src_ip = packet_info.get('src_ip', 'Unknown')
            dst_ip = packet_info.get('dst_ip', 'Unknown')
            print(f"[{timestamp}] {protocol:4} {operation:8} {src_ip:15} -> {dst_ip:15}")
            
        else:
            print(f"[{timestamp}] {protocol:4} Length: {length} bytes")
    
    def print_statistics(self):
        """Print capture statistics"""
        print("\n" + "="*60)
        print("CAPTURE STATISTICS")
        print("="*60)
        
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"Capture Duration: {duration:.2f} seconds")
        
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"Total Bytes: {self.stats['total_bytes']:,}")
        
        if self.stats['total_packets'] > 0:
            print(f"Average Packet Size: {self.stats['total_bytes'] / self.stats['total_packets']:.2f} bytes")
        
        print(f"\nProtocol Distribution:")
        print(f"  TCP Packets: {self.stats['tcp_packets']}")
        print(f"  UDP Packets: {self.stats['udp_packets']}")
        print(f"  ICMP Packets: {self.stats['icmp_packets']}")
        print(f"  ARP Packets: {self.stats['arp_packets']}")
        
        # Top conversations
        conversations = defaultdict(int)
        for packet in self.captured_packets:
            if packet.get('src_ip') and packet.get('dst_ip'):
                key = f"{packet['src_ip']} <-> {packet['dst_ip']}"
                conversations[key] += 1
        
        if conversations:
            print(f"\nTop Conversations:")
            for conv, count in sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {conv}: {count} packets")
    
    def start_capture(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            print("Error: Scapy library is required for packet capture")
            print("Install with: pip install scapy")
            return
            
        print("Starting packet capture...")
        print(f"Interface: {self.interface or 'Default'}")
        print(f"Filter: {self.filter_expr or 'None'}")
        print(f"Packet Count: {self.packet_count or 'Unlimited'}")
        print("Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_expr,
                prn=self.packet_handler,
                count=self.packet_count,
                store=0
            )
        except KeyboardInterrupt:
            print("\n\nCapture stopped by user")
        except PermissionError:
            print("Error: Permission denied. Run as administrator/root for raw socket access")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            self.print_statistics()

def list_interfaces():
    """List available network interfaces"""
    if not SCAPY_AVAILABLE:
        print("Scapy not available. Cannot list interfaces.")
        return
        
    print("Available network interfaces:")
    try:
        interfaces = get_if_list()
        for i, interface in enumerate(interfaces, 1):
            print(f"  {i}. {interface}")
    except Exception as e:
        print(f"Error listing interfaces: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer - Capture and analyze network traffic"
    )
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-f', '--filter', help='BPF filter expression (e.g., "tcp port 80")')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture (0 = unlimited)', default=0)
    parser.add_argument('-l', '--list-interfaces', action='store_true', help='List available network interfaces')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        return
    
    # Check for root/admin privileges
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        print("Warning: Raw socket access requires administrator/root privileges")
        print("Some features may not work properly without elevated privileges")
    except OSError:
        pass  # Expected on some systems
    
    # Create and start analyzer
    analyzer = NetworkAnalyzer(
        interface=args.interface,
        filter_expr=args.filter,
        packet_count=args.count
    )
    
    analyzer.start_capture()

if __name__ == "__main__":
    main()
