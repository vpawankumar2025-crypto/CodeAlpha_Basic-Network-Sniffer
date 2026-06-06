#!/usr/bin/env python3
"""
CodeAlpha Internship - Task 1: Basic Network Sniffer
Author: Pawan Kumar V
Description: Captures and analyzes network traffic packets using Scapy.
Run with: sudo python3 network_sniffer.py
"""

import sys
import datetime
import argparse
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        ARP, Ether, Raw, wrpcap, rdpcap, get_if_list
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("[-] Scapy not found. Install it: pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────
#  Global stats
# ─────────────────────────────────────────────
stats = defaultdict(int)
captured_packets = []
LOG_FILE = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


def banner():
    print("""
╔══════════════════════════════════════════════════╗
║       CodeAlpha — Basic Network Sniffer          ║
║       Task 1 | Cybersecurity Internship          ║
╚══════════════════════════════════════════════════╝
    """)


def log(msg: str):
    """Write a message to both stdout and the log file."""
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")


def format_payload(raw_bytes: bytes, max_len: int = 100) -> str:
    """Convert raw bytes to a printable string, truncating if needed."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = repr(raw_bytes)
    return text[:max_len] + ("..." if len(text) > max_len else "")


def handle_http(packet):
    """Extract and display HTTP request/response details."""
    if packet.haslayer(HTTPRequest):
        method  = packet[HTTPRequest].Method.decode(errors="replace")
        host    = packet[HTTPRequest].Host.decode(errors="replace")
        path    = packet[HTTPRequest].Path.decode(errors="replace")
        log(f"  [HTTP REQUEST]  {method} http://{host}{path}")
        stats["HTTP"] += 1

    elif packet.haslayer(HTTPResponse):
        status = packet[HTTPResponse].Status_Code.decode(errors="replace")
        log(f"  [HTTP RESPONSE] Status: {status}")
        stats["HTTP"] += 1


def handle_dns(packet):
    """Extract DNS query/response details."""
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode(errors="replace")
        log(f"  [DNS QUERY]     {packet[IP].src} → {query}")
        stats["DNS"] += 1

    if packet.haslayer(DNSRR):
        name  = packet[DNSRR].rrname.decode(errors="replace")
        rdata = packet[DNSRR].rdata
        log(f"  [DNS RESPONSE]  {name} → {rdata}")


def handle_arp(packet):
    """Display ARP packet details."""
    op = "REQUEST" if packet[ARP].op == 1 else "REPLY"
    log(f"  [ARP {op}]  {packet[ARP].psrc} ({packet[ARP].hwsrc})"
        f"  →  {packet[ARP].pdst} ({packet[ARP].hwdst})")
    stats["ARP"] += 1


def process_packet(packet):
    """Main callback — called for every captured packet."""
    captured_packets.append(packet)
    stats["total"] += 1
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # ── ARP (no IP layer) ──────────────────────────────────────────────
    if packet.haslayer(ARP):
        log(f"\n[{ts}] ARP Packet #{stats['total']}")
        handle_arp(packet)
        return

    # ── IP packets ────────────────────────────────────────────────────
    if not packet.haslayer(IP):
        stats["other"] += 1
        return

    src_ip  = packet[IP].src
    dst_ip  = packet[IP].dst
    proto   = packet[IP].proto
    ttl     = packet[IP].ttl
    pkt_len = len(packet)

    # ── TCP ───────────────────────────────────────────────────────────
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags
        stats["TCP"] += 1

        log(f"\n[{ts}] TCP Packet #{stats['total']}  ({pkt_len} bytes)")
        log(f"  Source      : {src_ip}:{src_port}")
        log(f"  Destination : {dst_ip}:{dst_port}")
        log(f"  Flags       : {flags}   TTL: {ttl}")

        handle_http(packet)

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            log(f"  Payload     : {format_payload(payload)}")

    # ── UDP ───────────────────────────────────────────────────────────
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        stats["UDP"] += 1

        log(f"\n[{ts}] UDP Packet #{stats['total']}  ({pkt_len} bytes)")
        log(f"  Source      : {src_ip}:{src_port}")
        log(f"  Destination : {dst_ip}:{dst_port}")
        log(f"  TTL         : {ttl}")

        handle_dns(packet)

    # ── ICMP ──────────────────────────────────────────────────────────
    elif packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        stats["ICMP"] += 1

        type_map = {0: "Echo Reply", 8: "Echo Request",
                    3: "Destination Unreachable", 11: "Time Exceeded"}
        desc = type_map.get(icmp_type, f"Type {icmp_type}")

        log(f"\n[{ts}] ICMP Packet #{stats['total']}  ({pkt_len} bytes)")
        log(f"  Source      : {src_ip}  →  {dst_ip}")
        log(f"  Type        : {desc} (Code {icmp_code})")

    else:
        stats["other"] += 1
        log(f"\n[{ts}] Other IP Packet #{stats['total']}  proto={proto}  "
            f"{src_ip} → {dst_ip}")


def print_summary():
    """Print a summary of captured traffic."""
    sep = "═" * 50
    log(f"\n{sep}")
    log("  CAPTURE SUMMARY")
    log(sep)
    log(f"  Total packets : {stats['total']}")
    log(f"  TCP           : {stats['TCP']}")
    log(f"  UDP           : {stats['UDP']}")
    log(f"  ICMP          : {stats['ICMP']}")
    log(f"  ARP           : {stats['ARP']}")
    log(f"  DNS           : {stats['DNS']}")
    log(f"  HTTP          : {stats['HTTP']}")
    log(f"  Other         : {stats['other']}")
    log(f"\n  Log saved to  : {LOG_FILE}")
    log(sep)


def list_interfaces():
    print("\n[*] Available network interfaces:")
    for i, iface in enumerate(get_if_list(), 1):
        print(f"    {i}. {iface}")
    print()


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="CodeAlpha Network Sniffer — Task 1"
    )
    parser.add_argument("-i", "--iface",   default=None,
                        help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count",   type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter",  default="",
                        help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-s", "--save",    default=None,
                        help="Save captured packets to a .pcap file")
    parser.add_argument("-l", "--list",    action="store_true",
                        help="List available interfaces and exit")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    list_interfaces()

    iface  = args.iface
    count  = args.count
    bpf    = args.filter
    saveto = args.save

    log(f"[*] Starting sniffer on interface : {iface or 'default'}")
    log(f"[*] Packet count limit            : {count or 'unlimited'}")
    log(f"[*] BPF filter                    : '{bpf}' (empty = all)")
    log(f"[*] Log file                      : {LOG_FILE}")
    log("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=iface,
            count=count if count > 0 else 0,
            filter=bpf if bpf else None,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        log("\n[!] Sniffer stopped by user.")
    except PermissionError:
        print("[-] Permission denied. Run with sudo: sudo python3 network_sniffer.py")
        sys.exit(1)
    finally:
        print_summary()
        if saveto and captured_packets:
            wrpcap(saveto, captured_packets)
            print(f"[+] Packets saved to {saveto}")


if __name__ == "__main__":
    main()
