# CodeAlpha Cybersecurity Internship

Complete implementations of all four CodeAlpha cybersecurity internship tasks, tested on **Kali Linux**.

---

## Quick Setup (Kali Linux)

```bash
# Install the one dependency all tasks share
sudo apt update
sudo apt install python3-pip -y
pip install scapy
```

---

## Task 1 — Basic Network Sniffer

**File:** `task1_network_sniffer/network_sniffer.py`

```bash
# List interfaces
sudo python3 task1_network_sniffer/network_sniffer.py --list

# Capture all traffic on eth0
sudo python3 task1_network_sniffer/network_sniffer.py -i eth0

# Capture 100 packets, filter HTTP, save to pcap
sudo python3 task1_network_sniffer/network_sniffer.py -i eth0 -c 100 -f "tcp port 80" -s capture.pcap
```

**Features:** TCP / UDP / ICMP / ARP / DNS / HTTP parsing, payload display, BPF filters, pcap export.

---
