# Python Network Security Tool
A modular, CLI tool designed for network traffic analysis. Uses python, raw socket handling, multi-threaded scanning, and packet sniffing with Scapy. 

## Features
### 1. TCP Port Scanner
- Identifies active hosts and checks for open TCP ports across specific subnets.
- Implements multi-threading queue managing to simultaneously scan 254 hosts, reducing scan times across large networks.
- Utilizes standard Python sockets to perform TCP handshakes. 

### 2. ARP Scanner
- Bypasses OS level ARP caches to send ARP requests directly across the local network using Scapy. 
- Returns an accurate, realtime mapping of IP addresses to MAC addresses. 

### 3. HTTP Packet Sniffer
- Captures and filters live network traffic to monitor TCP and UDP communication.
- Specifically targets port 80 traffic.

## Tech Stack
* **Language:** Python 3.x 
* **Libraries:** `scapy`, `socket`, `threading`, `queue`, `sys`, `time`

## Prerequisites
* **Operating System:** Linux (Kali Linux or Ubuntu) or macOS.
* **Permissions:** Root/Sudo privileges are required to access the ARP scanner and Packet Sniffer due to raw socket use.

## Installation & Use

1. Clone the repository:
   git clone https://github.com/Yabdalla01/Network-Security-Tool.git
   cd Network-Security-Tool

2. Run the tool:
   sudo python3 main.py

3. Select the desired feature from the menu.
