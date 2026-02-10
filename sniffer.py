import sys
from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        protocol = "Other"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"

        print(f"{src} -> {dst} | {protocol}")

        if packet.haslayer(Raw) and packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                try:
                    load = packet[Raw].load.decode('utf-8', errors = 'ignore')
                    if "GET" in load or "POST" in load or "password" in load:
                        print(f"\nHTTP DATA CAUGHT: \n{load}\n")
                except:
                    pass

def start_sniff():
    print("\n--- Starting Packet Sniffer (Ctrl+c to stop) ---")
    print("Listening for traffic on network...")

    try:
        sniff(prn = packet_callback, store = 0)
    except KeyboardInterrupt:
        print("\n--- Stopping Sniffer ---")
