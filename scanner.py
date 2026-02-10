import socket
import threading
from queue import Queue
import time
from scapy.all import ARP, Ether, srp, conf

target_queue = Queue()
active_ips = []

def port_scan(ports_to_scan):
    while not target_queue.empty():
        ip = target_queue.get()
        is_active = False
        
        try:
            for port in ports_to_scan:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    print(f"[+] Found Active Ip: {ip}")
                    active_ips.append(ip)
                    is_active = True
                    break
            
        except:
            pass
        finally:
            target_queue.task_done()

def start_scan():
    network_prefix = input("Enter Subnet (e.g., 192.168.1): ")
    if not network_prefix.endswith('.'):
        network_prefix += '.'
    
    try:
        port_input = input("Enter Port to scan (e.g., 80, 443, 22): ")
        target_port = int(port_input)
    except ValueError:
        print("Invalid port. Scanning default ports.")
        target_port = 80
        
    print(f"\n--- Scanning {network_prefix}0/24 for Port {target_port} ---")
    
    with target_queue.mutex:
        target_queue.queue.clear()
    
    for i in range(1, 255):
        target_queue.put(f"{network_prefix}{i}")
    
    for _ in range(50):
        t = threading.Thread(target=port_scan, args=([target_port],))
        t.daemon = True
        t.start()
        
    target_queue.join()
    print("\n--- Scan Complete ---")
    input("Press Enter to return to the main menu...")
    
def scan_arp(ip_range):
    print(f"--- Running ARP Scan on {ip_range} ---")
    
    arp = ARP(pdst = ip_range)
    ether = Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        result = srp(packet, timeout=2, verbose = 0)[0]
    except Exception as e:
        print(f"Error: {e}")
        result = []
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        print(f"Device Found: {received.psrc} {received.hwsrc}")
        
    return devices
        
    