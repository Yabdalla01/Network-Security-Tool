import sys
import scanner
import sniffer

def main():
    while True:
        print("\n=== Network Tools Menu ===")
        print("1. Port Scanner")
        print("2. ARP Scanner")
        print("3. Packet Sniffer")
        print("4. Exit")

        choice = input("Select a module (1-5):")

        if choice == '1':
            scanner.start_scan()
        elif choice == '2':
            target = input("Enter IP range (e.g., 192.168.1.1/24): ")
            scanner.scan_arp(target)
        elif choice == '3':
            sniffer.start_sniff()
        elif choice == '4':     
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid choice. Please select a valid option.")
    
if __name__ == "__main__":

    main()

