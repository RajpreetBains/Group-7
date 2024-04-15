import socket
import netifaces
from scapy.all import *
from scapy.layers.l2 import ARP
from threading import Thread

class PacketSnifferCLI:
    def __init__(self):
        self.sniffing = False
        self.captured_packets = []
        self.devices = {}

    def start_capture(self):
        if self.sniffing:
            print("Already sniffing packets.")
            return

        print("Starting packet capture...")
        self.sniffing = True
        self.captured_packets = []

        def sniff_packets():
            while self.sniffing:
                packets = sniff(count=10)
                self.captured_packets.extend(packets)
                # Removed time.sleep(1)

        self.sniff_thread = Thread(target=sniff_packets)
        self.sniff_thread.start()

    def stop_capture(self):
        if not self.sniffing:
            print("Not sniffing packets.")
            return

        print("Stopping packet capture...")
        self.sniffing = False

    def export_packets(self):
        if not self.captured_packets:
            print("No packets captured yet.")
            return

        # Removed time-related formatting
        filename = f"captured_packets.pcap"
        wrpcap(filename, self.captured_packets)
        print(f"Packets have been exported to {filename}")

    def display_devices(self):
        self.devices = {}
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    mac = addrs[netifaces.AF_LINK][0]['addr']
                    self.devices[ip] = {'mac': mac, 'name': socket.gethostname()}
            except ValueError:
                pass

        if not self.sniffing:
            print("Devices on Network:")
            for ip, info in self.devices.items():
                print(f"IP: {ip}, MAC: {info['mac']}, Name: {info['name']}")
        else:
            print("Cannot display devices while sniffing packets.")

    def run(self):
        while True:
            print("\n1. Start Capture")
            print("2. Stop Capture")
            print("3. Export Packets")
            print("4. Display Devices")
            print("5. Exit")

            choice = input("Enter your choice: ")

            if choice == '1':
                self.start_capture()
            elif choice == '2':
                self.stop_capture()
            elif choice == '3':
                self.export_packets()
            elif choice == '4':
                self.display_devices()
            elif choice == '5':
                if self.sniffing:
                    self.stop_capture()
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    sniffer = PacketSnifferCLI()
    sniffer.run()