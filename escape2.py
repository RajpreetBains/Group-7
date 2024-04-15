from scapy.all import ARP, Ether, srp
import sys

def arp_scan(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def main():
    if len(sys.argv) != 2:
        print("Usage: python arp_scan.py <ip_range>")
        sys.exit(1)
    
    ip_range = sys.argv[1]
    devices = arp_scan(ip_range)
    
    print("Devices on the network:")
    print("======================")
    print("IP Address\t\tMAC Address")
    print("-----------\t\t-----------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    main()
