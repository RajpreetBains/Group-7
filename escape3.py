from scapy.all import ARP, Ether, srp
import socket

print(r"""
 _   _      _                      _      _____                                 
| \ | |    | |                    | |    /  ___|                                
|  \| | ___| |___      _____  _ __| | __ \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
| . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
| |\  |  __/ |_ \ V  V / (_) | |  |   <  /\__/ / (_| (_| | | | | | | |  __/ |   
\_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\ \____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                
""")

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    arp_request_broadcast = ether / arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        device_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        device_dict["name"] = get_device_name(device_dict["ip"])
        devices_list.append(device_dict)
    return devices_list

def main():
    ip_range = input("Please enter the IP range you want to scan (ex. 192.168.1.0/24): ")
    devices = scan_network(ip_range)
    
    print("\nDevices on the network:")
    print("{:<20} {:<20} {:<20}".format("IP Address", "MAC Address", "Device Name"))
    print("-" * 60)
    for device in devices:
        print("{:<20} {:<20} {:<20}".format(device["ip"], device["mac"], device["name"]))

if __name__ == "__main__":
    main()
