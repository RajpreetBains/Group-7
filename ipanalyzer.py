<<<<<<< HEAD
#import packages
import scapy.all as scapy
import tabulate
import matplotlib.pyplot as plt
import statistics

def capture_packets():
    mode = input("Real time, file mode, or upload mode? (r/f/u): ")
    if mode == "r":
        count = input("Enter the number of packets to capture: ")
        ip_packets = scapy.sniff(int(count), filter="ip")
    elif mode == "f":
        filename = input("Enter the name of the file to capture from: ")
        packets = scapy.rdpcap(filename)
        ip_packets = [packet for packet in packets if scapy.IP in packet]
    elif mode == "u":
        filename = input("Enter the name of the file to upload: ")
        with open(filename, 'rb') as file:
            ip_packets = scapy.rdpcap(file)
            ip_packets = [packet for packet in ip_packets if scapy.IP in packet]
    else:
        print("Invalid mode. Please try again.")
        return
    return ip_packets

# function to extract packet info
# @param captured packets
# @return packet information
def get_packet_info(packets):
  # list of dictionaries to store packet info
  packet_info = []
  # for loop 
  for packet in packets:
    # dictionary to store packet information
    packet_dict = {}
    # extract source and destination IP
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    protocol = packet[scapy.IP].proto
    # extract ports and protocol
    if packet.haslayer(scapy.TCP):
      #extract source and destination ports
      src_port = packet[scapy.TCP].sport
      dst_port = packet[scapy.TCP].dport   
    elif packet.haslayer(scapy.UDP):
      #extract source and destination ports
      src_port = packet[scapy.UDP].sport
      dst_port = packet[scapy.UDP].dport
    else:
      #if no TCP or UDP layer is present, set ports to None
      src_port = None
      dst_port = None 
    # extract packet length
    packet_length = len(packet)
    #extract packet data
    packet_data = packet.sprintf("%Raw.load%")

    #add packet information to dictionary
    packet_dict["Source IP"] = src_ip
    packet_dict["Destination IP"] = dst_ip
    packet_dict["Source Port"] = src_port
    packet_dict["Destination Port"] = dst_port
    packet_dict["Protocol"] = protocol
    packet_dict["Packet Length"] = packet_length
    packet_dict["Packet Data"] = packet_data

    #add dictionary to list
    packet_info.append(packet_dict)
  return packet_info

# method to display packet information in a table
def display_packet_info(packet_info):
  # create table headers
  headers = ["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Packet Length"]
  # create table rows
  rows = []
  for packet in packet_info:
    row = [packet["Source IP"], packet["Destination IP"], packet["Source Port"], packet["Destination Port"], packet["Protocol"], packet["Packet Length"]]
    rows.append(row)
  # create table
  table = tabulate.tabulate(rows, headers, tablefmt="grid")
  # print table
  print(table)

# method to get unusually large packets
# @param list of packet information
# @return list of unusually large packets
def get_unusual_packet(packet_info):
  # create list to store packet sizes
  packet_lengths = [packet["Packet Length"] for packet in packet_info]
  # calculate statistics
  mean = statistics.mean(packet_lengths)
  st_dev = statistics.stdev(packet_lengths)
  # create threshold
  threshold = mean + (st_dev * 2)
  # create list to store packets above threshold
  above_threshold = []
  # for loop to iterate through packet info
  for packet in packet_info:
    # compare packet length to threshold
    if packet["Packet Length"] > threshold:
      # add packet to list
      above_threshold.append(packet)
  # return list of packets above threshold
  return above_threshold





packets = capture_packets()
packet_info = get_packet_info(packets)
display_packet_info(packet_info)
unusual_packets = get_unusual_packet(packet_info)
display_packet_info(unusual_packets)
||||||| 0824643
=======
#import packages
import scapy.all as scapy
import tabulate
import matplotlib.pyplot as plt

# function to capture ip packets
# @return packets with ip headers
def capture_packets():
  # prompt to choose capture mode
  mode = input("Real time or file mode? (r/f): ")
  # real time capture mode
  if mode == "r":
    count = input("Enter the number of packets to capture: ")
    ip_packets = scapy.sniff(int(count), filter="ip")
  # file capture mode
  elif mode == "f":
    filename = input("Enter the name of the file to capture from: ")
    packets = scapy.rdpcap(filename)
    ip_packets = [packet for packet in packets if scapy.IP in packet]
  else:
    print("Invalid mode. Please try again.")
    return
  return ip_packets

# function to extract packet info
# @param captured packets
# @return packet information
def get_packet_info(packets):
  # list of dictionaries to store packet info
  packet_info = []
  # for loop 
  for packet in packets:
    # dictionary to store packet information
    packet_dict = {}
    # extract source and destination IP
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    protocol = packet[scapy.IP].proto
    # extract ports and protocol
    if packet.haslayer(scapy.TCP):
      #extract source and destination ports
      src_port = packet[scapy.TCP].sport
      dst_port = packet[scapy.TCP].dport   
    elif packet.haslayer(scapy.UDP):
      #extract source and destination ports
      src_port = packet[scapy.UDP].sport
      dst_port = packet[scapy.UDP].dport
    else:
      #if no TCP or UDP layer is present, set ports to None
      src_port = None
      dst_port = None 
    # extract packet length
    packet_length = len(packet)
    #extract packet data
    packet_data = packet.sprintf("%Raw.load%")

    #add packet information to dictionary
    packet_dict["Source IP"] = src_ip
    packet_dict["Destination IP"] = dst_ip
    packet_dict["Source Port"] = src_port
    packet_dict["Destination Port"] = dst_port
    packet_dict["Protocol"] = protocol
    packet_dict["Packet Length"] = packet_length
    packet_dict["Packet Data"] = packet_data

    #add dictionary to list
    packet_info.append(packet_dict)
  return packet_info

# method to display packet information in a table
def display_packet_info(packet_info):
  # create table headers
  headers = ["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Packet Length"]
  # create table rows
  rows = []
  for packet in packet_info:
    row = [packet["Source IP"], packet["Destination IP"], packet["Source Port"], packet["Destination Port"], packet["Protocol"], packet["Packet Length"]]
    rows.append(row)
  # create table
  table = tabulate.tabulate(rows, headers, tablefmt="grid")
  # print table
  print(table)

# method to get unusually large packets
# @param list of packet information
# @return list of unusually large packets
def get_unusual_packet(packet_info):
  # create list to store packet sizes
  packet_lengths = [packet["Packet Length"] for packet in packet_info]
  # calculate statistics
  mean = statistics.mean(packet_lengths)
  st_dev = statistics.stdev(packet_lengths)
  # create threshold
  threshold = mean + (st_dev * 2)
  # create list to store packets above threshold
  above_threshold = []
  # for loop to iterate through packet info
  for packet in packet_info:
    # compare packet length to threshold
    if packet["Packet Length"] > threshold:
      # add packet to list
      above_threshold.append(packet)
  # return list of packets above threshold
  return above_threshold





packets = capture_packets()
packet_info = get_packet_info(packets)
display_packet_info(packet_info)
unusual_packets = get_unusual_packet(packet_info)
display_packet_info(unusual_packets)
>>>>>>> ae8814cac236f78b2945ded742c3008f276b6cf6
