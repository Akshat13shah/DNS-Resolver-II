# client.py
from scapy.utils import PcapReader
from scapy.layers.dns import DNS
from datetime import datetime
import socket
import struct
import os

# List of PCAP files (make sure they exist in /home/mininet/)
pcap_files = [
    "PCAP_1_H1.pcap",
    "PCAP_2_H2.pcap",
    "PCAP_3_H3.pcap",
    "PCAP_4_H4.pcap"
]

dns_pkts = []
cnt = 0

# Process each PCAP file
for pcap_file in pcap_files:
    if not os.path.isfile(pcap_file):
        print(f"File not found: {pcap_file}")
        continue

    print(f"Processing {pcap_file}...")
    with PcapReader(pcap_file) as pcap:
        for pkt in pcap:
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
                seq_id = f"{cnt % 100:02d}"
                timestamp = datetime.now().strftime("%H%M%S")
                cstm_hdr = (timestamp + seq_id).encode()

                dns_pkts.append({
                    "custom_header": cstm_hdr,
                    "original_packet": pkt[DNS]
                })

            cnt += 1
            if cnt % 50000 == 0:
                print(f"Processed {cnt} packets...")

print(f"\nTotal packets scanned: {cnt}")
print(f"Total DNS query packets: {len(dns_pkts)}\n")

# Connect to server
server_ip = '127.0.0.1'
server_port = 12345

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((server_ip, server_port))
print(f"Connected to server {server_ip}:{server_port}")

# Send packets
for pkt in dns_pkts:
    packet_to_send = pkt['custom_header'] + bytes(pkt['original_packet'])
    size = len(packet_to_send)
    client.sendall(struct.pack("!I", size) + packet_to_send)

print("All packets sent.")
client.close()
