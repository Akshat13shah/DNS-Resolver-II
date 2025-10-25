# client.py (minimal updated version)
from scapy.utils import PcapReader
from scapy.layers.dns import DNS
from datetime import datetime
import socket
import struct
import os
import time

# List of PCAP files
pcap_files = [
    "PCAP_1_H1.pcap",
    "PCAP_2_H2.pcap",
    "PCAP_3_H3.pcap",
    "PCAP_4_H4.pcap"
]

host_names = ["H1", "H2", "H3", "H4"]

dns_pkts = []
cnt_total = 0

# Process each PCAP file
for idx, pcap_file in enumerate(pcap_files):
    host = host_names[idx]
    if not os.path.isfile(pcap_file):
        print(f"File not found: {pcap_file}")
        continue

    print(f"Processing {pcap_file} for {host}...")
    with PcapReader(pcap_file) as pcap:
        for pkt in pcap:
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
                seq_id = f"{cnt_total % 100:02d}"
                timestamp = datetime.now().strftime("%H%M%S")
                cstm_hdr = (timestamp + seq_id).encode()

                dns_pkts.append({
                    "custom_header": cstm_hdr,
                    "original_packet": pkt[DNS],
                    "host": host
                })

            cnt_total += 1

print(f"\nTotal packets scanned: {cnt_total}")
print(f"Total DNS query packets: {len(dns_pkts)}\n")

# Connect to server
server_ip = '127.0.0.1'
server_port = 12345
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((server_ip, server_port))
print(f"Connected to server {server_ip}:{server_port}\n")

# Metrics
stats = {host: {"success":0, "fail":0, "latencies":[], "bytes_sent":0} for host in host_names}

# Send packets and measure latency
for pkt in dns_pkts:
    host = pkt["host"]
    packet_to_send = pkt['custom_header'] + bytes(pkt['original_packet'])
    size = len(packet_to_send)
    stats[host]["bytes_sent"] += size

    try:
        start_time = time.time()
        client.sendall(struct.pack("!I", size) + packet_to_send)

        # Receive response from server
        raw_size = client.recv(4)
        if not raw_size:
            stats[host]["fail"] += 1
            continue
        resp_size = struct.unpack("!I", raw_size)[0]
        resp_data = client.recv(resp_size)
        end_time = time.time()

        stats[host]["success"] += 1
        stats[host]["latencies"].append((end_time - start_time)*1000)  # in ms

    except Exception as e:
        stats[host]["fail"] += 1
        print(f"{host} packet failed: {e}")

# Summary
print("======== Summary ========")
for host in host_names:
    success = stats[host]["success"]
    fail = stats[host]["fail"]
    avg_latency = sum(stats[host]["latencies"])/len(stats[host]["latencies"]) if stats[host]["latencies"] else 0
    total_bytes = stats[host]["bytes_sent"]
    total_time_sec = sum(stats[host]["latencies"])/1000 if stats[host]["latencies"] else 1
    throughput = total_bytes / total_time_sec if total_time_sec>0 else 0

    print(f"{host}: Success={success}, Fail={fail}, Avg Latency={avg_latency:.2f} ms, Throughput={throughput/1024:.2f} KB/s")

client.close()
print("\nAll packets sent. Connection closed.")
