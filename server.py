import socket
import struct
import csv
import time
from scapy.layers.dns import DNS, DNSQR

srvr_ip = '127.0.0.1'
srvr_port = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((srvr_ip, srvr_port))
server.listen()
print(f"Server listening on {srvr_ip}:{srvr_port}")

conn, addr = server.accept()
print("Connected by", addr)

IP_pool = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

tot = 0
log_file = "dns_log.csv"
with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Timestamp","Domain","ResolutionMode","DNS_Server_IP",
        "Step","Response","RTT","TotalTime","CacheStatus"
    ])

while True:
    data_len = conn.recv(4)
    if not data_len:
        print("========Done========")
        break

    tot += 1
    siz = struct.unpack("!I", data_len)[0]

    pkt = b''
    while len(pkt) < siz:
        pkt += conn.recv(siz - len(pkt))

    cstm_hdr = pkt[:8]
    dns_pkt_bytes = pkt[8:]

    # Decode custom header
    try:
        cstm_hdr_str = cstm_hdr.decode()
    except UnicodeDecodeError:
        print("Invalid header:", cstm_hdr)
        continue

    HH = cstm_hdr_str[:2]
    ID = int(cstm_hdr_str[6:])
    
    # IP selection logic
    ip_pool_start = 0
    if HH < '04':
        ip_pool_start = 10
    elif HH < '12':
        ip_pool_start = 0
    elif HH < '20':
        ip_pool_start = 5

    trgt_indx = ip_pool_start + (ID % 5)
    resolved_ip = IP_pool[trgt_indx]

    # Extract domain from DNS query
    try:
        dns_query = DNS(dns_pkt_bytes)
        if dns_query.qd is not None:
            domain_name = dns_query.qd.qname.decode().rstrip('.')
        else:
            domain_name = "UNKNOWN"
    except:
        domain_name = "INVALID"

    timestamp = time.time()
    resolution_mode = "CustomResolver"
    dns_server_ip = srvr_ip
    step = "Root/TLD/Authoritative"
    response = resolved_ip
    rtt = 0
    total_time = 0
    cache_status = "MISS"

    # Append to CSV
    with open(log_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp, domain_name, resolution_mode, dns_server_ip,
            step, response, rtt, total_time, cache_status
        ])

    # Send response to client
    resp_bytes = resolved_ip.encode()
    conn.sendall(struct.pack("!I", len(resp_bytes)) + resp_bytes)

    print(f"Packet {tot}: Header={cstm_hdr_str}, Domain={domain_name}, Resolved={resolved_ip}")

print("Total packets received =", tot)
conn.close()
