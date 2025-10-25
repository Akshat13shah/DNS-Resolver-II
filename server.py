import socket
import struct
import csv
import time


srvr_ip = '127.0.0.1'
srvr_port = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((srvr_ip, srvr_port))
server.listen()
print(f"Server listening on {srvr_ip}:{srvr_port}")

conn, addr = server.accept()
print("Connected by", addr)

IP_pool = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"]

tot = 0
log_file = "dns_log.csv"
with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp","Domain","ResolutionMode","DNS_Server_IP",
                     "Step","Response","RTT","TotalTime","CacheStatus"])

while True:
    data_len = conn.recv(4)
   
    if not data_len:   # <-- client closed connection
        print("========Done========")
        print("No more data. Closing connection.")
        break
   
    tot+=1
    print("----NEW pkt",tot,"---->")
    siz = struct.unpack("!I",data_len)[0]
   
    pkt = b''
    while len(pkt) < siz:
        chunk = conn.recv(siz-len(pkt))
        pkt+=chunk
   
    cstm_hdr = pkt[:8]
    # print("Raw header bytes:", cstm_hdr)
   
    dns_pkt_bytes = pkt[8:]
   
    try:
        cstm_hdr_str = cstm_hdr.decode()
    except UnicodeDecodeError:
        print("Invalid header received:", cstm_hdr)
        continue # Skip this pkt
   
    HH = cstm_hdr_str[:2]
   
    ip_pool_start = 0
    if (HH<'04'):
        ip_pool_start = 10
    elif (HH<'12'):
        ip_pool_start = 0
    elif (HH<'20'):
        ip_pool_start = 5
   
    ID = int(cstm_hdr_str[6:])
   
    trgt_indx = ip_pool_start+(ID%5)
    resolved_ip = IP_pool[trgt_indx]   
    timestamp = time.time()
    domain_name = "example.com"  # you can try to extract from dns_pkt_bytes if needed
    resolution_mode = "CustomResolver"
    dns_server_ip = srvr_ip
    step = "Root/TLD/Authoritative"  # placeholder, as we are not doing real recursive steps
    response = resolved_ip
    rtt = 0  # optional, if measuring per hop
    total_time = 0  # optional
    cache_status = "MISS"  # if you implement caching

    with open(log_file, "a", newline="") as f:
    	writer = csv.writer(f)
    	writer.writerow([timestamp, domain_name, resolution_mode, dns_server_ip,
                     step, response, rtt, total_time, cache_status])

    if not pkt:
        break
    print("Received packet:", pkt)
    print("Received header:", cstm_hdr)
    print("Resolved address:", IP_pool[trgt_indx])
    print()
    
    resp_bytes = resolved_ip.encode()
    resp_size = len(resp_bytes)
    conn.sendall(struct.pack("!I", resp_size) + resp_bytes)


print("Total no of pkts =",tot)

conn.close()
