import socket
import struct
from collections import Counter

#  FILTER OPTIONS - TCP / UDP / DNS / ALL
FILTER = "ALL"   

packet_count = 0
tcp_count = 0
udp_count = 0
dns_count = 0
src_ips = Counter()
dst_ips = Counter()
port_hits = Counter()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

LOCAL_IP = get_local_ip()
print(f"[+] Using local IP: {LOCAL_IP}")


sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind((LOCAL_IP, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print("[+] Sniffer started...\n")

def parse_ip_header(data):
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version = iph[0] >> 4
    ihl = (iph[0] & 0xF) * 4
    protocol = iph[6]
    src = socket.inet_ntoa(iph[8])
    dst = socket.inet_ntoa(iph[9])
    return ihl, protocol, src, dst

def parse_tcp_header(data):
    tcph = struct.unpack('!HHLLBBHHH', data[:20])
    return tcph[0], tcph[1]

def parse_udp_header(data):
    udph = struct.unpack('!HHHH', data[:8])
    return udph[0], udph[1]

def extract_dns(payload):
    try:
        domain = ""
        idx = 12
        length = payload[idx]
        while length != 0:
            domain += payload[idx+1:idx+1+length].decode() + "."
            idx += length + 1
            length = payload[idx]
        return domain
    except:
        return None

def extract_http(payload):
    try:
        data = payload.decode(errors="ignore")
        if data.startswith("GET") or data.startswith("POST"):
            return data.split("\r\n")[0]
    except:
        pass
    return None

while True:
    raw, addr = sniffer.recvfrom(65535)
    ihl, proto, src, dst = parse_ip_header(raw)
    packet_count += 1
    src_ips[src] += 1
    dst_ips[dst] += 1

   
    if FILTER == "TCP" and proto != 6:
        continue
    if FILTER == "UDP" and proto != 17:
        continue


    print("\n===== PACKET =====")
    print(f"IP: {src} --> {dst}")

    payload = raw[ihl:]

   
    if proto == 6:
        tcp_count += 1
        src_p, dst_p = parse_tcp_header(payload[:20])
        port_hits[dst_p] += 1

        print(f"TCP: {src_p} --> {dst_p}")

        http_req = extract_http(payload[20:])
        if http_req:
            print(f"[HTTP] {http_req}")

   
    elif proto == 17:
        udp_count += 1
        src_p, dst_p = parse_udp_header(payload[:8])
        print(f"UDP: {src_p} --> {dst_p}")

      
        if src_p == 53 or dst_p == 53:
            dns_count += 1
            domain = extract_dns(payload[8:])
            if domain:
                print(f"[DNS] Query: {domain}")

 
    print("---- Analysis ----")
    print(f"Total packets: {packet_count} | TCP: {tcp_count} | UDP: {udp_count} | DNS: {dns_count}")
    print(f"Top Source IP: {src_ips.most_common(1)}")
    print(f"Top Dest IP:   {dst_ips.most_common(1)}")

  
    if len(port_hits) > 5 and max(port_hits.values()) < 3:
        print("[!] Suspicious activity: Possible port scan detected!")

    print("====================\n")
