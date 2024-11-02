from scapy.all import IP, ICMP, send

def send_icmp():
    packet = IP(dst="172.22.0.2", ttl=1) / ICMP()    
    send(packet)

if __name__ == "__main__":
    send_icmp()
