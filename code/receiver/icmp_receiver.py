from scapy.all import sniff, ICMP

def handle_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        packet.show()

def receive_icmp():
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    receive_icmp()
