from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to analyze each captured packet
def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"\n[+] Packet Captured:")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {proto}")

        # Check for TCP/UDP/ICMP and print basic info
        if packet.haslayer(TCP):
            print("    Protocol Type  : TCP")
            print(f"    Source Port    : {packet[TCP].sport}")
            print(f"    Dest Port      : {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("    Protocol Type  : UDP")
            print(f"    Source Port    : {packet[UDP].sport}")
            print(f"    Dest Port      : {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("    Protocol Type  : ICMP")
        else:
            print("    Protocol Type  : Other")

        # Show raw payload (optional)
        if packet.haslayer(Raw):
            print(f"    Payload        : {packet[Raw].load[:50]}")  # First 50 bytes

# Start sniffing packets on your network interface
print("Starting packet sniffer... Press Ctrl+C to stop.\n")
sniff(prn=analyze_packet, store=False)
