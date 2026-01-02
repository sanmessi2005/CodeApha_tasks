from scapy.all import sniff
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, hexdump

from scapy.utils import hexdump
import datetime

def process_packet(packet):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"\n[{ts}] Packet captured:")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"  From: {ip_layer.src}  -->  To: {ip_layer.dst}")
        print(f"  Protocol Number: {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("  Protocol: TCP")
        elif packet.haslayer(UDP):
            print("  Protocol: UDP")
        elif packet.haslayer(ICMP):
            print("  Protocol: ICMP")

        if packet.haslayer(Raw):
            print("  Payload (first 50 bytes):")
            hexdump(packet[Raw].load[:50])
    else:
        print("  Non-IP packet")

print("[*] Starting packet sniffing... Press CTRL+C to stop.")
sniff(prn=process_packet, store=False, count=10)  # capture 10 packets
