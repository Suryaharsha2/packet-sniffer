from scapy.all import sniff, IP, TCP, UDP

def handle_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        else:
            proto = "Other"
        print(f"{src} -> {dst}  [{proto}]")

print("Starting sniffer... press Ctrl+C to stop.")
sniff(prn=handle_packet, filter="ip", store=False, count=20)