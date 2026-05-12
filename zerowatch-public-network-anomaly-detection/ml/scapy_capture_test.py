from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        size = len(packet)

        print(f"SRC: {src_ip} -> DST: {dst_ip} | Protocol: {proto} | Size: {size}")

        if TCP in packet:
            print(f"TCP sport={packet[TCP].sport}, dport={packet[TCP].dport}, flags={packet[TCP].flags}")

        if UDP in packet:
            print(f"UDP sport={packet[UDP].sport}, dport={packet[UDP].dport}")

        print("-" * 50)


print("Capturing packets... Press CTRL + C to stop.")
sniff(prn=packet_callback, store=False)
