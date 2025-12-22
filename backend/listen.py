from scapy.all import sniff, ARP, ICMP, IP, TCP

def packet_handler(pkt):
    # ARP packets
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.op == 2:  # ARP Reply
            print(f"ARP Reply: {arp.psrc} is at {arp.hwsrc}")

    # ICMP packets (like ping)
    elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
        ip = pkt[IP]
        icmp = pkt[ICMP]
        direction = "Request" if icmp.type == 8 else "Reply" if icmp.type == 0 else f"Type {icmp.type}"
        if direction != "Request":
            print(f"[ICMP {direction}] {ip.src} → {ip.dst}")

    # TCP packets (SYN, SYN-ACK)
    elif pkt.haslayer(TCP) and pkt.haslayer(IP):
        ip = pkt[IP]
        tcp = pkt[TCP]
        flags = tcp.flags

        if flags & 0x02 and not flags & 0x10:  # SYN set, ACK not set → SYN
            print(f"[TCP SYN] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}")
        elif flags & 0x12:  # SYN and ACK both set → SYN-ACK
            print(f"[TCP SYN-ACK] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}")

# Sniff packets indefinitely, filter ARP, ICMP, and TCP
print("Sniffing ARP, ICMP, and TCP SYN/SYN-ACK packets... Press Ctrl+C to stop.")
sniff(filter="arp or icmp or tcp", prn=packet_handler, store=False)
