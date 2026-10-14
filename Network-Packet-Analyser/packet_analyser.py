from scapy.all import sniff, IP, TCP, UDP, ICMP


def identify_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"

    elif packet.haslayer(UDP):
        return "UDP"

    elif packet.haslayer(ICMP):
        return "ICMP"

    else:
        return "Other"


def analyze_packet(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol = identify_protocol(packet)

        print(
            f"Source IP: {source_ip} | "
            f"Destination IP: {destination_ip} | "
            f"Protocol: {protocol}"
        )


if __name__ == "__main__":
    print("NETWORK PACKET ANALYZER")
    print("Waiting for network packets...")
    print("Press Ctrl+C to stop.\n")

    sniff(
        prn=analyze_packet,
        store=False
    )