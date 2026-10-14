 from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP



packet_counts = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}


total_packets = 0
total_bytes = 0


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
    global total_packets, total_bytes
    if not packet.haslayer(IP):
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = identify_protocol(packet)

    source_port = "N/A"
    destination_port = "N/A"

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    packet_size = len(packet)
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    packet_counts[protocol] += 1
    total_packets += 1
    total_bytes += packet_size

    print(
        f"{timestamp:<12} | "
        f"{source_ip:<15} | "
        f"{str(source_port):<11} | "
        f"{destination_ip:<15} | "
        f"{str(destination_port):<12} | "
        f"{protocol:<8} | "
        f"{packet_size} B"
    )


def display_statistics():
    print(f"Total IPv4 packets analyzed: {total_packets}")

    print("\nProtocol Distribution:")

    for protocol, count in packet_counts.items():
        print(f"{protocol:<6}: {count}")

    print(f"\nTotal packet data captured: {total_bytes} bytes")

    if total_packets > 0:
        average_size = total_bytes / total_packets
        print(f"Average packet size: {average_size:.2f} bytes")


if __name__ == "__main__":
    print("NETWORK PACKET ANALYZER")
    print("Capturing packets... Press Ctrl+C to stop.\n")

    print(
        f"{'TIME':<12} | "
        f"{'SOURCE IP':<15} | "
        f"{'SOURCE PORT':<11} | "
        f"{'DESTINATION IP':<15} | "
        f"{'DEST PORT':<12} | "
        f"{'PROTOCOL':<8} | "
        f"SIZE"
    )

    print("-" * 105)

    try:
        sniff(
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

    finally:
        display_statistics()
