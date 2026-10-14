import csv
import argparse
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
captured_packets = []


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
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    packet_counts[protocol] += 1
    total_packets += 1
    total_bytes += packet_size

    packet_record = {
        "Timestamp": timestamp,
        "Source IP": source_ip,
        "Source Port": source_port,
        "Destination IP": destination_ip,
        "Destination Port": destination_port,
        "Protocol": protocol,
        "Size (bytes)": packet_size
    }

    captured_packets.append(packet_record)

    print(
        f"{timestamp:<23} | "
        f"{source_ip:<15} | "
        f"{str(source_port):<11} | "
        f"{destination_ip:<15} | "
        f"{str(destination_port):<12} | "
        f"{protocol:<8} | "
        f"{packet_size} B"
    )


def export_to_csv(filename):
    if not captured_packets:
        print("\nNo IPv4 packets matched the selected filter.")
        return

    fieldnames = list(captured_packets[0].keys())

    with open(filename, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(captured_packets)

    print(f"\nPacket details exported to: {filename}")


def display_statistics():
    print(f"Total IPv4 packets analyzed: {total_packets}")

    print("\nProtocol Distribution:")

    for protocol, count in packet_counts.items():
        print(f"{protocol:<6}: {count}")

    print(f"\nTotal packet data captured: {total_bytes} bytes")

    if total_packets > 0:
        average_size = total_bytes / total_packets
        print(f"Average packet size: {average_size:.2f} bytes")



def main():
    global captured_packets

    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer with protocol filtering"
    )

    parser.add_argument(
        "-f",
        "--filter",
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Choose which IPv4 protocol to analyze"
    )

    args = parser.parse_args()

    capture_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"packet_capture_{args.filter}_{capture_time}.csv"

    bpf_filters = {
        "all": "ip",
        "tcp": "ip and tcp",
        "udp": "ip and udp",
        "icmp": "ip and icmp"
    }

    print("NETWORK PACKET ANALYZER")
    print(f"Selected filter: {args.filter.upper()}")
    print("Capturing packets... Press Ctrl+C to stop.\n")

    print(
        f"{'TIMESTAMP':<23} | "
        f"{'SOURCE IP':<15} | "
        f"{'SOURCE PORT':<11} | "
        f"{'DESTINATION IP':<15} | "
        f"{'DEST PORT':<12} | "
        f"{'PROTOCOL':<8} | SIZE"
    )

    print("-" * 125)

    try:
        sniff(
            filter=bpf_filters[args.filter],
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

    finally:
        export_to_csv(csv_filename)
        display_statistics()


if __name__ == "__main__":
    main()
