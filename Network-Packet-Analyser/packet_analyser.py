import argparse
import csv
import logging
import math
import sys

from datetime import datetime
from pathlib import Path
from time import monotonic

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, Raw

PROTOCOL_FILTERS = {
    "all": "ip",
    "tcp": "ip and tcp",
    "udp": "ip and udp",
    "icmp": "ip and icmp",
}

CSV_FIELDS = [
    "Timestamp",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Size (bytes)",
    "Payload (hex)",
]

packet_counts = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0,
}

total_packets = 0
total_bytes = 0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


def identify_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    return "Other"


def extract_payload(packet):
    """Return the application-data candidate as hexadecimal text."""
    if packet.haslayer(Raw):
        return bytes(packet[Raw].load).hex()

    return ""


def analyze_packet(packet, csv_writer, csv_file):
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

    timestamp = datetime.fromtimestamp(
        float(packet.time)
    ).astimezone().isoformat(timespec="milliseconds")

    payload_hex = extract_payload(packet)

    packet_record = {
        "Timestamp": timestamp,
        "Source IP": source_ip,
        "Source Port": source_port,
        "Destination IP": destination_ip,
        "Destination Port": destination_port,
        "Protocol": protocol,
        "Size (bytes)": packet_size,
        "Payload (hex)": payload_hex,
    }

    packet_counts[protocol] += 1
    total_packets += 1
    total_bytes += packet_size

    csv_writer.writerow(packet_record)
    csv_file.flush()

    print(
        f"{timestamp:<29} | "
        f"{source_ip:<15} | "
        f"{str(source_port):<11} | "
        f"{destination_ip:<15} | "
        f"{str(destination_port):<12} | "
        f"{protocol:<8} | "
        f"{packet_size} B",
        flush=True,
    )


def display_statistics(start_time):
    duration = monotonic() - start_time

    print("\nCAPTURE SUMMARY")
    print(f"Total IPv4 packets analyzed: {total_packets}")
    print(f"Total packet bytes: {total_bytes}")
    print(f"Capture duration: {duration:.2f} seconds")

    if duration > 0:
        print(
            f"Average packet rate: "
            f"{total_packets / duration:.2f} packets/sec"
        )
        print(
            f"Average byte rate: "
            f"{total_bytes / duration:.2f} bytes/sec"
        )

    if total_packets > 0:
        average_size = total_bytes / total_packets
        print(f"Average packet size: {average_size:.2f} bytes")

    print("\nProtocol Distribution:")

    for protocol, count in packet_counts.items():
        percentage = (
            count / total_packets * 100
            if total_packets > 0
            else 0
        )

        print(
            f"{protocol:<6}: {count:>6} packets "
            f"({percentage:.2f}%)"
        )


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-i",
        "--iface",
        help="Network interface to monitor",
    )

    parser.add_argument(
        "-f",
        "--filter",
        choices=PROTOCOL_FILTERS.keys(),
        default="all",
        help="Protocol filter",
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Maximum matching packets; 0 means unlimited",
    )

    parser.add_argument(
        "-d",
        "--duration",
        type=float,
        default=0,
        help="Maximum capture duration in seconds; 0 means unlimited",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Custom CSV output path",
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count cannot be negative")

    if not math.isfinite(args.duration) or args.duration < 0:
        parser.error("--duration must be a finite, non-negative number")

    if args.count == 0 and args.duration == 0:
        logger.warning(
            "Capture has no count or duration limit. "
            "Press Ctrl+C to stop."
        )

    return args


def main():
    global packet_counts, total_packets, total_bytes

    args = parse_arguments()

    packet_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Other": 0,
    }
    total_packets = 0
    total_bytes = 0

    if args.iface:
        try:
            interfaces = get_if_list()
        except Exception as error:
            logger.error("Unable to list network interfaces: %s", error)
            return 1

        if args.iface not in interfaces:
            logger.error(
                "Network interface '%s' was not found.",
                args.iface,
            )
            print("\nAvailable interfaces:")

            for interface in interfaces:
                print(f"  - {interface}")

            return 1

    capture_time = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.output:
        output_path = Path(args.output).expanduser()
    else:
        output_path = (
            Path("captures")
            / f"packet_capture_{args.filter}_{capture_time}.csv"
        )

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    except OSError as error:
        logger.error("Unable to create output directory: %s", error)
        return 1

    capture_filter = PROTOCOL_FILTERS[args.filter]

    print(f"Interface: {args.iface or 'Default interface selection'}")
    print(f"Protocol filter: {args.filter.upper()}")
    print(f"Capture filter: {capture_filter}")
    print(f"Packet limit: {args.count or 'Unlimited'}")
    print(f"Duration limit: {args.duration or 'Unlimited'} seconds")
    print(f"CSV output: {output_path}")
    print("\nPress Ctrl+C to stop capturing.")
    print(
        f"{'TIMESTAMP':<29} | "
        f"{'SOURCE IP':<15} | "
        f"{'SOURCE PORT':<11} | "
        f"{'DESTINATION IP':<15} | "
        f"{'DEST PORT':<12} | "
        f"{'PROTOCOL':<8} | SIZE"
    )

    start_time = monotonic()
    capture_error = False

    try:
        with output_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as csv_file:

            csv_writer = csv.DictWriter(
                csv_file,
                fieldnames=CSV_FIELDS,
            )
            csv_writer.writeheader()
            csv_file.flush()

            logger.info("Packet capture started.")

            sniff(
                iface=args.iface,
                filter=capture_filter,
                prn=lambda packet: analyze_packet(
                    packet,
                    csv_writer,
                    csv_file,
                ),
                store=False,
                count=args.count,
                timeout=args.duration or None,
            )

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
        logger.info("Capture interrupted by user.")

    except PermissionError:
        logger.error(
            "Permission denied. Check packet-capture permissions "
            "and output-file permissions."
        )
        capture_error = True

    except OSError as error:
        logger.error("Network or file error: %s", error)
        capture_error = True

    except Exception as error:
        logger.error("Packet capture failed: %s", error)
        capture_error = True

    finally:
        print(f"\nCSV output: {output_path}")
        display_statistics(start_time)
        logger.info("Packet capture session ended.")

    return 1 if capture_error else 0


if __name__ == "__main__":
    sys.exit(main())
