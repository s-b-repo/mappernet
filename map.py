import scapy.all as scapy
import argparse


def scan(ip_range):
    """
    Scans the network to identify active devices within the given IP range.
    """
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and receive responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Store results
    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices


def save_to_file(devices, output_file):
    """
    Saves the scanned devices to a file.
    """
    with open(output_file, "w") as file:
        file.write("IP Address\t\tMAC Address\n")
        file.write("-" * 40 + "\n")
        for device in devices:
            file.write(f"{device['ip']}\t\t{device['mac']}\n")


def main():
    """
    Main function to handle argument parsing and scanning.
    """
    parser = argparse.ArgumentParser(description="Simple Python Network Scanner")
    parser.add_argument("-r", "--range", required=True, help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", default="network_scan.txt", help="Output file to save results")
    args = parser.parse_args()

    print(f"Scanning network: {args.range}")
    devices = scan(args.range)
    if devices:
        print(f"Found {len(devices)} devices:")
        print("IP Address\t\tMAC Address")
        print("-" * 40)
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
        
        # Save results to a file
        save_to_file(devices, args.output)
        print(f"\nResults saved to {args.output}")
    else:
        print("No devices found on the network.")


if __name__ == "__main__":
    main()
