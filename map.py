import scapy.all as scapy
import argparse
import time
import pandas as pd


def scan(ip_range):
    """
    Scans the network to identify active devices within the given IP range.
    """
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"IP Address": element[1].psrc, "MAC Address": element[1].hwsrc})
    return devices


def monitor_network(ip_range, duration, output_file):
    """
    Monitors the network for a specified duration and saves connected devices to a spreadsheet.
    """
    print(f"Monitoring the network for {duration} seconds...")
    start_time = time.time()
    all_devices = {}

    while time.time() - start_time < duration:
        current_devices = scan(ip_range)
        for device in current_devices:
            mac = device["MAC Address"]
            if mac not in all_devices:
                all_devices[mac] = {
                    "IP Address": device["IP Address"],
                    "MAC Address": mac,
                    "First Seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                }

        # Delay before next scan
        time.sleep(5)

    # Save results to a spreadsheet
    save_to_spreadsheet(all_devices, output_file)
    print(f"\nMonitoring complete. Results saved to {output_file}")


def save_to_spreadsheet(devices, output_file):
    """
    Saves devices to a spreadsheet.
    """
    df = pd.DataFrame(devices.values())
    df.to_excel(output_file, index=False)
    print(f"Saved {len(devices)} devices to {output_file}")


def main():
    """
    Main function to handle argument parsing and monitoring.
    """
    parser = argparse.ArgumentParser(description="Python Network Monitor Tool")
    parser.add_argument("-r", "--range", required=True, help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-d", "--duration", type=int, default=120, help="Monitoring duration in seconds (default: 120)")
    parser.add_argument("-o", "--output", default="network_devices.xlsx", help="Output file to save results")
    args = parser.parse_args()

    monitor_network(args.range, args.duration, args.output)


if __name__ == "__main__":
    main()
