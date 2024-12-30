Features:

    Scans a specified IP range using ARP requests.
    Lists devices with their IP and MAC addresses.
    Saves results to a text file.

Usage:

    Install scapy:

pip install scapy

Save the script to a file, e.g., network_mapper.py.
Run the tool:

    python map.py -r 192.168.1.0/24 -o results.txt

        -r specifies the IP range to scan (CIDR notation).
        -o specifies the output file (default: network_scan.txt).

Output Example:

Console:

Scanning network: 192.168.1.0/24
Found 3 devices:
IP Address              MAC Address
----------------------------------------
192.168.1.1             00:11:22:33:44:55
192.168.1.2             66:77:88:99:aa:bb
192.168.1.3             cc:dd:ee:ff:00:11

Results saved to results.txt

File (results.txt):

IP Address              MAC Address
----------------------------------------
192.168.1.1             00:11:22:33:44:55
192.168.1.2             66:77:88:99:aa:bb
192.168.1.3             cc:dd:ee:ff:00:11
