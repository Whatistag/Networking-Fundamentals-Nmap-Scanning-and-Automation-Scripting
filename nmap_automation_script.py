# Import the nmap library to interact with the Nmap scanner
import nmap

# Import datetime to record scan date and time
from datetime import datetime

# Create an object of PortScanner class
# This object will be used to perform Nmap scans
scanner = nmap.PortScanner()

# Take target IP address or hostname from the user
# Example: 127.0.0.1 or localhost
target = input("Enter target IP or hostname: ")

# Inform the user that scanning has started
print("Scanning target...")

# Perform a SYN scan (-sS) with service and version detection (-sV)
# -sS : Stealth TCP SYN scan
# -sV : Detect service version information
scanner.scan(target, arguments='-sS -sV')

# Define the output report file name
report_file = "scan_report.txt"

# Open the report file in write mode
with open(report_file, "w") as report:

    # Write report heading
    report.write("Nmap Scan Report\n")

    # Write scan timestamp
    report.write(f"Scan Time: {datetime.now()}\n")

    # Write target information
    report.write(f"Target: {target}\n\n")

    # Write table header similar to Nmap output
    report.write("PORT\tSTATE\tSERVICE\tVERSION\n")

    # Loop through all detected hosts (usually one host)
    for host in scanner.all_hosts():

        # Loop through all detected protocols (TCP / UDP)
        for proto in scanner[host].all_protocols():

            # Get all scanned ports for the protocol
            ports = scanner[host][proto].keys()

            # Loop through each port
            for port in ports:

                # Extract port-related data
                port_data = scanner[host][proto][port]

                # Port state (open/closed)
                state = port_data['state']

                # Service name (http, mysql, etc.)
                service = port_data['name']

                # Product name (Apache httpd, MariaDB, etc.)
                product = port_data.get('product', '')

                # Service version number
                version = port_data.get('version', '')

                # Extra information (OS, distro, framework details)
                extrainfo = port_data.get('extrainfo', '')

                # Combine product, version, and extra info
                # This makes the output similar to 'nmap -sV'
                full_version = f"{product} {version} ({extrainfo})".strip()

                # Write the extracted information into the report file
                report.write(
                    f"{port}/{proto}\t{state}\t{service}\t{full_version}\n"
                )

    # Write scan completion message
    report.write("\nScan completed successfully.\n")

# Inform user that scan is completed and report is saved
print("Scan completed. Report saved as scan_report.txt")
