# Networking-Fundamentals-Nmap-Scanning-and-Automation-Scripting
This project focuses on building a strong foundation in networking concepts such as IP addressing, ports, and communication protocols, while gaining practical experience with Nmap, a widely used network scanning and security auditing tool.
The project also emphasizes the importance of analyzing scan results to identify security risks associated with exposed services.
For hands-on learning, OWASP Juice Shop, an intentionally vulnerable web application, is used as the target and is hosted locally on localhost (127.0.0.1). Since the application is designed for educational and authorized testing, it provides a safe environment to practice real-world scanning and analysis techniques without violating ethical or legal boundaries.
In addition to manual scanning, this project introduces automation through Python scripting using the python-nmap library. Automating the scanning process improves efficiency, reduces human error, and demonstrates practical scripting skills required in modern security operations. Overall, this project integrates networking knowledge, security assessment, and automation to simulate a real-world penetration testing workflow.


# Objective
The objective of this project is to understand basic networking concepts, perform network scanning using Nmap, analyze the scan results for potential security risks, and automate the scanning process using Python scripting. This project strengthens foundational knowledge in networking, cybersecurity, and automation.

# Networking Fundamentals
IP Address
An IP (Internet Protocol) address uniquely identifies a device on a network. IPv4 addresses are written in dotted decimal format (e.g., 192.168.1.100).
Ports
Ports are logical communication endpoints on a device. Common ports include:
Protocols

•	TCP (Transmission Control Protocol): Reliable, connection-oriented protocol.

•	UDP (User Datagram Protocol): Faster, connectionless protocol with no delivery guarantee.

# Nmap Overview
Nmap (Network Mapper) is a powerful open-source tool used for:

•	Network discovery

•	Port scanning

•	Service and OS detection

•	Security auditing

 Installation Verification
nmap -v
This command confirms that Nmap is installed successfully.

Target Description

•	Target Application: OWASP Juice Shop (Vulnerable Web Application)

•	Hosting Environment: Localhost (Docker / Node.js application)

•	Target IP Address: 127.0.0.1

•	Target URL: http://localhost:3000

•	Authorization: OWASP Juice Shop is intentionally vulnerable and deployed locally for educational and authorized security testing purposes only.

# Nmap Scans Performed
1. SYN Scan - Performs a stealth TCP SYN scan
nmap -sS 127.0.0.1 -oN syn_scan.txt
 <img width="906" height="277" alt="image" src="https://github.com/user-attachments/assets/0356b1df-d91b-42bf-b1a4-623a26b5c833" />

Screenshot 1 - Output for SYN scan

2. TCP Connect Scan - Uses a full TCP handshake and Confirms service accessibility on the Juice Shop port
nmap -sT 127.0.0.1 -oN tcp_scan.txt
<img width="908" height="280" alt="image" src="https://github.com/user-attachments/assets/783269bc-a1da-4172-bbe8-72acdd1dee65" /> 

Screenshot 2 – Output for TCP scan

3. UDP Scan - Checks for open UDP services on localhost
nmap -sU 127.0.0.1 -oN udp_scan.txt
<img width="910" height="208" alt="image" src="https://github.com/user-attachments/assets/7c2088c9-559a-4b03-a623-1680c9d3194a" />

Screenshot 3 – Output for UDP scan


# Scan Results Analysis
A service version detection scan (nmap -sV) was performed on the target system (127.0.0.1) to identify active services and their running versions. The scan revealed multiple open TCP ports, indicating that several services are actively listening on the localhost system.


# Security Risk Analysis 

The Nmap scan of 127.0.0.1 revealed multiple open TCP ports, which increases the system’s attack surface if exposed beyond the local environment.

•	Port 80 (HTTP):
Uses an unencrypted protocol, making it vulnerable to attacks such as packet sniffing, session hijacking, and man-in-the-middle (MITM). Web applications on this port may also suffer from XSS, SQL Injection, and misconfigurations.

•	Port 3000 (ppp):
Commonly used for development applications. OWASP Juice Shop is intentionally vulnerable and includes OWASP Top 10 issues like SQL Injection, XSS, and broken authentication. Exposing such services publicly poses high security risks.

•	Port 3306 (MySQL / MariaDB):
An exposed database service is a critical risk, as attackers can attempt brute-force attacks or exploit weak credentials, potentially leading to data compromise.

# Service Research

1. HTTP (Port 3000 – OWASP Juice Shop)
 
•	Purpose: Deliberately vulnerable web application for security training

•	Technology Stack:

o	Node.js

o	Express.js

o	Angular

•	Common Vulnerabilities:

o	SQL Injection

o	Cross-Site Scripting (XSS)

o	Broken Access Control

o	Insecure Authentication

4. MySQL / MariaDB (Port 3306)
   
•	Purpose:
Port 3306 is used by MySQL/MariaDB database servers to manage and store application data, including user credentials, product information, and transaction records.

•	Common Vulnerabilities:
Exposed database services may be vulnerable to brute-force login attempts, weak or default credentials, SQL misconfigurations, and exploitation of known database version vulnerabilities.

•	Security Best Practice:
Database services should be restricted to localhost or internal networks only, protected with strong authentication, and regularly updated to prevent unauthorized access.

# Network Diagram:
A simple network diagram was created using draw.io, showing:

•	Attacker Machine (Kali Linux)

•	Localhost Target (OWASP Juice Shop – 127.0.0.1)

•	Open Port: 3000 (HTTP)

•	Scan direction from Kali Linux to OWASP Juice Shop application

 <img width="941" height="327" alt="image" src="https://github.com/user-attachments/assets/87ae7ea8-19f3-4cb3-8933-4feeb6d41771" />

Screenshot - Network Diagram
 
# Python Automation Script :
<img width="618" height="610" alt="image" src="https://github.com/user-attachments/assets/af6fb0dd-7ca2-4b59-b9e5-96e5f4de6352" />

Screenshot - Python Automation Script

# Sample Output :
<img width="620" height="399" alt="image" src="https://github.com/user-attachments/assets/256e5c19-d24d-4048-b263-7f39170aeebe" />

Screenshot – Output of the automation script

Contains scan timestamp, target IP, open ports, services, and completion note
# Key Learnings

•	Understood how IP addresses, ports, and protocols work together in a network

•	Learned different Nmap scan types and their purposes

•	Identified common security risks from open services

•	Gained hands-on experience in automating security projects using Python

•	Improved technical documentation and reporting skills


# Conclusion

This project provided practical exposure to network scanning and security assessment. By combining Nmap scanning with Python automation, the project demonstrates essential skills required for cybersecurity and network analysis roles.
________________________________________
