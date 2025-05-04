###🛡️ Network Security Toolkit
A powerful and user-friendly terminal-based toolkit designed for network administrators, ethical hackers, and cybersecurity professionals. This tool provides essential reconnaissance, vulnerability assessment, and reporting features in a single interface.

mathematica
Copy
Edit
╔══════════════════════════════════════╗
║            MAIN MENU                 ║
╠══════════════════════════════════════╣
║ 1.  Network Interface Information    ║
║ 2.  Network Discovery Scan           ║
║ 3.  Port Scanner                     ║
║ 4.  OS Detection                     ║
║ 5.  Vulnerability Check              ║
║ 6.  Password Strength Checker        ║
║ 7.  DNS Lookup                       ║
║ 8.  Traceroute                       ║
║ 9.  Generate Report                  ║
║ 10. Set Target                       ║
║ 11. Full Security Scan               ║
║ 0.  Exit                             ║
╚══════════════════════════════════════╝
🔧 Features
Network Interface Information
View all active network interfaces and their configurations.

Network Discovery Scan
Discover live hosts on a network using ARP or ICMP techniques.

Port Scanner
Scan open TCP/UDP ports on a specified target with customizable scan types.

OS Detection
Identify the operating system of a remote host via TCP/IP fingerprinting.

Vulnerability Check
Perform basic vulnerability assessments on open ports and known services.

Password Strength Checker
Test password strength using entropy and brute-force time estimation.

DNS Lookup
Resolve domain names, find DNS records (A, MX, TXT, etc.).

Traceroute
Map the route packets take to a remote host across the network.

Generate Report
Automatically generate detailed scan reports in .txt or .html formats.

Set Target
Set and manage your scanning target(s) for all modules.

Full Security Scan
Run a comprehensive scan that includes discovery, port scanning, OS detection, and vulnerability checking.

🚀 Getting Started
Requirements
Python 3.8+

nmap (for OS detection and advanced scanning)

netifaces, socket, scapy, dns.resolver, termcolor, prettytable (Install via pip)

Installation
bash
Copy
Edit
git clone https://github.com/yourusername/network-security-toolkit.git
cd network-security-toolkit
pip install -r requirements.txt

###🖥️ Usage
Launch the toolkit by running:

bash
Copy
Edit
python3 main.py
Navigate through the main menu using number keys to select desired modules.

📄 Reporting
Each scan or action can be saved using the Generate Report option, which creates a detailed output for logging or compliance purposes.

⚠️ Disclaimer
This toolkit is intended for educational and authorized security testing only. Unauthorized access or scanning is illegal. The developers are not responsible for any misuse of this software.

👨‍💻 Author
Created by S2
GitHub: @S2 AKIRA
