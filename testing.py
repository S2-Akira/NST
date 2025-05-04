#!/usr/bin/env python3
"""
NST (Network Security Toolkit) - A simple network security toolkit for ethical hacking
"""

import os
import sys
import socket
import subprocess
import time
import threading
import ipaddress
import argparse
import re
from datetime import datetime
import random
from scapy.all import ARP, Ether, srp
try:
    import netifaces
except ImportError:
    print("[!] netifaces module not found. Some features may not work.")
    print("[!] Install with: pip install netifaces")

# ANSI color codes for prettier output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class NST:
    def __init__(self):
        self.target = ""
        self.scan_results = {}
        self.device_list = []
        self.open_ports = []
        self.version = "1.0"
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Print the NST banner"""
        self.clear_screen()
        banner = f"""
{Colors.BLUE}███╗   ██╗███████╗████████╗{Colors.ENDC}
{Colors.BLUE}████╗  ██║██╔════╝╚══██╔══╝{Colors.ENDC}
{Colors.BLUE}██╔██╗ ██║███████╗   ██║   {Colors.ENDC}
{Colors.BLUE}██║╚██╗██║╚════██║   ██║   {Colors.ENDC}
{Colors.BLUE}██║ ╚████║███████║   ██║   {Colors.ENDC}
{Colors.BLUE}╚═╝  ╚═══╝╚══════╝   ╚═╝   {Colors.ENDC}
{Colors.YELLOW}Network Security Toolkit v{self.version}{Colors.ENDC}
{Colors.GREEN}For ethical use only{Colors.ENDC}
"""
        print(banner)

    def get_local_ip(self):
        """Get local IP address"""
        try:
            # This creates a socket to a public IP but doesn't send any data
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            print(f"{Colors.RED}[!] Error getting local IP: {e}{Colors.ENDC}")
            return "127.0.0.1"

    def get_network_interfaces(self):
        """Get list of network interfaces"""
        try:
            interfaces = netifaces.interfaces()
            print(f"{Colors.GREEN}[+] Available network interfaces:{Colors.ENDC}")
            
            for iface in interfaces:
                try:
                    if netifaces.AF_INET in netifaces.ifaddresses(iface):
                        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
                        print(f"  {Colors.BLUE}[-] {iface}: {ip}{Colors.ENDC}")
                except KeyError:
                    pass
        except NameError:
            print(f"{Colors.YELLOW}[!] netifaces module not available{Colors.ENDC}")
            local_ip = self.get_local_ip()
            print(f"{Colors.BLUE}[-] Current IP: {local_ip}{Colors.ENDC}")

    def scan_network(self, target_ip=None):
        """Scan the local network for devices using ARP"""
        if not target_ip:
            local_ip = self.get_local_ip()
            network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
        else:
            network = target_ip
            if not '/' in network:
                network += '/24'  # Default to /24 CIDR if not specified
        
        print(f"{Colors.GREEN}[+] Scanning network {network} for active devices...{Colors.ENDC}")
        self.device_list = []
        
        try:
            # Create ARP request packets for all IPs in the network
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
            packet = ether/arp
            
            # Send packets and get responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            print(f"{Colors.GREEN}[+] {len(result)} devices found:{Colors.ENDC}")
            
            # Process and display the results
            for sent, received in result:
                mac = received.hwsrc
                ip = received.psrc
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown"
                
                device_info = {'ip': ip, 'mac': mac, 'hostname': hostname}
                self.device_list.append(device_info)
                
                # Print result
                print(f"  {Colors.BLUE}[-] IP: {ip:<15} MAC: {mac:<17} Hostname: {hostname}{Colors.ENDC}")
                
            return self.device_list
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error during network scan: {e}{Colors.ENDC}")
            return []

    def port_scan(self, target_ip, port_range=None):
        """Scan ports on a target IP"""
        if not port_range:
            start_port = 1
            end_port = 1024
        else:
            try:
                if '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                else:
                    start_port = int(port_range)
                    end_port = start_port
            except ValueError:
                print(f"{Colors.RED}[!] Invalid port range. Using default (1-1024).{Colors.ENDC}")
                start_port = 1
                end_port = 1024
        
        # Validate port range
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print(f"{Colors.RED}[!] Invalid port range. Using default (1-1024).{Colors.ENDC}")
            start_port = 1
            end_port = 1024
            
        print(f"{Colors.GREEN}[+] Scanning ports {start_port}-{end_port} on {target_ip}...{Colors.ENDC}")
        self.open_ports = []
        
        # Function to scan a single port
        def scan_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    self.open_ports.append((port, service))
                    print(f"  {Colors.BLUE}[-] Port {port}/tcp open - {service}{Colors.ENDC}")
                sock.close()
            except:
                pass
        
        # Use threading to speed up the scan
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_port, args=(target_ip, port))
            threads.append(t)
            t.start()
            
            # Limit the number of concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for all remaining threads to complete
        for t in threads:
            t.join()
            
        if not self.open_ports:
            print(f"{Colors.YELLOW}[!] No open ports found.{Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}[+] Found {len(self.open_ports)} open ports.{Colors.ENDC}")
            
        return self.open_ports

    def os_detection(self, target_ip):
        """Simple OS detection using TTL values from ping"""
        print(f"{Colors.GREEN}[+] Attempting OS detection for {target_ip}...{Colors.ENDC}")
        
        try:
            if os.name == 'nt':  # Windows
                ping_cmd = f"ping -n 1 {target_ip}"
            else:  # Linux/Mac
                ping_cmd = f"ping -c 1 {target_ip}"
                
            ping_output = subprocess.check_output(ping_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            
            # Extract TTL value
            ttl_match = re.search(r"TTL=(\d+)", ping_output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                # Estimate OS based on TTL
                if ttl <= 64:
                    os_guess = "Linux/Unix/Mac OS X"
                elif ttl <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Cisco/Network Device"
                
                print(f"{Colors.GREEN}[+] OS Detection Results:{Colors.ENDC}")
                print(f"  {Colors.BLUE}[-] TTL: {ttl}{Colors.ENDC}")
                print(f"  {Colors.BLUE}[-] Possible OS: {os_guess}{Colors.ENDC}")
                return os_guess
            else:
                print(f"{Colors.YELLOW}[!] Could not determine TTL value.{Colors.ENDC}")
                return "Unknown"
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error during OS detection: {e}{Colors.ENDC}")
            return "Unknown"

    def check_common_vulnerabilities(self, target_ip, open_ports):
        """Check for common vulnerabilities based on open ports"""
        print(f"{Colors.GREEN}[+] Checking for common vulnerabilities on {target_ip}...{Colors.ENDC}")
        vulnerabilities = []
        
        for port, service in open_ports:
            # These are example vulnerability checks
            if port == 21:
                vulnerabilities.append(f"FTP service (port 21) - Potentially vulnerable to brute force attacks")
                vulnerabilities.append(f"FTP service (port 21) - Check for anonymous login")
            
            elif port == 22:
                vulnerabilities.append(f"SSH service (port 22) - Check for outdated versions vulnerable to exploits")
            
            elif port == 23:
                vulnerabilities.append(f"Telnet service (port 23) - Unencrypted protocol, credentials can be sniffed")
            
            elif port == 25 or port == 587:
                vulnerabilities.append(f"SMTP service (port {port}) - Check for open relay")
            
            elif port == 80 or port == 443:
                vulnerabilities.append(f"Web service (port {port}) - Check for common web vulnerabilities")
                vulnerabilities.append(f"Web service (port {port}) - Check for outdated web server version")
            
            elif port == 445:
                vulnerabilities.append(f"SMB service (port 445) - Check for EternalBlue vulnerability (MS17-010)")
            
            elif port == 3306:
                vulnerabilities.append(f"MySQL service (port 3306) - Check for weak password policies")
            
            elif port == 3389:
                vulnerabilities.append(f"RDP service (port 3389) - Check for BlueKeep vulnerability (CVE-2019-0708)")
                
        if vulnerabilities:
            print(f"{Colors.GREEN}[+] Potential vulnerabilities identified: {len(vulnerabilities)}{Colors.ENDC}")
            for vuln in vulnerabilities:
                print(f"  {Colors.YELLOW}[-] {vuln}{Colors.ENDC}")
        else:
            print(f"{Colors.BLUE}[-] No common vulnerabilities identified based on open ports.{Colors.ENDC}")
            
        return vulnerabilities

    def password_strength_checker(self, password=None):
        """Check password strength"""
        if not password:
            print(f"{Colors.YELLOW}[!] Enter a password to check (input is hidden):{Colors.ENDC}")
            import getpass
            password = getpass.getpass()
            
        print(f"{Colors.GREEN}[+] Checking password strength...{Colors.ENDC}")
        
        # Define criteria
        length_score = min(len(password) // 3, 5)  # Length score (max 5)
        
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        variety_score = sum([has_lower, has_upper, has_digit, has_special])
        
        # Check for common patterns
        common_patterns = [
            r'12345', r'qwerty', r'password', r'admin', r'welcome', 
            r'123456789', r'abc123', r'111111', r'987654321'
        ]
        
        pattern_found = False
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                pattern_found = True
                break
                
        repeat_chars = bool(re.search(r'(.)\1{2,}', password))  # 3+ repeating chars
        sequential = bool(re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789|890)', password, re.IGNORECASE))
        
        pattern_score = -3 if pattern_found else 0
        pattern_score += -1 if repeat_chars else 0
        pattern_score += -1 if sequential else 0
        
        # Calculate total score
        total_score = length_score + variety_score + pattern_score
        total_score = max(0, min(10, total_score))  # Clamp between 0-10
        
        # Generate result
        if total_score <= 3:
            strength = f"{Colors.RED}Weak{Colors.ENDC}"
        elif total_score <= 6:
            strength = f"{Colors.YELLOW}Moderate{Colors.ENDC}"
        elif total_score <= 8:
            strength = f"{Colors.GREEN}Strong{Colors.ENDC}"
        else:
            strength = f"{Colors.BLUE}Very Strong{Colors.ENDC}"
            
        print(f"{Colors.GREEN}[+] Password Strength Analysis:{Colors.ENDC}")
        print(f"  {Colors.BLUE}[-] Length: {len(password)} characters{Colors.ENDC}")
        print(f"  {Colors.BLUE}[-] Contains lowercase letters: {'Yes' if has_lower else 'No'}{Colors.ENDC}")
        print(f"  {Colors.BLUE}[-] Contains uppercase letters: {'Yes' if has_upper else 'No'}{Colors.ENDC}")
        print(f"  {Colors.BLUE}[-] Contains digits: {'Yes' if has_digit else 'No'}{Colors.ENDC}")
        print(f"  {Colors.BLUE}[-] Contains special characters: {'Yes' if has_special else 'No'}{Colors.ENDC}")
        
        if pattern_found:
            print(f"  {Colors.RED}[-] Contains common patterns{Colors.ENDC}")
        if repeat_chars:
            print(f"  {Colors.RED}[-] Contains repeating characters{Colors.ENDC}")
        if sequential:
            print(f"  {Colors.RED}[-] Contains sequential characters{Colors.ENDC}")
            
        print(f"  {Colors.YELLOW}[-] Overall strength: {strength} ({total_score}/10){Colors.ENDC}")
        
        # Improvement suggestions
        if total_score < 8:
            print(f"{Colors.YELLOW}[+] Suggestions for improvement:{Colors.ENDC}")
            if len(password) < 12:
                print(f"  {Colors.BLUE}[-] Increase length to at least 12 characters{Colors.ENDC}")
            if not has_lower:
                print(f"  {Colors.BLUE}[-] Add lowercase letters{Colors.ENDC}")
            if not has_upper:
                print(f"  {Colors.BLUE}[-] Add uppercase letters{Colors.ENDC}")
            if not has_digit:
                print(f"  {Colors.BLUE}[-] Add numbers{Colors.ENDC}")
            if not has_special:
                print(f"  {Colors.BLUE}[-] Add special characters (!, @, #, $, etc.){Colors.ENDC}")
            if pattern_found or repeat_chars or sequential:
                print(f"  {Colors.BLUE}[-] Avoid common patterns and sequential characters{Colors.ENDC}")
                
        return total_score, strength

    def dns_lookup(self, target):
        """Perform DNS lookup on a target domain"""
        print(f"{Colors.GREEN}[+] Performing DNS lookup for {target}...{Colors.ENDC}")
        
        try:
            ip_address = socket.gethostbyname(target)
            print(f"  {Colors.BLUE}[-] IP Address: {ip_address}{Colors.ENDC}")
            
            # Try reverse lookup
            try:
                host_info = socket.gethostbyaddr(ip_address)
                hostname = host_info[0]
                print(f"  {Colors.BLUE}[-] Hostname: {hostname}{Colors.ENDC}")
                print(f"  {Colors.BLUE}[-] Aliases: {', '.join(host_info[1])}{Colors.ENDC}")
            except socket.herror:
                print(f"  {Colors.YELLOW}[-] Reverse lookup failed{Colors.ENDC}")
                
            # Additional DNS information if available
            try:
                import dns.resolver
                print(f"{Colors.GREEN}[+] Additional DNS records:{Colors.ENDC}")
                
                # A records
                try:
                    answers = dns.resolver.resolve(target, 'A')
                    print(f"  {Colors.BLUE}[-] A records:{Colors.ENDC}")
                    for rdata in answers:
                        print(f"    {Colors.BLUE}* {rdata.address}{Colors.ENDC}")
                except:
                    pass
                    
                # MX records
                try:
                    answers = dns.resolver.resolve(target, 'MX')
                    print(f"  {Colors.BLUE}[-] MX records:{Colors.ENDC}")
                    for rdata in answers:
                        print(f"    {Colors.BLUE}* {rdata.exchange} (preference: {rdata.preference}){Colors.ENDC}")
                except:
                    pass
                    
                # NS records
                try:
                    answers = dns.resolver.resolve(target, 'NS')
                    print(f"  {Colors.BLUE}[-] NS records:{Colors.ENDC}")
                    for rdata in answers:
                        print(f"    {Colors.BLUE}* {rdata.target}{Colors.ENDC}")
                except:
                    pass
                    
                # TXT records
                try:
                    answers = dns.resolver.resolve(target, 'TXT')
                    print(f"  {Colors.BLUE}[-] TXT records:{Colors.ENDC}")
                    for rdata in answers:
                        print(f"    {Colors.BLUE}* {rdata.strings}{Colors.ENDC}")
                except:
                    pass
                    
            except ImportError:
                print(f"{Colors.YELLOW}[!] dnspython module not found. For more detailed DNS information, install it with: pip install dnspython{Colors.ENDC}")
                
            return ip_address
            
        except socket.gaierror:
            print(f"{Colors.RED}[!] Could not resolve hostname: {target}{Colors.ENDC}")
            return None

    def traceroute(self, target_ip):
        """Perform a simple traceroute to target IP"""
        print(f"{Colors.GREEN}[+] Performing traceroute to {target_ip}...{Colors.ENDC}")
        
        max_hops = 30
        timeout = 2
        
        print(f"  {Colors.BLUE}Hop  IP Address        Hostname           Time{Colors.ENDC}")
        print(f"  {Colors.BLUE}---- ----------------- ------------------ -------{Colors.ENDC}")
        
        for ttl in range(1, max_hops + 1):
            # Create socket
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            
            # Set TTL
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            
            # Set timeout
            recv_socket.settimeout(timeout)
            
            # Bind receive socket
            recv_socket.bind(("", 0))
            
            # Random destination port
            port = 33434 + ttl
            
            # Get start time
            start_time = time.time()
            
            # Send packet
            send_socket.sendto(b"", (target_ip, port))
            
            try:
                # Receive packet
                data, addr = recv_socket.recvfrom(1024)
                end_time = time.time()
                
                # Get hostname
                try:
                    hostname = socket.gethostbyaddr(addr[0])[0]
                    if len(hostname) > 18:
                        hostname = hostname[:15] + "..."
                except socket.herror:
                    hostname = "Unknown"
                    
                # Calculate time
                elapsed_time = (end_time - start_time) * 1000  # ms
                
                print(f"  {ttl:<4} {addr[0]:<17} {hostname:<18} {elapsed_time:.2f} ms")
                
                # Check if we've reached the destination
                if addr[0] == target_ip:
                    break
                    
            except socket.timeout:
                print(f"  {ttl:<4} {'*' * 17} {'Request timed out':<18} *")
                
            finally:
                send_socket.close()
                recv_socket.close()

    def generate_report(self, filename=None):
        """Generate a report of all findings"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nst_report_{timestamp}.txt"
        
        print(f"{Colors.GREEN}[+] Generating report to {filename}...{Colors.ENDC}")
        
        with open(filename, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("NST (Network Security Toolkit) Scan Report\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            # Network devices
            if self.device_list:
                f.write("NETWORK DEVICES\n")
                f.write("-" * 60 + "\n")
                for device in self.device_list:
                    f.write(f"IP: {device['ip']:<15} MAC: {device['mac']:<17} Hostname: {device['hostname']}\n")
                f.write("\n")
                
            # Open ports
            if self.open_ports and self.target:
                f.write(f"PORT SCAN RESULTS FOR {self.target}\n")
                f.write("-" * 60 + "\n")
                for port, service in self.open_ports:
                    f.write(f"Port {port}/tcp open - {service}\n")
                f.write("\n")
                
            # Vulnerabilities (if any were checked)
            if hasattr(self, 'vulnerabilities') and self.vulnerabilities:
                f.write("POTENTIAL VULNERABILITIES\n")
                f.write("-" * 60 + "\n")
                for vuln in self.vulnerabilities:
                    f.write(f"- {vuln}\n")
                f.write("\n")
                
            f.write("=" * 60 + "\n")
            f.write("End of Report\n")
            
        print(f"{Colors.GREEN}[+] Report saved to {filename}{Colors.ENDC}")
        return filename

    def interactive_menu(self):
        """Display interactive menu for the tool"""
        while True:
            self.print_banner()
            
            print(f"\n{Colors.BOLD}╔══════════════════════════════════════╗{Colors.ENDC}")
            print(f"{Colors.BOLD}║            MAIN MENU                  ║{Colors.ENDC}")
            print(f"{Colors.BOLD}╠══════════════════════════════════════╣{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}1.  Network Interface Information{Colors.ENDC}      {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}2.  Network Discovery Scan{Colors.ENDC}            {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}3.  Port Scanner{Colors.ENDC}                      {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}4.  OS Detection{Colors.ENDC}                      {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}5.  Vulnerability Check{Colors.ENDC}               {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}6.  Password Strength Checker{Colors.ENDC}         {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}7.  DNS Lookup{Colors.ENDC}                        {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}8.  Traceroute{Colors.ENDC}                        {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}9.  Generate Report{Colors.ENDC}                   {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}10. Set Target{Colors.ENDC}                        {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.BLUE}11. Full Security Scan{Colors.ENDC}                {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}║{Colors.ENDC} {Colors.RED}0.  Exit{Colors.ENDC}                             {Colors.BOLD}║{Colors.ENDC}")
            print(f"{Colors.BOLD}╚══════════════════════════════════════╝{Colors.ENDC}")
            
            if self.target:
                print(f"\n{Colors.GREEN}Current Target: {self.target}{Colors.ENDC}")
            
            choice = input(f"\n{Colors.YELLOW}Enter your choice (0-11): {Colors.ENDC}")
            
            if choice == '0':
                print(f"\n{Colors.GREEN}Exiting NST. Goodbye!{Colors.ENDC}")
                sys.exit(0)
            
            elif choice == '1':
                self.get_network_interfaces()
                
            elif choice == '2':
                target = input(f"{Colors.YELLOW}Enter network to scan (leave blank for local network): {Colors.ENDC}")
                self.scan_network(target if target else None)
                
            elif choice == '3':
                if not self.target:
                    self.target = input(f"{Colors.YELLOW}Enter target IP address: {Colors.ENDC}")
                port_range = input(f"{Colors.YELLOW}Enter port range (e.g., 1-1024) or leave blank for default: {Colors.ENDC}")
                self.port_scan(self.target, port_range if port_range else None)
                
            elif choice == '4':
                if not self.target:
                    self.target = input(f"{Colors.YELLOW}Enter target IP address: {Colors.ENDC}")
                self.os_detection(self.target)
                
            elif choice == '5':
                if not self.target:
                    self.target = input(f"{Colors.YELLOW}Enter target IP address: {Colors.ENDC}")
                if not self.open_ports:
                    print(f"{Colors.YELLOW}[!] No port scan results available. Running port scan first...{Colors.ENDC}")
                    self.port_scan(self.target)
                self.vulnerabilities = self.check_common_vulnerabilities(self.target, self.open_ports)
                
            elif choice == '6':
                self.password_strength_checker()
                
            elif choice == '7':
                target = input(f"{Colors.YELLOW}Enter domain name to lookup: {Colors.ENDC}")
                self.dns_lookup(target)
                
            elif choice == '8':
                if not self.target:
                    self.target = input(f"{Colors.YELLOW}Enter target IP address: {Colors.ENDC}")
                self.traceroute(self.target)
                
            elif choice == '9':
                filename = input(f"{Colors.YELLOW}Enter filename for report (leave blank for default): {Colors.ENDC}")
                self.generate_report(filename if filename else None)
                
            elif choice == '10':
                self.target = input(f"{Colors.YELLOW}Enter new target IP address or hostname: {Colors.ENDC}")
                if self.target:
                    # If hostname, try to resolve it
                    try:
                        socket.inet_aton(self.target)  # Check if valid IP
                    except socket.error:
                        print(f"{Colors.YELLOW}[!] Resolving hostname to IP...{Colors.ENDC}")
                        ip = self.dns_lookup(self.target)
                        if ip:
                            self.target = ip
            
            elif choice == '11':
                print(f"{Colors.GREEN}[+] Starting full security scan...{Colors.ENDC}")
                
                if not self.target:
                    self.target = input(f"{Colors.YELLOW}Enter target IP address or hostname: {Colors.ENDC}")
                    if not self.target:
                        print(f"{Colors.RED}[!] Target is required for a full scan.{Colors.ENDC}")
                        continue
                    
                    # If hostname, try to resolve it
                    try:
                        socket.inet_aton(self.target)  # Check if valid IP
                    except socket.error:
                        print(f"{Colors.YELLOW}[!] Resolving hostname to IP...{Colors.ENDC}")
                        ip = self.dns_lookup(self.target)
                        if ip:
                            self.target = ip
                        else:
                            continue
                
                # Run OS detection
                print(f"{Colors.YELLOW}[*] Step 1/4: OS Detection{Colors.ENDC}")
                self.os_detection(self.target)
                print()
                
                # Run port scan
                print(f"{Colors.YELLOW}[*] Step 2/4: Port Scanning{Colors.ENDC}")
                self.port_scan(self.target)
                print()
                
                # Check vulnerabilities
                print(f"{Colors.YELLOW}[*] Step 3/4: Vulnerability Assessment{Colors.ENDC}")
                self.vulnerabilities = self.check_common_vulnerabilities(self.target, self.open_ports)
                print()
                
                # Generate report
                print(f"{Colors.YELLOW}[*] Step 4/4: Generating Report{Colors.ENDC}")
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"nst_fullscan_{self.target}_{timestamp}.txt"
                self.generate_report(filename)
                
                print(f"{Colors.GREEN}[+] Full security scan completed!{Colors.ENDC}")
            
            else:
                print(f"{Colors.RED}[!] Invalid choice. Please try again.{Colors.ENDC}")
                
            # Pause before showing menu again
            input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.ENDC}")

def main():
    """Main function to run the tool"""
    parser = argparse.ArgumentParser(description="NST - Network Security Toolkit")
    parser.add_argument("-t", "--target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1024)")
    parser.add_argument("-s", "--scan", action="store_true", help="Perform network scan")
    parser.add_argument("-o", "--os", action="store_true", help="Perform OS detection")
    parser.add_argument("-v", "--vulns", action="store_true", help="Check for vulnerabilities")
    parser.add_argument("-r", "--report", help="Generate report to specified filename")
    args = parser.parse_args()
    
    nst = NST()
    
    # If command line arguments are provided, use them
    if args.target or args.scan or args.os or args.vulns or args.report:
        # Set target if provided
        if args.target:
            nst.target = args.target
            # Try to resolve if it's a hostname
            try:
                socket.inet_aton(nst.target)  # Check if valid IP
            except socket.error:
                print(f"{Colors.YELLOW}[!] Resolving hostname to IP...{Colors.ENDC}")
                ip = nst.dns_lookup(nst.target)
                if ip:
                    nst.target = ip
        
        # Perform network scan if requested
        if args.scan:
            nst.scan_network(nst.target if nst.target else None)
            
        # Perform port scan if target is set
        if nst.target and args.ports:
            nst.port_scan(nst.target, args.ports)
        elif nst.target:
            nst.port_scan(nst.target)
            
        # Perform OS detection if requested
        if args.os and nst.target:
            nst.os_detection(nst.target)
            
        # Check for vulnerabilities if requested
        if args.vulns and nst.target:
            if not nst.open_ports:
                print(f"{Colors.YELLOW}[!] No port scan results available. Running port scan first...{Colors.ENDC}")
                nst.port_scan(nst.target)
            nst.vulnerabilities = nst.check_common_vulnerabilities(nst.target, nst.open_ports)
            
        # Generate report if requested
        if args.report:
            nst.generate_report(args.report)
            
        sys.exit(0)
    else:
        # If no command line arguments, show interactive menu
        nst.interactive_menu()

if __name__ == "__main__":
    main()
