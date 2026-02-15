import socket
import subprocess
import dns.resolver
import dns.reversename
import os
import sys
import json
import logging
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from jinja2 import Template  # For HTML report generation

# Disclaimer: This tool is for educational and authorized testing purposes only.
# Do not use it on systems without permission. Unauthorized scanning may be illegal.

class PortScanner:
    def __init__(self, target, ports, timeout=1, max_workers=100):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                return port
        except Exception as e:
            logging.debug(f"Error scanning port {port}: {e}")
        finally:
            sock.close()
        return None

    def scan(self):
        logging.info(f"Scanning {len(self.ports)} ports on {self.target}...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_port, port) for port in self.ports]
            for future in as_completed(futures):
                port = future.result()
                if port:
                    self.open_ports.append(port)
        logging.info(f"Found {len(self.open_ports)} open ports: {self.open_ports}")
        return self.open_ports

class SubdomainEnumerator:
    def __init__(self, domain, wordlist=None, use_sublist3r=True):
        self.domain = domain
        self.wordlist = wordlist or ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'secure']
        self.use_sublist3r = use_sublist3r
        self.subdomains = []

    def enumerate(self):
        if self.use_sublist3r:
            try:
                logging.info("Using sublist3r for subdomain enumeration...")
                result = subprocess.run(['sublist3r', '-d', self.domain, '-o', '/tmp/subdomains.txt'], capture_output=True, text=True)
                if result.returncode == 0:
                    with open('/tmp/subdomains.txt', 'r') as f:
                        self.subdomains = [line.strip() for line in f if line.strip()]
                else:
                    logging.warning("sublist3r failed, falling back to basic DNS.")
                    self._basic_enumerate()
            except FileNotFoundError:
                logging.warning("sublist3r not installed, using basic DNS enumeration.")
                self._basic_enumerate()
        else:
            self._basic_enumerate()
        return self.subdomains

    def _basic_enumerate(self):
        for sub in self.wordlist:
            try:
                dns.resolver.resolve(f"{sub}.{self.domain}")
                self.subdomains.append(f"{sub}.{self.domain}")
            except:
                pass

class VulnerabilityChecker:
    @staticmethod
    def check_suspicious_ports(open_ports):
        suspicious = {
            21: "FTP - Often vulnerable to anonymous access or exploits (e.g., vsftpd backdoor).",
            22: "SSH - Check for weak keys, outdated versions, or brute-force attacks.",
            23: "Telnet - Insecure, plaintext protocol; easily intercepted.",
            25: "SMTP - Can be exploited for spam, relay attacks, or email spoofing.",
            53: "DNS - Potential for DNS poisoning, amplification DDoS, or zone transfers.",
            80: "HTTP - Check for web vulnerabilities (e.g., XSS, SQLi, directory traversal).",
            110: "POP3 - Insecure email protocol; susceptible to man-in-the-middle.",
            143: "IMAP - Insecure email protocol; similar risks to POP3.",
            443: "HTTPS - Ensure proper SSL/TLS; check for Heartbleed, POODLE, or misconfigurations.",
            445: "SMB - Vulnerable to EternalBlue (WannaCry), remote code execution.",
            3389: "RDP - Remote Desktop; often targeted for brute force or BlueKeep exploit.",
            8080: "HTTP Proxy - May expose internal services or be misconfigured.",
            8443: "HTTPS Alt - Similar to 443; check for weak ciphers or cert issues."
        }
        flagged = {port: suspicious[port] for port in open_ports if port in suspicious}
        return flagged

    @staticmethod
    def nmap_vuln_scan(target, open_ports):
        if not open_ports:
            return "No open ports to scan for vulnerabilities."
        port_str = ','.join(map(str, open_ports))
        try:
            # Run nmap with vuln scripts (e.g., for SSL, SMB)
            result = subprocess.run(['nmap', '-sV', '--script=vuln', '-p', port_str, target], capture_output=True, text=True, timeout=300)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Nmap vuln scan timed out."
        except FileNotFoundError:
            return "Nmap not installed."

class ReportGenerator:
    def __init__(self, target, open_ports, nmap_output, suspicious, subdomains, vuln_output, is_ip, format='text'):
        self.target = target
        self.open_ports = open_ports
        self.nmap_output = nmap_output
        self.suspicious = suspicious
        self.subdomains = subdomains
        self.vuln_output = vuln_output
        self.is_ip = is_ip
        self.format = format
        self.timestamp = datetime.now()

    def generate(self):
        data = {
            'target': self.target,
            'timestamp': str(self.timestamp),
            'type': 'IP Address' if self.is_ip else 'Domain',
            'open_ports': self.open_ports,
            'nmap_output': self.nmap_output,
            'suspicious': self.suspicious,
            'subdomains': self.subdomains,
            'vuln_output': self.vuln_output
        }
        filename = f"scan_report_{self.target.replace('.', '_')}"
        if self.format == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(data, f, indent=4)
        elif self.format == 'html':
            html_template = """
            <!DOCTYPE html>
            <html>
            <head><title>Port Scanner Report</title><style>body{font-family:Arial;} .section{margin:20px;}</style></head>
            <body>
            <h1>Port Scanner Report for {{ target }}</h1>
            <p>Generated on: {{ timestamp }}</p>
            <p>Type: {{ type }}</p>
            <div class="section"><h2>Open Ports</h2><ul>{% for port in open_ports %}<li>{{ port }}</li>{% endfor %}</ul></div>
            <div class="section"><h2>Nmap Output</h2><pre>{{ nmap_output }}</pre></div>
            <div class="section"><h2>Suspicious Ports</h2><ul>{% for port, desc in suspicious.items() %}<li>{{ port }}: {{ desc }}</li>{% endfor %}</ul></div>
            <div class="section"><h2>Subdomains</h2><ul>{% for sub in subdomains %}<li>{{ sub }}</li>{% endfor %}</ul></div>
            <div class="section"><h2>Vulnerability Scan</h2><pre>{{ vuln_output }}</pre></div>
            </body>
            </html>
            """
            template = Template(html_template)
            with open(f"{filename}.html", 'w') as f:
                f.write(template.render(**data))
        else:  # text
            with open(f"{filename}.txt", 'w') as f:
                f.write(f"=== Port Scanner Report for {self.target} ===\n")
                f.write(f"Generated on: {self.timestamp}\n")
                f.write(f"Target Type: {data['type']}\n\n")
                f.write("=== Open Ports ===\n" + '\n'.join(map(str, self.open_ports)) + "\n\n")
                f.write("=== Nmap Service and Version Detection ===\n" + self.nmap_output + "\n")
                f.write("=== Suspicious/Vulnerable Ports ===\n" + '\n'.join([f"{p}: {d}" for p, d in self.suspicious.items()]) + "\n\n")
                f.write("=== Subdomains ===\n" + '\n'.join(self.subdomains) + "\n\n")
                f.write("=== Vulnerability Scan ===\n" + self.vuln_output + "\n")
                f.write("=== End of Report ===\n")
        logging.info(f"Report saved as {filename}.{self.format}")

def get_domain_from_ip(ip):
    try:
        addr = dns.reversename.from_address(ip)
        result = dns.resolver.resolve(addr, "PTR")
        return str(result[0]).rstrip('.')
    except Exception as e:
        logging.warning(f"Reverse DNS failed: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Enhanced Port Scanner Tool")
    parser.add_argument('target', help="Target IP or domain (e.g., 192.168.1.1 or example.com)")
    parser.add_argument('--ports', type=str, default='1-1024', help="Ports to scan (e.g., 1-1024 or 80,443)")
    parser.add_argument('--format', choices=['text', 'json', 'html'], default='text', help="Output format")
    parser.add_argument('--wordlist', type=str, help="Path to subdomain wordlist (for basic enum)")
    parser.add_argument('--no-sublist3r', action='store_true', help="Disable sublist3r and use basic DNS")
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING'], default='INFO', help="Logging level")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[logging.FileHandler('scanner.log'), logging.StreamHandler()])

    target = args.target
    is_ip = target.replace('.', '').isdigit()
    domain = target
    if is_ip:
        logging.info(f"IP detected: {target}. Performing reverse DNS...")
        domain = get_domain_from_ip(target) or target

    # Parse ports
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    else:
        ports = [int(p) for p in args.ports.split(',')]

    # Initialize components
    scanner = PortScanner(target, ports)
    open_ports = scanner.scan()

    nmap_output = VulnerabilityChecker.nmap_vuln_scan(target, open_ports)  # Combined service and basic vuln
    suspicious = VulnerabilityChecker.check_suspicious_ports(open_ports)

    enumerator = SubdomainEnumerator(domain, wordlist=args.wordlist, use_sublist3r=not args.no_sublist3r)
    subdomains = enumerator.enumerate() if domain else []

    vuln_output = VulnerabilityChecker.nmap_vuln_scan(target, open_ports)  # Separate vuln scan if needed

    # Generate report
    report_gen = ReportGenerator(target, open_ports, nmap_output, suspicious, subdomains, vuln_output, is_ip, args.format)
    report_gen.generate()

    logging.info("Scan complete.")

if __name__ == "__main__":
    main()
