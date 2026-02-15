# Port Scanner Tool

An enhanced Python-based port scanner for web reconnaissance, including service detection, vulnerability flagging, and subdomain enumeration.

## Features
- Multithreaded port scanning for speed.
- Nmap integration for service/version detection and basic vuln scans.
- Suspicious port flagging with descriptions.
- Subdomain enumeration (with sublist3r support).
- Multiple output formats: Text, JSON, HTML.
- Logging and error handling.

## Installation
1. Clone the repo: `git clone https://github.com/username/port-scanner-tool.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Install system tools: `sudo apt install nmap sublist3r` (on Linux).

## Usage
python src/port_scanner.py example.com --ports 1-1000 --format html

## Examples
- Scan a domain: `python src/port_scanner.py example.com`
- Scan an IP with JSON output: `python src/port_scanner.py 192.168.1.1 --format json`
- Custom ports: `python src/port_scanner.py example.com --ports 80,443,8080`

## Ethical Use
Only scan systems you own or have permission for. Unauthorized use is illegal.

## License
MIT License.