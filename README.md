# Nmap Scan Automator

A Python wrapper around Nmap that automates service/version scans,
parses the XML output, flags commonly attacked ports, and saves a
clean text report.

## Features
- Runs `nmap -sV` and parses the XML output
- Lists open ports with service and version info
- Flags risky ports (FTP, Telnet, SMB, RDP, etc.)
- Saves a timestamped report file
- No third-party Python libraries needed

## Requirements
- Python 3
- Nmap (`sudo apt install nmap`)

## Usage
```
python3 scanner.py scanme.nmap.org
python3 scanner.py 192.168.1.0/24 -p 1-1000
python3 scanner.py 192.168.1.10 -o myreport.txt
```

## Example Output
```
Host: 45.33.32.156
  22/tcp  ssh          OpenSSH 6.6.1p1
  80/tcp  http         Apache httpd 2.4.7
  9929/tcp nping-echo
```

## Legal Notice
Only scan systems you own or have written permission to test.
`scanme.nmap.org` is provided by the Nmap project for practice scans.

## MITRE ATT&CK Mapping
T1046 - Network Service Discovery

## Future Improvements
- CVE lookup for detected service versions
- JSON/HTML report export
- Scheduled scans with change detectionw
