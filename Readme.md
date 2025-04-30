# Network Scanner

A Python script to scan networks using Nmap, log results, and send email alerts for open ports.

## Features

    Multiple scan types

    Scheduled scans

    Email alerts

    Logging to scanner.log

## Setup

    Install dependencies:

pip install nmap pyyaml schedule

Update config.yaml with your decoy IPs and email settings.

Make the script executable:

    chmod +x scanner.py

Usage

One-time scan:

    ./scanner.py -t <target> -s <scan-type>

Scheduled scan:

    ./scanner.py -t <target> -s <scan-type> --schedule <minutes>

Example

    ./scanner.py -t 192.168.1.0/24 -s aggressive --schedule 5

Scan Types

quick, full, stealth, os-detect, version-detect, aggressive, udp-scan, top-ports-2000, slow-scan, ipv6-scan
