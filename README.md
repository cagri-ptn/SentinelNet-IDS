# SentinelNet IDS 🛡️

SentinelNet is a Python-based Network Intrusion Detection System (IDS) that monitors network traffic in real-time, detects potential DoS attacks, and logs suspicious activities.

## Features 🚀
- **Real-time Sniffing:** Analyzes IP packets and raw payloads.
- **DoS Detection:** Implements a rate-limiting algorithm to detect potential Denial of Service attacks.
- **Sensitive Data Detection:** Flags keywords like `admin`, `login`, and `password` in unencrypted traffic.
- **Logging:** Automatically saves security alerts to a local file for further investigation.

## How It Works 🛠️
The tool uses the `Scapy` library to hook into the network interface. It monitors packet frequency per second for each IP address and performs pattern matching on raw data.

## Installation 📦
1. Install [Npcap](https://npcap.com/).
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
