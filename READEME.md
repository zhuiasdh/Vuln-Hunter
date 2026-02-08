# 🕸️ VulnHunter - Network Vulnerability Scanner

## 🚀 Overview
VulnHunter is a lightweight vulnerability scanner that bridges the gap between basic port scanning and vulnerability assessment. It uses **Nmap** for service discovery and the **Vulners API** to map discovered services to known CVEs in real-time.

## 🛠️ Features
- **Port Scanning:** Identifies open ports and running services.
- **Service Enumeration:** Detects service versions (e.g., Apache 2.4.49).
- **Vulnerability Mapping:** Queries the Vulners database for CVEs.
- **Web Interface:** Clean, responsive dashboard built with Flask & Bootstrap.
- **Reporting:** Generates detailed HTML reports for each scan.

## 📦 Installation
1. Clone the repo:
   ```bash
   git clone [https://github.com/zhuiasdh/vulnhunter.git](https://github.com/zhuiasdh/vulnhunter.git)