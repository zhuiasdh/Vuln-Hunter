import nmap
import requests
import json
import os
from dotenv import load_dotenv # Import the library

# 1. Load the variables from the .env file
load_dotenv()

# 2. Get the key safely
VULNERS_API_KEY = os.getenv('VULNERS_API_KEY')

# Check if it loaded correctly 
if not VULNERS_API_KEY:
    raise ValueError("Error: API Key not found. Make sure .env file exists.")

def get_vulns(service, version):
    """
    Queries the Vulners API for vulnerabilities based on service and version.
    """
    if not version or not service:
        return []

    base_url = "https://vulners.com/api/v3/burp/software/"
    
    # Payload for the API request
    payload = {
        "software": service,
        "version": version,
        "type": "software",
        "apiKey": VULNERS_API_KEY
    }
    
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(base_url, data=json.dumps(payload), headers=headers)
        data = response.json()
        
        # If vulnerabilities are found, they appear in 'data['search']'
        if data.get('result') == 'OK':
            return data.get('data', {}).get('search', [])
    except Exception as e:
        print(f"Error querying API: {e}")
        
    return []

def scan_target(target_ip):
    """
    Scans the target IP for open ports and services.
    """
    nm = nmap.PortScanner()
    print(f"Starting scan on {target_ip} (This may take a minute)...")
    
    # -sV: Version Detection
    # -T4: Aggressive timing (faster)
    try:
        nm.scan(target_ip, arguments='-sV -T4')
    except Exception as e:
        print(f"Nmap error: {e}")
        return []

    results = []

    for host in nm.all_hosts():
        print(f"Host found: {host}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service_info = nm[host][proto][port]
                service_name = service_info['product']
                version = service_info['version']
                
                print(f"Found Port {port}: {service_name} {version}")

                # Get vulnerabilities for this service
                vulns = get_vulns(service_name, version)
                
                vuln_list = []
                for v in vulns[:3]: # Limit to top 3 to keep it readable
                    vuln_list.append({
                        "id": v.get('id'),
                        "title": v.get('title'),
                        "cvss": v.get('cvss', {}).get('score', 0)
                    })

                results.append({
                    "port": port,
                    "service": service_name,
                    "version": version,
                    "vulnerabilities": vuln_list
                })
    return results

# CLI TEST BLOCK
if __name__ == "__main__":
    target = input("Enter Target IP: ")
    scan_data = scan_target(target)
    print(json.dumps(scan_data, indent=4))