import nmap
import datetime
import requests
import base64
import sys



# CONFIGURATION

TARGET_HOST = "scanme.nmap.org"
VT_API_KEY = "SAMPLE_KEY"   # Original key not shared



# NMAP SCANNING FUNCTION

def run_nmap_scan(target):
    print("=" * 70)
    print("NETWORK RECONNAISSANCE REPORT")
    print("=" * 70)
    print(f"Target Host  : {target}")
    print(f"Scan Started : {datetime.datetime.now()}")
    print("=" * 70)

    scanner = nmap.PortScanner()

    try:
        print("\n[+] Executing Nmap Scan (-sV -Pn)...\n")
        scanner.scan(target, arguments="-sV -Pn")

        if target not in scanner.all_hosts():
            print("[-] Target unreachable or scan failed.")
            return None

        print(f"[+] Host Status : {scanner[target].state()}")
        print("\n" + "-" * 70)
        print("DISCOVERED SERVICES")
        print("-" * 70)

        results = []

        for protocol in scanner[target].all_protocols():
            ports = sorted(scanner[target][protocol].keys())

            for port in ports:
                service_info = scanner[target][protocol][port]

                record = {
                    "protocol": protocol,
                    "port": port,
                    "state": service_info.get("state"),
                    "service": service_info.get("name"),
                    "product": service_info.get("product", "N/A"),
                    "version": service_info.get("version", "N/A")
                }

                results.append(record)

                print(f"\nPort       : {port}/{protocol}")
                print(f"State      : {record['state']}")
                print(f"Service    : {record['service']}")
                print(f"Product    : {record['product']}")
                print(f"Version    : {record['version']}")
                print("-" * 40)

        # Save XML output
        xml_data = scanner.get_nmap_last_output()
        if xml_data:
            with open("nmap_scan_output.xml", "w", encoding="utf-8") as file:
                file.write(xml_data)
            print("\n[+] XML report saved as nmap_scan_output.xml")

        print("\n[+] Nmap Scan Completed Successfully\n")
        return results

    except Exception as error:
        print(f"[!] Error during Nmap scan: {error}")
        return None

# VIRUSTOTAL FUNCTION

def query_virustotal(url):
    print("\n" + "=" * 70)
    print("VIRUSTOTAL INTELLIGENCE REPORT")
    print("=" * 70)

    try:
        # URL-safe Base64 encoding (without padding)
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(vt_endpoint, headers=headers)

        if response.status_code != 200:
            print("[-] VirusTotal API Error:", response.status_code)
            return None

        return response.json()

    except Exception as error:
        print(f"[!] Error querying VirusTotal: {error}")
        return None

# VIRUSTOTAL ANALYSIS
def analyze_vt_data(vt_data):
    if not vt_data:
        print("[-] No VirusTotal data available.")
        return

    try:
        attributes = vt_data["data"]["attributes"]

        stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", "N/A")
        categories = attributes.get("categories", {})
        last_analysis_date = attributes.get("last_analysis_date", "N/A")

        print(f"\nReputation Score : {reputation}")
        print(f"Last Analysis    : {last_analysis_date}")

        print("\nDetection Summary:")
        for key, value in stats.items():
            print(f"  {key.capitalize():15}: {value}")

        print("\nCategories:")
        if categories:
            for engine, category in categories.items():
                print(f"  {engine}: {category}")
        else:
            print("  No category data available.")

        # Basic Risk Interpretation
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        print("\nSecurity Interpretation:")
        if malicious_count > 0:
            print(" Malicious detections found!")
        elif suspicious_count > 0:
            print(" Suspicious indicators detected.")
        else:
            print(" No engines flagged this URL as malicious.")

    except KeyError:
        print("[!] Unexpected VirusTotal response structure.")


# ==========================
# MAIN EXECUTION
# ==========================
if __name__ == "__main__":

    # Run Nmap
    nmap_results = run_nmap_scan(TARGET_HOST)

    # Run VirusTotal
    vt_data = query_virustotal("http://scanme.nmap.org")

    # Analyze VT results
    analyze_vt_data(vt_data)

    print("\nReport Finished.")
