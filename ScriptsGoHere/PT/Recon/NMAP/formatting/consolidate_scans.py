"""
Usage:
This script generates a consolidated HTML report from Nmap XML files, optionally including CVE information and CISA's KEV catalog details.

Before running, ensure you have Nmap XML output files in a designated directory.

To run the script:
python consolidate_scans.py [options] xml_directory output_html

Options:
- xml_directory: The directory containing Nmap XML files.
- output_html: The path where the output HTML report will be saved.
- --cve_output_json (optional): The path where the CVE mappings JSON file will be saved. Required unless --no_cve is used.
- -k or --api_key (optional): The API key for querying the NVD. Using an API key increases the rate limit.
- --no_cve (optional): Disables fetching and mapping CVE information.
- --kev_catalog_path (optional): The path to the CISA KEV catalog file. If the file does not exist, it will be downloaded and saved to this path. Required unless --no_kev is used.
- --no_kev (optional): Disables including KEV catalog information in the report.

Example:
python consolidate_scans.py /path/to/nmap/xmls /path/to/output/report.html --cve_output_json /path/to/output/cve_mappings.json --kev_catalog_path /path/to/kev_catalog.csv
"""

import xml.etree.ElementTree as ET
import argparse
import os
import json
import requests
import time
import csv
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_cves_for_service(service, version, api_key=None, rate_limit=1):
    rate_limit = 0.6 if api_key else 6  # Adjusted based on NVD's rate limits
    headers = {"X-Api-Key": api_key} if api_key else {}
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service} {version}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Check for HTTP request errors
        cve_items = response.json().get('result', {}).get('CVE_Items', [])
        cves = [item['cve']['CVE_data_meta']['ID'] for item in cve_items]
        time.sleep(rate_limit)  # Respect the rate limit
        return cves
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch CVEs for {service}:{version} - {e}")
        return []

def fetch_cve_details(cve_id, api_key=None):
    headers = {"X-Api-Key": api_key} if api_key else {}
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        cve_data = response.json().get('result', {}).get('CVE_Items', [])[0]
        return {
            'cvss_v3_severity': cve_data['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'N/A'),
            'cvss_v2_severity': cve_data['impact'].get('baseMetricV2', {}).get('severity', 'N/A'),
            'cwe_id': cve_data['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] if cve_data['cve']['problemtype']['problemtype_data'] else "N/A",
            # Include additional KEV list details as needed
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch details for {cve_id} - {e}")
        return {}
        
def generate_cve_mappings(xml_files, api_key=None, rate_limit=1):
    cve_mappings = {}
    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                for port in host.findall('ports/port'):
                    service = port.find('service').get('name') if port.find('service') is not None else 'unknown'
                    version = port.find('service').get('version') if port.find('service') is not None else 'unknown'
                    key = f"{service}:{version}"
                    if key not in cve_mappings and service != 'unknown' and version != 'unknown':
                        cve_mappings[key] = fetch_cves_for_service(service, version, api_key, rate_limit)
        except ET.ParseError as e:
            logging.error(f"Error parsing XML file {xml_file}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error processing file {xml_file}: {e}")
    return cve_mappings

def get_xml_files_from_directory(directory_path):
    return [os.path.join(directory_path, f) for f in os.listdir(directory_path) if f.endswith('.xml')]

def parse_nmap_xml(xml_files):
    hosts_data = {}
    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('./host'):
                # Check if the host is up
                if host.find("./status").get("state") == "up":
                    ip_address = host.find("./address[@addrtype='ipv4']").get("addr")
                    hostnames_element = host.find('hostnames')
                    hostname = hostnames_element.find('hostname').get('name') if hostnames_element is not None else ''

                    host_info = {'hostname': hostname, 'ports': {}}

                    for port in host.findall('./ports/port'):
                        port_id = port.get('portid')
                        service_element = port.find('service')
                        service_name = service_element.get('name') if service_element is not None else 'unknown'
                        service_version = service_element.get('version') if service_element is not None else 'unknown'

                        host_info['ports'][port_id] = {'service': service_name, 'version': service_version}

                    hosts_data[ip_address] = host_info
        except ET.ParseError as e:
            logging.error(f"XML parsing error in file {xml_file}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error when processing {xml_file}: {e}")
            
    return hosts_data

def download_kev_catalog(csv_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv", save_path=None):
    response = requests.get(csv_url)
    response.raise_for_status()  # Ensure the request was successful
    if save_path:
        with open(save_path, 'w', newline='', encoding='utf-8') as f:
            f.write(response.text)
    return csv.DictReader(response.text.splitlines())

def load_or_fetch_kev_catalog(kev_catalog_path):
    if os.path.exists(kev_catalog_path):
        with open(kev_catalog_path, 'r', newline='', encoding='utf-8') as f:
            return list(csv.DictReader(f))
    else:
        print("KEV catalog not found, downloading...")
        kev_entries = download_kev_catalog(save_path=kev_catalog_path)
        return list(kev_entries)

def load_or_fetch_kev_catalog(kev_catalog_path):
    if os.path.exists(kev_catalog_path):
        try:
            with open(kev_catalog_path, 'r', newline='', encoding='utf-8') as f:
                return list(csv.DictReader(f))
        except Exception as e:
            logging.error(f"Error reading KEV catalog from {kev_catalog_path} - {e}")
            # Proceed to download as fallback
    logging.info("KEV catalog not found or error reading, downloading new catalog now...")
    try:
        return download_kev_catalog(save_path=kev_catalog_path)
    except Exception as e:
        logging.error(f"Failed to download KEV catalog - {e}")
        return []

def cvss_severity_to_color(severity):
    """Convert CVSS severity to a color for HTML display."""
    return {
        'CRITICAL': 'red',
        'HIGH': 'darkorange',
        'MEDIUM': 'yellow',
        'LOW': 'lightgreen',
        'NONE': 'white',  # Default if severity is undefined or 'N/A'
    }.get(severity, 'white')

def generate_html_report(hosts_data, cve_mappings, output_html, kev_data=None):
    kev_dict = {item['cve_id']: item for item in kev_data} if kev_data else {}

    with open(output_html, 'w') as f:
        f.write("<html><head><title>Nmap Scan Report</title><style>")
        f.write("table {border-collapse: collapse;} th, td {border: 1px solid black; padding: 8px;} ")
        f.write(".critical {background-color: red;} .high {background-color: darkorange;} ")
        f.write(".medium {background-color: yellow;} .low {background-color: lightgreen;} ")
        f.write("</style></head><body>")
        f.write("<h1>Nmap Scan Results</h1>")
        
        for host, data in hosts_data.items():
            f.write(f"<h2>{host} - {data.get('hostname', '')}</h2>")
            f.write("<table><tr><th>Port</th><th>Service</th><th>Version</th><th>CVSS v3</th><th>CVSS v2</th><th>CWE ID</th><th>CVEs</th><th>KEV Info</th></tr>")
            
            for port, port_data in data['ports'].items():
                service = port_data['service']
                version = port_data.get('version', 'N/A')
                service_version_key = f"{service}:{version}"
                cves = cve_mappings.get(service_version_key, [])
                
                # Determine the highest CVSS severity for color-coding
                max_severity = "NONE"
                for cve in cves:
                    cve_details = fetch_cve_details(cve)
                    severity_v3 = cve_details['cvss_v3_severity']
                    if severity_v3 and severity_v3 != "N/A":
                        max_severity = max(max_severity, severity_v3, key=lambda s: cvss_severity_to_color(s))
                
                row_color_class = cvss_severity_to_color(max_severity).lower()
                f.write(f"<tr class='{row_color_class}'><td>{port}</td><td>{service}</td><td>{version}</td>")
                
                for cve in cves:
                    cve_details = fetch_cve_details(cve)
                    kev_info = kev_dict.get(cve)
                    kev_status = "Yes" if kev_info else "No"
                    f.write(f"<td>{cve_details['cvss_v3_severity']}</td><td>{cve_details['cvss_v2_severity']}</td><td>{cve_details['cwe_id']}</td>")
                    f.write(f"<td><a href='https://nvd.nist.gov/vuln/detail/{cve}'>{cve}</a></td>")
                    f.write(f"<td>{kev_status}</td></tr>")
            
            f.write("</table>")
        f.write("</body></html>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a consolidated HTML report from Nmap XML files, optionally including CVE information and CISA's KEV catalog details.")
    parser.add_argument("xml_directory", help="Directory containing Nmap XML files.")
    parser.add_argument("output_html", help="Path for the output consolidated HTML report.")
    parser.add_argument("--cve_output_json", help="Path for the output CVE mappings JSON file. Required unless --no_cve is used.", default="")
    parser.add_argument("-k", "--api_key", help="API key for querying the NVD. Increases rate limit to 50 requests per 30 seconds.", default=None)
    parser.add_argument("--no_cve", action="store_true", help="Disable CVE fetching and mapping.")
    parser.add_argument("--kev_catalog_path", help="Path to the KEV catalog file. If not found, it will be downloaded.", default="kev_catalog.csv")
    parser.add_argument("--no_kev", action="store_true", help="Disable KEV information inclusion.")

    args = parser.parse_args()
    
    try:
        xml_files = get_xml_files_from_directory(args.xml_directory)
        if not xml_files:
            logging.error("No XML files found in the specified directory.")
            exit()

        hosts_data = parse_nmap_xml(xml_files)

        if not args.no_cve:
            cve_mappings = generate_cve_mappings(xml_files, args.api_key, args.rate_limit)
            with open(args.cve_output_json, 'w') as f:
                json.dump(cve_mappings, f, indent=4)
            logging.info(f"CVE mappings saved to {args.cve_output_json}")

        kev_data = None
        if not args.no_kev:
            kev_data = load_or_fetch_kev_catalog(args.kev_catalog_path)

        generate_html_report(hosts_data, cve_mappings if not args.no_cve else None, args.output_html, kev_data)
        logging.info(f"HTML report generated: {args.output_html}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
