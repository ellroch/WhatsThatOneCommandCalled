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
import urllib.parse
from urllib.parse import quote

DEFAULT_RATE_LIMIT_WITH_KEY = 0.6  # 50 requests in 30 seconds
DEFAULT_RATE_LIMIT_WITHOUT_KEY = 6  # 5 requests in 30 seconds

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_nvd_search_url(service, version):
    keywords = f"{service} {version}"
    encoded_keywords = quote_plus(keywords)
    return f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={encoded_keywords}&search_type=all"

def fetch_cves_for_service(service, version, api_key=None):
    keywords = " ".join([service, version])
    encoded_keywords = quote(keywords)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_keywords}"
    headers = {"X-Api-Key": api_key} if api_key else {}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Ensure successful response
        data = response.json()
        
        cves = []
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                cve_id = vuln['cve']['CVE_data_meta']['ID']
                cvss_v2 = vuln.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                cvss_v3 = vuln.get('metrics', {}).get('cvssMetricV3', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                references = [ref['url'] for ref in vuln.get('references', [])]
                
                cves.append({
                    'cve_id': cve_id,
                    'cvss_v2': cvss_v2,
                    'cvss_v3': cvss_v3,
                    'references': references
                })
                
        return cves
    except Exception as e:
        print(f"Error fetching CVE data for {service} {version}: {e}")
        print(f"Attempting to fetch CVE data for {service} alone")
        keywords = " ".join([service])
        encoded_keywords = quote(keywords)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_keywords}"
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Ensure successful response
            data = response.json()
        
            cves = []
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve_id = vuln['cve']['CVE_data_meta']['ID']
                    cvss_v2 = vuln.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                    cvss_v3 = vuln.get('metrics', {}).get('cvssMetricV3', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                    references = [ref['url'] for ref in vuln.get('references', [])]
                
                    cves.append({
                        'cve_id': cve_id,
                        'cvss_v2': cvss_v2,
                        'cvss_v3': cvss_v3,
                        'references': references
                    })
                
            return cves
        except Exception as e:
            print(f"Error fetching CVE data for {service} alone: {e}")
            return []


def fetch_cve_details(cve_id, api_key=None):
    headers = {"X-Api-Key": api_key} if api_key else {}
    # Updated to use the 2.0 endpoint and direct CVE ID querying
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # Parsing the response to extract the relevant information
        cve_data = response.json().get('result', {}).get('CVE_Items', [])[0]
        cvss_v3 = cve_data.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
        cvss_v2 = cve_data.get('impact', {}).get('baseMetricV2', {})
        
        return {
            'cvss_v3_severity': cvss_v3.get('baseSeverity', 'N/A'),
            'cvss_v2_severity': cvss_v2.get('severity', 'N/A'),
            'cwe_id': cve_data.get('cve', {}).get('problemtype', {}).get('problemtype_data', [{}])[0].get('description', [{}])[0].get('value', 'N/A'),
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch details for {cve_id} - {e}")
        return None
        
def generate_cve_mappings(xml_files, api_key=None):
    cve_mappings = {}
    for xml_file in xml_files:
        try:
            hosts_data = parse_nmap_xml([xml_file])  # Ensure this function is correctly implemented
            for ip_address, host_data in hosts_data.items():
                for port_id, port_data in host_data['ports'].items():
                    service = port_data['service']
                    version = port_data['version']
                    # Skip fetching for unknown services or versions
                    if service == 'unknown' or version == 'unknown':
                        #logging.info(f"Skipping CVE fetch for unknown service/version: {service}:{version}")
                        continue
                    service_version_key = f"{service}:{version}"
                    if service_version_key not in cve_mappings:
                        cves = fetch_cves_for_service(service, version, api_key)
                        if cves:  # Only add entry if CVEs were found
                            cve_mappings[service_version_key] = cves
        except Exception as e:
            logging.error(f"Error generating CVE mappings from {xml_file}: {e}")
    return cve_mappings
    
def get_xml_files_from_directory(directory_path):
    return [os.path.join(directory_path, f) for f in os.listdir(directory_path) if f.endswith('.xml')]

def parse_nmap_xml(xml_files):
    hosts_data = {}
    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                # Initialize a dictionary to hold host information
                host_info = {'addresses': [], 'hostnames': [], 'ports': {}}

                # Collect all addresses (IPv4, IPv6)
                for addr in host.findall("address"):
                    if addr.get("addrtype") in ["ipv4", "ipv6"]:
                        host_info['addresses'].append(addr.get("addr"))

                # Collect all hostnames
                for hostname in host.findall('hostnames/hostname'):
                    host_info['hostnames'].append(hostname.get('name'))

                # Process port information
                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    service_element = port.find('service')
                    service_name = service_element.get('name') if service_element is not None else 'unknown'
                    service_version = service_element.get('product') if service_element is not None and service_element.get('product') is not None else 'unknown'
                    
                    # Update port information
                    host_info['ports'][port_id] = {'service': service_name, 'version': service_version}

                # Use the first address or hostname as the primary identifier, favoring addresses
                primary_identifier = host_info['addresses'][0] if host_info['addresses'] else (host_info['hostnames'][0] if host_info['hostnames'] else None)
                if primary_identifier:
                    hosts_data[primary_identifier] = host_info
        except ET.ParseError as e:
            logging.error(f"XML parsing error in file {xml_file}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error when processing {xml_file}: {e}")

    return hosts_data



def download_kev_catalog(csv_url="https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv", save_path=None):
    response = requests.get(csv_url)
    response.raise_for_status()  # Ensure the request was successful
    if save_path:
        with open(save_path, 'w', newline='', encoding='utf-8') as f:
            f.write(response.text)
    return csv.DictReader(response.text.splitlines())

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
        
def transform_kev_data(kev_list):
    kev_dict = {}
    for entry in kev_list:
        cve_id = entry.get('cve_id')  # Adjust 'cve_id' based on your KEV catalog's column name for CVE IDs
        if cve_id:
            kev_dict[cve_id] = entry  # Stores the entire row as the value
    return kev_dict


def get_severity_class(cvss_score):
    """Returns a CSS class based on CVSS score."""
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    else:
        return "low"
        
def generate_html_report(hosts_data, cve_mappings, output_html, api_key=None, kev_data=None):
    with open(output_html, 'w') as f:
        # Include the refined stylesheet and JavaScript function at the beginning of the HTML document
        f.write("""
        <html>
        <head>
            <title>Nmap Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; font-size: 14px; margin: 20px; }
                .container { margin-bottom: 20px; }
                .toggle { padding: 10px; margin-bottom: 5px; background-color: #f0f0f0; border-radius: 5px; cursor: pointer; border: 1px solid #ccc; }
                .toggle:hover { background-color: #e9e9e9; }
                .content { display: none; padding: 10px; border: 1px solid #ccc; border-top: none; border-radius: 0 0 5px 5px; background-color: #f9f9f9; }
                .critical { border-color: #ff0000; }
                .high { border-color: #ff8c00; }
                .medium { border-color: #ffd700; }
                .low { border-color: #9acd32; }
                .unknown { border-color: #d3d3d3; }
            </style>
            <script>
                function toggleVisibility(id) {
                    var elements = document.getElementsByClassName(id);
                    for (var i = 0; i < elements.length; i++) {
                        elements[i].style.display = elements[i].style.display === 'none' ? 'block' : 'none';
                    }
                }
            </script>
        </head>
        <body>
        <h1>Nmap Scan Report</h1>
        """)
            
        for host_id, host_info in hosts_data.items():
            # Mock
            logging.info(f"Processing host: {host_id}")
            # Display host information
            addresses = ', '.join(host_info['addresses'])
            hostnames = ', '.join(host_info['hostnames'])
            f.write(f'<div class="toggle" onclick="toggleVisibility(\'{host_id}\')"><strong>{host_id}</strong> - Hostnames: {hostnames}</div>\n')
            f.write(f'<div class="content {host_id}" style="display:none;">\n')


            # Iterate over services
            for port_id, port_info in host_info['ports'].items():
                # Mock
                logging.info(f"Service: {port_info['service']}, Version: {port_info.get('version', 'unknown')}")
                # Here, service_cves will be a list of CVE IDs, and fallback_url is provided if direct CVE info is unavailable
                service_key = f"{port_info['service']}:{port_info.get('version', None)}"
                if service_key in cve_mappings:
                    logging.info(f"CVE data found for {service_key}")
                else:
                    logging.info(f"No CVE data found for {service_key}")
                service_cves = cve_mappings.get(service_key, [])
                
                highest_cvss = 0
                for cve_id in service_cves:
                    cve_info = fetch_cve_details(cve_id, api_key)
                    if cve_info:
                        cvss_v3_score = float(cve_info.get('cvss_v3_severity', 0))
                        highest_cvss = max(highest_cvss, cvss_v3_score)

                severity_class = get_severity_class(highest_cvss)
                f.write(f'<div class="toggle {severity_class}" onclick="toggleVisibility(\'service{port_id}\')">Port: {port_id}, Service: {port_info["service"]}, Version: {port_info.get("version", "unknown")}</div>\n')
                f.write(f'<div id="service{port_id}" class="content service{port_id}" style="display:none;">\n')

                if not service_cves:  # Handle fallback URL logic here
                    search_query = urllib.parse.quote(f"{port_info['service']}".replace('unknown', '').strip())
                    fallback_url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={search_query}&search_type=all"
                    f.write(f'<p>No direct CVE information available. <a href="{fallback_url}" target="_blank">Search NVD for more details.</a></p>\n')
                else:
                    for cve_id in service_cves:
                        cve_info = fetch_cve_details(cve_id, api_key)
                        if cve_info:
                            cve_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                            exploitdb_link = f'https://www.exploit-db.com/search?cve={cve_id}'
                            f.write(f'<p>CVE: <a href="{cve_link}" target="_blank">{cve_id}</a>, CVSS v3: {cve_info.get("cvss_v3_severity", "N/A")}, CVSS v2: {cve_info.get("cvss_v2_severity", "N/A")}, CWE: {cve_info.get("cwe_id", "N/A")}<br>ExploitDB: <a href="{exploitdb_link}" target="_blank">Link</a></p>\n')
                
                # Include KEV information if available
                        if cve_id in kev_data:
                            kev_info = kev_data[cve_id]
                            f.write(f"<p>KEV Info: Vulnerability Name: {kev_info.get('Vulnerability Name', 'N/A')}, "
                                    f"Date Added: {kev_info.get('Date Added', 'N/A')}, "
                                    f"Due Date: {kev_info.get('Due Date', 'N/A')}, "
                                    f"Required Action: {kev_info.get('Required Action', 'N/A')}</p>\n")

                f.write('</div>\n')  # Close service details div
            f.write('</div>\n')  # Close host details div

        f.write('</body></html>')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a consolidated HTML report from Nmap XML files, optionally including CVE information and CISA's KEV catalog details.")
    parser.add_argument("xml_directory", help="Directory containing Nmap XML files.")
    parser.add_argument("output_html", help="Path for the output consolidated HTML report.")
    parser.add_argument("--cve_output_json", help="Path for the output CVE mappings JSON file. Required unless --no_cve is used.", default="")
    parser.add_argument("-k", "--api_key", help="API key for querying the NVD. Increases rate limit to 50 requests per 30 seconds (compliant with NVD rate limitations).", default=None)
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
            cve_mappings = generate_cve_mappings(xml_files, args.api_key)
            with open(args.cve_output_json, 'w') as f:
                json.dump(cve_mappings, f, indent=4)
            logging.info(f"CVE mappings saved to {args.cve_output_json}")

        kev_data = None
        if not args.no_kev:
            kev_data = load_or_fetch_kev_catalog(args.kev_catalog_path)
            kev_data = transform_kev_data(kev_data)
"""
        #################################### Mock Start
        cve_mappings = {'http:Apache httpd:2.4.29': ['CVE-2017-9798', 'CVE-2021-41773']}
        kev_data = {
            'CVE-2021-41773': {
                'Vulnerability Name': 'Path Traversal in Apache HTTP Server 2.4.49',
                'Date Added': '2021-10-05',
                'Due Date': '2021-11-02',
                'Required Action': 'Apply Patch'
            }
        }
        
        # Assuming you have variables cve_mappings and kev_data filled with mock data
        logging.info(f"Mock CVE mappings: {cve_mappings}")
        logging.info(f"Mock KEV data: {kev_data}")
        #################################### Mock End
"""
        generate_html_report(hosts_data, cve_mappings if not args.no_cve else None, args.output_html,args.api_key, kev_data)
        logging.info(f"HTML report generated: {args.output_html}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
