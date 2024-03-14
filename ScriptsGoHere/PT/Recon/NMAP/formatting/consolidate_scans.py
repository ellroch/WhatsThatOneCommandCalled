import xml.etree.ElementTree as ET
import argparse
import os
import json
import requests
import time

def fetch_cves_for_service(service, version, api_key=None, rate_limit=1):
    rate_limit = 0.6 if api_key else 6  # Adjusted based on NVD's rate limits
    headers = {"X-Api-Key": api_key} if api_key else {}
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service} {version}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        cve_items = response.json().get('result', {}).get('CVE_Items', [])
        cves = [item['cve']['CVE_data_meta']['ID'] for item in cve_items]
        time.sleep(rate_limit)
        return cves
    else:
        print(f"Failed to fetch CVEs for {service}:{version}")
        return []

def generate_cve_mappings(xml_files, api_key=None, rate_limit=1):
    cve_mappings = {}
    for xml_file in xml_files:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            for port in host.findall('ports/port'):
                service = port.find('service').get('name') if port.find('service') is not None else None
                version = port.find('service').get('version') if port.find('service') is not None and port.find('service').get('version') is not None else None
                if service and version:
                    key = f"{service}:{version}"
                    if key not in cve_mappings:
                        cve_mappings[key] = fetch_cves_for_service(service, version, api_key, rate_limit)
    return cve_mappings

def get_xml_files_from_directory(directory_path):
    return [os.path.join(directory_path, f) for f in os.listdir(directory_path) if f.endswith('.xml')]

def parse_nmap_xml(xml_files):
    hosts_data = {}
    for xml_file in xml_files:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            ip_address = host.find('address').get('addr')
            hostnames = host.find('hostnames')
            hostname = hostnames.find('hostname').get('name') if hostnames is not None else ''
            host_info = {'hostname': hostname, 'ports': {}}
            for port in host.findall('ports/port'):
                port_id = port.get('portid')
                service_element = port.find('service')
                service_name = service_element.get('name') if service_element is not None else 'unknown'
                service_version = service_element.get('version') if service_element is not None and service_element.get('version') is not None else 'unknown'
                host_info['ports'][port_id] = {'service': service_name, 'version': service_version}
            hosts_data[ip_address] = host_info
    return hosts_data

def generate_html_report(hosts_data, cve_mappings, output_html):
    with open(output_html, 'w') as f:
        f.write("<html><head><title>Nmap Scan Report</title></head><body>")
        f.write("<h1>Nmap Scan Results</h1>")
        for host, data in hosts_data.items():
            f.write(f"<h2>{host}</h2>")
            f.write("<ul>")
            for port in data['ports']:
                service = data['ports'][port]['service']
                version = data['ports'][port].get('version', 'Unknown version')
                f.write(f"<li>Port: {port}, Service: {service}, Version: {version}")
                if cve_mappings:
                    service_version_key = f"{service}:{version}"
                    cves = cve_mappings.get(service_version_key, [])
                    if cves:
                        f.write("<ul>")
                        for cve in cves:
                            f.write(f"<li><a href='https://nvd.nist.gov/vuln/detail/{cve}'>{cve}</a></li>")
                        f.write("</ul>")
                f.write("</li>")
            f.write("</ul>")
        f.write("</body></html>")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a consolidated HTML report from Nmap XML files, optionally including CVE information.")
    parser.add_argument("xml_directory", help="Directory containing Nmap XML files.")
    parser.add_argument("output_html", help="Path for the output consolidated HTML report.")
    parser.add_argument("--cve_output_json", help="Path for the output CVE mappings JSON file. Required unless --no_cve is used.", default="")
    parser.add_argument("-k", "--api_key", help="API key for querying the NVD. Increases rate limit to 50 requests per 30 seconds.", default=None)
    parser.add_argument("-r", "--rate_limit", help="Custom rate limit in seconds for NVD queries. Defaults to 6 seconds without API key, 0.6 seconds with API key.", type=float, default=None)
    parser.add_argument("--no_cve", action="store_true", help="Disable CVE fetching and mapping.")

    args = parser.parse_args()

    xml_files = get_xml_files_from_directory(args.xml_directory)
    hosts_data = parse_nmap_xml(xml_files)

    if not args.no_cve:
        cve_mappings = generate_cve_mappings(xml_files, args.api_key, args.rate_limit)
        with open(args.cve_output_json, 'w') as f:
            json.dump(cve_mappings, f, indent=4)
        print(f"CVE mappings saved to {args.cve_output_json}")
    else:
        cve_mappings = None

    generate_html_report(hosts_data, cve_mappings, args.output_html)
    print(f"HTML report generated: {args.output_html}")
