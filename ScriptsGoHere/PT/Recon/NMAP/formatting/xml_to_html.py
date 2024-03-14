# to use call:
# python script_name.py myscan.xml output_base_name
# python script_name.py /path/to/xml/directory output_base_name

import xml.etree.ElementTree as ET
import argparse
import os
from datetime import datetime

def parse_xml_files(xml_files):
    hosts_data = {}
    for xml_file in xml_files:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            host_ip = host.find('address').get('addr')
            hostname = host.find('hostnames/hostname').get('name') if host.find('hostnames/hostname') is not None else 'N/A'
            state = host.find('status').get('state')
            if host_ip not in hosts_data:
                hosts_data[host_ip] = {'hostname': hostname, 'state': state, 'ports': {}}
            for port in host.findall('ports/port'):
                port_id = port.get('portid')
                service = port.find('service').get('name') if port.find('service') is not None else 'N/A'
                version = port.find('service').get('version') if port.find('service') is not None and port.find('service').get('version') is not None else 'N/A'
                # Avoid duplicating port information
                if port_id not in hosts_data[host_ip]['ports']:
                    hosts_data[host_ip]['ports'][port_id] = {'service': service, 'version': version}
    return hosts_data

def generate_html_report(hosts_data, output_html):
    html_content = """
    <html>
    <head>
        <title>Nmap Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            h1 { background-color: #f2f2f2; padding: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { text-align: left; padding: 8px; }
            tr:nth-child(even) { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Nmap Scan Report</h1>
        <table>
            <tr>
                <th>Host</th>
                <th>State</th>
                <th>Port</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
    """
    for host_ip, info in hosts_data.items():
        for port_id, port_info in info['ports'].items():
            html_content += f"""
            <tr>
                <td>{host_ip}<br>({info['hostname']})</td>
                <td>{info['state']}</td>
                <td>{port_id}</td>
                <td>{port_info['service']}</td>
                <td>{port_info['version']}</td>
            </tr>
            """

    html_content += """
        </table>
    </body>
    </html>
    """
    with open(output_html, 'w') as file:
        file.write(html_content)

def get_xml_files_from_directory(directory_path):
    return [os.path.join(directory_path, f) for f in os.listdir(directory_path) if f.endswith('.xml')]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an HTML report from one or more Nmap XML files.")
    parser.add_argument("xml_source", help="The Nmap XML file or directory containing XML files.")
    parser.add_argument("output_html_base", help="The base name for the output HTML file, date will be appended.")

    args = parser.parse_args()

    current_date = datetime.now().strftime("%Y-%m-%d")
    output_html = f"{args.output_html_base}_{current_date}.html"

    if os.path.isdir(args.xml_source):
        xml_files = get_xml_files_from_directory(args.xml_source)
    elif os.path.isfile(args.xml_source) and args.xml_source.endswith('.xml'):
        xml_files = [args.xml_source]
    else:
        raise ValueError("The xml_source argument must be a valid XML file or a directory containing XML files.")

    hosts_data = parse_xml_files(xml_files)
    generate_html_report(hosts_data, output_html)
    print(f"HTML report generated: {output_html}")
