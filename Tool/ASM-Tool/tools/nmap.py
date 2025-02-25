from tools import get_config
# from __init__ import get_config
import subprocess
import json
import os
import xml.etree.ElementTree as ET
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

config = get_config()
GO_BIN = config.get('GO_PATH', 'GO_BINARIES')


def nmap_scan(ip, open_port,lmao):
    print(f"Scanning for vulnerabilities of {ip}")
    command = f"nmap --script vulners -Pn -sC -sV {ip} -p {open_port} -oX vulners/{ip}.xml"
    print(command)
    
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    services = []

    try:
        tree = ET.parse(f"vulners/{ip}.xml")
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return services

    root = tree.getroot()
    ports_tag = root.find('.//ports')

    if ports_tag is None:
        print("No ports found")
        return services

    for port_ele in ports_tag.findall('port'):
        port_num = port_ele.attrib.get('portid', None)
        target = None
        for i in lmao:
            if int(i['ports']) == int(port_num):
                target = i
                break
                    
        service_name = port_ele.find('./service').attrib.get('name', '')
        softwares = []

        service_product = port_ele.find('./service').attrib.get('product', '')
        service_version = port_ele.find('./service').attrib.get('version', '')
        service = {
            'vendor': service_product,
            'product': service_product,
            'version': service_version
        }
        softwares.append(service)

        service_other = port_ele.find('./service').attrib.get('extrainfo', '')
        service_other = service_other.split(" ")

        for info in service_other:
            if "/" in info:
                service_product, service_version = info.split("/")
                service = {
                    'vendor': service_product if service_product else None,
                    'product': service_product,
                    'version': service_version
                }
                softwares.append(service)

        vulns = []
        vuln_table = port_ele.findall('.//table')

        for i in range(1, len(vuln_table)):
            vuln_info = {
                "id": "",
                "cvss": "",
                "type": "",
                "is_exploit": "",
                "reference": ""
            }
            for elem_element in vuln_table[i].findall('.//elem'):
                elem_key = elem_element.attrib.get('key', None)
                elem_value = elem_element.text if elem_element.text else None
                if elem_key == "id":
                    vuln_info['id'] = elem_value
                elif elem_key == "cvss":
                    vuln_info['cvss'] = elem_value
                elif elem_key == "type":
                    vuln_info['type'] = elem_value
                else:
                    vuln_info['is_exploit'] = elem_value
            vuln_info['reference'] = f"https://vulners.com/{vuln_info['type']}/{vuln_info['id']}"
            vulns.append(vuln_info)

        try:
            response = requests.get(f"http://{ip}:{port_num}", timeout=5, verify=False)
            http_info = {
                "status_code": response.status_code,
                "status_reason": response.reason,
                "header_location": response.headers.get('Location', None),
                "html_title": ""
            }
        except requests.exceptions.RequestException as e:
            try:
                response = requests.get(f"https://{ip}:{port_num}", timeout=5, verify=False)
                http_info = {
                    "status_code": response.status_code,
                    "status_reason": response.reason,
                    "header_location": response.headers.get('Location', None),
                    "html_title": ""
                }
            except requests.exceptions.RequestException as e:
                http_info = {
                    "status_code": None,
                    "status_reason": None,
                    "header_location": None,
                    "html_title": None
                }

        info = {
            "http": {
                "request": {
                    "method": "GET",
                    "uri": f"{ip}:{port_num}"
                },
                "response": http_info
            },
            "port": port_num,
            "service_name": service_name,
            "cpe": target['cpes'],
            "software": softwares,
            "vulnerabilities": vulns
        }
        services.append(info)

    return services


def passive_scan(ip):
    try:
        PORTS = []
        print(f"[+] Checking port passively for {ip}")
        os.makedirs('passive', exist_ok=True)
        result = subprocess.run(
            [f"{GO_BIN}smap", "-sV", ip, "-oJ", f'passive/{ip}.json'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"Error executing smap: {result.stderr}")
            return {}
        
        json_file = f'passive/{ip}.json'
        if not os.path.exists(json_file):
            print(f"[-] JSON output file {json_file} not found.")
            return None, None, None
        
        with open(json_file, 'r') as f:
            data = f.read()
        json_data = json.loads(data)
        
        if isinstance(json_data, list):
            if json_data:
                operating_system = json_data[0]["os"]
                ports = json_data[0]["ports"]
            else:
                print("[-] JSON data list is empty.")
                return None, None, None
        elif isinstance(json_data, dict):
            operating_system = json_data.get("os")
            ports = json_data.get('ports')
        else:
            print("[-] Unexpected JSON structure.")
            return None, None, None
        for port in ports:
            PORTS.append(port['port'])
        os.remove(f"passive/{ip}.json")   
        return operating_system, ports, PORTS    
    except FileNotFoundError as fnf_error:
        print(f"[-] File not found: {fnf_error}")
        os.remove(f"passive/{ip}.json")
        return None,None,None
    except json.JSONDecodeError as json_error:
        print(f"[-] Error parsing JSON: {json_error}")
        os.remove(f"passive/{ip}.json")
        return None,None,None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        os.remove(f"passive/{ip}.json")
        return None, None, None


def active_scan(ip):
    print(f"[+] Checking active scan for {ip}")
    script_path = "tools/nmap_automator/nmapAutomator.sh"
    result = subprocess.run(["bash", script_path, "-H", ip, "-t", "Port"], check=True, capture_output=True, text=True)    # command = f"bash tools/nmap_automator/nmapAutomator.sh -H {ip} -t Port"
    # result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = result.stdout.splitlines()
    PORTS_DATA = []
    PORTS = []
    try:
        check = False
        for index in range(len(lines)):
            if 'STATE' in lines[index] and 'SERVICE' in lines[index]:
                cursor = index
                check = True
                break
        
        if not check:
            return {
				"ip": ip,
				"ports": 0
			}
        
        lines_tmp = lines[cursor+1:]
        port_scan_results = lines_tmp[:len(lines_tmp)-5]
        
        for port in port_scan_results:
            detail = port.split(" ")
            detail = list(filter(bool, detail))  
            if len(detail) < 3:
                continue

            detail_dict = {
                "ports": int(detail[0].strip().split("/")[0]),
                "service": detail[2].strip(),
                "cpes": None,
                "protocol": detail[0].strip().split("/")[1]
            }
            PORTS.append(int(detail[0].strip().split("/")[0]))
            PORTS_DATA.append(detail_dict)
        
        return PORTS_DATA, PORTS

    except Exception as e:
        print(f"Error: {e}")
        return PORTS_DATA, PORTS.sort()


def enrich_scan_results(scan_results, additional_info):
    for result in scan_results:
        for info in (additional_info):
            if int(result['ports']) == int(info['port']):
                if not result['service'] or result['service'].endswith('?'):
                    result['service'] = info['service']
                if not result['cpes']:
                    result['cpes'] = info['cpes']
                if not result['protocol']:
                    result['protocol'] = info['protocol']
    return scan_results

       
def merge_scan(ip):
    """
    Merge Passive and Active scan results
    Args:
        ip (str): IP address
    Returns:
        tuple: OS, list of dictionaries containing merged scan results, set of merged ports
    """  
    
    os, passive_port_info, passive_port = passive_scan(ip)
    
    
    if os is None and passive_port_info is None and passive_port is None:
        passive_port_info = []
        passive_port = set()
        
    active_port_info, active_port = active_scan(ip)
    
    if type(active_port_info) is not list:
        return None, None, None
    
    new_info = enrich_scan_results(active_port_info, passive_port_info)
    
    active_ports_in_new_info = {entry['ports'] for entry in new_info}
    
    merged_ports = set(passive_port).union(active_port)
    
    for passive_port_entry in passive_port:
        if passive_port_entry not in active_ports_in_new_info:
            for passive_info in passive_port_info:
                if passive_info['port'] == passive_port_entry:
                    passive_info_copy = passive_info.copy()  
                    passive_info_copy['ports'] = passive_info_copy.pop('port')
                    new_info.append(passive_info_copy)
                    break

    
    return os, new_info, str(merged_ports)[1:-1]

    
##############USAGE################
# os,info,port= merge_scan('ssoss.yenbai.gov.vn')    
# for i in info:
#     print(i)
# a = nmap_scan('yenbai.gov.vn', str(port).replace(', ',','),info)
# # print(os[''])
# print(os['name'])
# print(os['cpe'])
# for i in a:
#     print(json.dumps(i, indent=4))

