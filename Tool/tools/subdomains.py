from tools import get_config, safe_get
# from __init__ import get_config,safe_get
import subprocess
import json
import requests
from datetime import datetime,timezone
from urllib.parse import urlparse
from dateutil import parser

config = get_config()
GO_BIN = config.get('GO_PATH', 'GO_BINARIES')
def check_domain_availability(domain):
    """
    Check if the domain is available by trying both http and https
    Args:
        domain (str): Domain to check
    Returns:
        bool: True if domain is reachable, False otherwise
    """
    try:
        if not domain.startswith(('http://', 'https://')):
            domain_http = 'http://' + domain
            response = requests.get(domain_http, timeout=5)
            if response.status_code == 200:
                return True
        else:
            if requests.get(domain, timeout=5).status_code == 200:
                return True
    except requests.exceptions.RequestException as e:
        print(f"Error checking {domain}: {e}")
    return False

def finding_subdomain_information(domain):
    """
    Finding all suhbdomain
    Arg: 
        domains: str
    Output: 
        json_objects: list
    """    
    if str(domain).startswith(("http", "https")):
        if not check_domain_availability(domain):
            print(f"Domain {domain} is not available.")
            return {}
        domain = urlparse(domain).netloc.replace("www.", "")
    else:
        if not check_domain_availability(domain):
            print(f"Domain {domain} is not available.")
            return {}
    
    print("[+] Finding subdomain")
    
    subfinder_cmd = [f"{GO_BIN}subfinder", "-silent", "-d", domain]
    subfinder_result = subprocess.run(subfinder_cmd, capture_output=True, text=True)
    
    if subfinder_result.returncode != 0:
        print(f"Error executing subfinder: {subfinder_result.stderr}")
        return {}
    if subfinder_result.stdout == "":
        print("No subdomains found.")
        return {}
    print("[+] Finding subdomain data")
    dnsx_cmd = [f"{GO_BIN}dnsx", "-silent", "-recon", "-cdn", "-asn", "-json"]
    dnsx_result = subprocess.run(dnsx_cmd, input=subfinder_result.stdout, capture_output=True, text=True)
    
    if dnsx_result.returncode != 0:
        print(f"Error executing dnsx: {dnsx_result.stderr}")
        return {}

    uniq_result = subprocess.run(["uniq"], input=dnsx_result.stdout, capture_output=True, text=True)
    
    if uniq_result.returncode != 0:
        print(f"Error executing uniq: {uniq_result.stderr}")
        return {}
    
    raw_output = uniq_result.stdout.strip()
    

    try:
        lmao = {}
        json_lines = [line for line in raw_output.splitlines() if line.strip().startswith('{') and line.strip().endswith('}')]
        json_objects = [json.loads(line) for line in json_lines]
        for data in json_objects:
            host = data.pop("host")
            lmao[host] = data
            timestamp_str = data.get('timestamp')
            timestamp = parser.isoparse(timestamp_str)
            timestamp_utc = timestamp.astimezone(timezone.utc)
            formatted_time = timestamp_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
            lmao[host]['timestamp'] = formatted_time
        return lmao
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}


def check_asn(domain):
    print("[+] Checking ASN")
    asn = [f"{GO_BIN}asnmap", "-silent", "-i", domain, "-json"]
    asn = subprocess.run(asn, capture_output=True, text=True)
    
    if asn.returncode != 0:
        print(f"Error executing subfinder: {asn.stderr}")
        return {}
    asn_output_lines = asn.stdout.splitlines()
    json_lines = [line for line in asn_output_lines if line.startswith("{")]

    if not json_lines:
        print("No valid JSON found in the output.")
        return {}

    try:
        asn_data = json.loads(json_lines[0]) 
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return {}

    return {
        "asn": safe_get(asn_data.get('as_number')),
        "description": "None",
        "bgp_prefix": safe_get(asn_data.get('as_range')),
        "name": safe_get(asn_data.get('as_name')),
        "country_code": safe_get(asn_data.get('as_country'))
    }


# main = finding_subdomain_information('http://vulnweb.com')
# for key, value in main.items():
#     print(value)
# print(check_asn('yenbai.gov.vn'))