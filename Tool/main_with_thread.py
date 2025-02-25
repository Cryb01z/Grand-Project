from tools.sslLab import *
from tools.technology import *
from tools.subdomains import *
from tools.nmap import *
import datetime
import logging
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from  json_repair import repair_json
MAIN_DOMAIN_TECH = get_web_technology("yenbai.gov.vn")

def process_subdomain(key, value):
    try:
        json_data = json.loads(repair_json(str(value).replace('\'','\"')))
        if json_data.get('asn') is not None:
            asn = json_data.pop('asn')
        else:
            asn = check_asn(f'{key}')
        ssl = sslinfo(key)
        
        operating_system,info_port, port= merge_scan(f'{key}')
        subdomain_json= parsing_technology(key)
        if subdomain_json is None:
            final_data = {
                "domain": key,
                "is_online": False,
                "discovery_reason": "FA24 Interanal Attack Surface",
                "discovery_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": json_data.get('a'),
                "services": None,
                "ssl": None,
                "technology": None,
                "autonomous_system": None,
                "operating_system": {
                    "vendor": None,
                    "cpe": None,
                    "port": None,
                },
                "dns": json_data
            }
        else:
            tech = compare_technology(MAIN_DOMAIN_TECH, subdomain_json)
            if info_port is None and port is None:
                    info_port, port = "",""
                    services = ""
                    operating_system = {"name": "",
                                        "cpes": "",
                                        "port": ""}
            else:
                services = nmap_scan(f'{key}', str(port).replace(', ',','),info_port)
                final_data = {
                        "domain": key,
                        "discovery_reason": "FA24 Interanal Attack Surface",
                        "discovery_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "ip": json_data.get('a'),
                        "services": services,
                        "ssl": ssl,
                        "technology": tech,
                        "autonomous_system": asn,
                        "operating_system": {
                            "vendor": operating_system['name'],
                            "cpe": operating_system['cpes'],
                            "port": operating_system['port'],
                        },
                        "dns": json_data
                }
                shutil.rmtree(key)
        with open('record/'+key+'.json', 'w') as f:
            json.dump(final_data, f, indent=4)            
    except Exception as e:
        logging.ERROR(f"Error at {e}")
        with open('error.log', 'a') as f:
            f.write(f"Error cannot scan at {key}\n")


def main():
    if not os.path.exists('subdomain.json'):
        subdomain_info = finding_subdomain_information('yenbai.gov.vn')
        with open('subdomain.json', 'w') as f:
            json.dump(subdomain_info, f, indent=4)
    else:
        with open('subdomain.json', 'r') as f:
            subdomain_info = json.load(f)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(process_subdomain, key, value): key for key, value in subdomain_info.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error processing {key}: {e}")

if __name__ == "__main__":
    main()