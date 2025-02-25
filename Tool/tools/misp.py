from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
from os import listdir
from os.path import isfile, join
import requests
import re
import zipfile
import json
import sys
import random

def init_misp(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', debug=False)

misp = init_misp(misp_url, misp_key)

def download_file(url, output_path):
    response = requests.get(url, stream=True)
    with open(output_path, 'wb') as file:
        for chunk in response:
            file.write(chunk)

def get_files(directory):
    return sorted([f for f in listdir(directory) if not f.startswith('.') and isfile(join(directory, f))])

def parse_cve_items(cve_items, skip=False, filter_id=None):
    new_events = 0
    existing_events = 0

    for cve in cve_items:
        cve_info = cve['cve']['CVE_data_meta']['ID']

        # Skip logic for filtering
        if not skip and filter_id and filter_id not in cve_info:
            print(f"{cve_info} skipped\n")
            continue
        elif not skip and filter_id and filter_id in cve_info:
            skip = True

        # Determine CVSS score and threat level
        try:
            score = cve['impact']['baseMetricV2']['cvssV2']['baseScore']
            if score < 4:
                cve_threat = 3
            elif 4 <= score <= 8:
                cve_threat = 2
            else:
                cve_threat = 1
        except KeyError:
            cve_threat = 2

        # Extract CVE details
        cve_comment = cve['cve']['description']['description_data'][0]['value']
        if "** REJECT **" in cve_comment:
            continue

        cve_date = cve.get('publishedDate', "")
        result = misp.search_index(eventinfo=cve_info)

        if result['response']:
            cve_id = result['response'][0]['id']
            event = misp.get_event(cve_id)
            if not event['Event']['published']:
                misp.fast_publish(cve_id)
            print(f"{cve_info} already exists: {event['Event']['uuid']}\n")
            existing_events += 1
        else:
            event = misp.new_event(2, cve_threat, 2, cve_info, cve_date)
            misp.fast_publish(event['Event']['id'])
            print(f"{cve_info} added: {event['Event']['uuid']}\n")
            new_events += 1

        misp.add_named_attribute(event, 'comment', cve_comment)
        print(f"CVE description added to {cve_info}")

        references = cve['cve']['references'].get('reference_data', [])
        for ref in references:
            misp.add_named_attribute(event, 'link', ref['url'])
        print(f"Added {len(references)} links into event {cve_info}\n")

        vendor_data = cve['cve']['affects']['vendor'].get('vendor_data', [])
        for vendor in vendor_data:
            for product in vendor['product']['product_data']:
                platform = f"{vendor['vendor_name']} {product['product_name']}"
                tag_text = f"ms-caro-malware:malware-platform={platform}"
                color = f"{random.randint(0, 0xFFFFFF):06x}"
                misp.new_tag(tag_text, colour=color)
                misp.tag(event['Event']['uuid'], tag_text)
                print(f"Added tag to {cve_info}: {platform}\n")

    return new_events, existing_events

def main():
    if len(sys.argv) >= 2:
        mode = sys.argv[1]
    else:
        mode = None

    if mode == "u":
        print("Script started in update mode\n")
        download_file('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip', 'nvd_recent/nvdcve_recent.zip')
        files = get_files("nvd_recent/")
    elif mode == "l":
        print("Script started in local mode\n")
        files = get_files("nvd/")
    else:
        response = requests.get('https://nvd.nist.gov/vuln/data-feeds')
        for filename in re.findall(r"nvdcve-1.0-[0-9]*\.json\.zip", response.text):
            print(f"Downloading {filename}")
            download_file(f"https://static.nvd.nist.gov/feeds/json/cve/1.0/{filename}", f"nvd/{filename}")
        files = get_files("nvd/")

    skip = False
    filter_id = None

    new_events, existing_events = 0, 0
    for file in files:
        dirname = "nvd_recent/" if mode == "u" else "nvd/"
        with zipfile.ZipFile(join(dirname, file), 'r') as archive:
            json_data = json.loads(archive.read(archive.namelist()[0]).decode('utf8'))
            new, existing = parse_cve_items(json_data['CVE_Items'], skip, filter_id)
            new_events += new
            existing_events += existing


if __name__ == "__main__":
    main()
