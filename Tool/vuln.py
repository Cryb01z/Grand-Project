import subprocess
import os 
import logging
import json
import tempfile
import threading
import concurrent.futures
import requests
import configparser

from tools.sqli import *
from tools.takeover import *
from tools.brokenlinks import *
from tools.gather import *

from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

config = configparser.ConfigParser()
config.read('config.ini')
logfile = config.get('LOGGING', 'log_file')

file_lock = threading.Lock()

with open('result/all_domain.txt', 'r') as file:
    ALL_DOMAIN_PATH = file.read().splitlines()


def parsing_output(array, directory):
    domain_dict = {}
    for url in array:
        domain = urlparse(url).netloc
        if domain not in domain_dict:
            domain_dict[domain] = []
        domain_dict[domain].append(url)
    with open(f'{directory}', 'w') as json_file:
        json.dump(domain_dict, json_file, indent=4)
    print(f"[+] Results saved to {directory}")


       
def ffufScan(url):
    try:
        domain = url.split('/')[0]
        print(f"Sanning {domain} with ffuf...")
        command = f"ffuf -mc 200 -w wordlist/onelistforallmicro.txt -u {domain}/FUZZ"
        result = subprocess.run(command, 
                                shell=True, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                text=True)
        result.check_returncode()
        return result.stdout.strip()
    except Exception as e:
        logging.error('Error at ffufScan function: %s', e)            


def combineUrls(katana, ffuf, output_file):
    with open(katana, 'r') as f:
        data_a = json.load(f)
    
    with open(ffuf, 'r') as f:
        data_b = json.load(f)

    merged_data = {}

    for key, urls in {**data_a, **data_b}.items():
        merged_urls = set(data_a.get(key, []) + data_b.get(key, []))
        merged_data[key] = list(merged_urls)

    with open(output_file, 'w') as f:
        json.dump(merged_data, f, indent=4)


def process_endpoint(url, key):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        if url == key:
            with open(f'dom/{url}.json', 'w') as f:
                f.write(soup.prettify())

        form_blocks = soup.find_all('form')
        form_data = []
        if form_blocks:
            for form in form_blocks:
                name_values = set()
                input_sections = form.find_all(['input', 'textarea'])
                for section in input_sections:
                    name = section.get('name')
                    if name:
                        name_values.add(name)

                action = form.get('action', '')

                if name_values or action:
                    form_data.append({
                        'action': action,
                        'name_values': sorted(name_values)
                    })

        if form_data:
            return {
                'url': url,
                'form_blocks': len(form_blocks),
                'forms': form_data
            }
    except requests.exceptions.RequestException:
        return None


def findingInput(filename):
    print("[+] Finding input fields...")
    with open(filename, 'r') as f:
        urls = json.loads(f.read())

    all_form_data = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for key, endpoint_urls in urls.items():
            for url in endpoint_urls:
                futures.append(executor.submit(process_endpoint, url, key))

        for future in as_completed(futures):
            result = future.result()
            if result:
                all_form_data.append(result)

    return all_form_data


def qsreplace(input_field, output):
    print("[+] Generating query strings...")
    formatted_urls = []

    for field in input_field:
        url = field['url']
        parsed_url = urlparse(url)
        url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        forms = field.get('forms', [])
        try:
            upload = forms[0]['action'].replace('\\','/')
            if str(upload).startswith('../'):
                upload = str(upload)[3:]
            if str(upload) == '#':
                upload = parsed_url.path.split('/')[-1] 
            name_values = forms[0]['name_values']
            query_string = "&".join([f"{name}=1" for name in name_values])
            formatted_url = f"{url+upload}?{query_string}"
            formatted_urls.append(formatted_url)
        except Exception as e:
            print(f"Error at qsreplace function: {e}")
            continue
    parsing_output(formatted_urls, output)


def gfScan(pattern):
    with open("result/qs.json", "r") as f:
        data = json.load(f)

    for key, value in data.items():
        urls = "\n".join(value)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_file.write(urls)
            temp_file.flush()

            gf_process = subprocess.Popen(
                ['gf', pattern, temp_file.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = gf_process.communicate()

            gf_output = stdout.splitlines() if stdout else []
            new_result = {
                "pattern": pattern,
                "results": gf_output
            }

            file_path = f"result/domain_gf/{key}.json"

            with file_lock:
                if os.path.exists(file_path):
                    with open(file_path, "r") as out_file:
                        try:
                            existing_data = json.load(out_file)
                        except json.JSONDecodeError:
                            existing_data = []
                else:
                    existing_data = []

                existing_data.append(new_result)

                with open(file_path, "w") as out_file:
                    json.dump(existing_data, out_file, indent=4)
            if stderr:
                print(f"Error for pattern '{pattern}' on '{key}': {stderr}")


def initial_scan():
    try:
        if not os.path.exists('result'):
            os.makedirs('result', exist_ok=True)
        brokenLinks()    
        if os.path.exists('result/katana.json') and os.path.exists('result/ffuf.json'):
            combineUrls('result/katana.json', 'result/ffuf.json', 'result/merged.json')
        
        input_element = findingInput('result/merged.json')
        qsreplace(input_element, "result/qs.json")
        
        # for url in ALL_DOMAIN_PATH:
        #     ffuf_result = ffufScan(url)
        #     if ffuf_result:
        #         parsing_output([ffuf_result], 'result/ffuf.json')
        
        gf_patterns = subprocess.run(['gf', '-list'], capture_output=True, text=True, check=True).stdout.split()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(gfScan, pattern) for pattern in gf_patterns]
            concurrent.futures.wait(futures)
        scan_CommonVulns()
        
    except Exception as e:
        logging.error("Error in main function: %s", e)


# if __name__ == "__main__":
#     logging.basicConfig(filename=logfile, level=logging.ERROR)
#     main()