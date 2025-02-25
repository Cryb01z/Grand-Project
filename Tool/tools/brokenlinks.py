import os
import subprocess
import logging
import json
from urllib.parse import urlparse
from configparser import ConfigParser

config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
config = ConfigParser()
config.read(config_path)

KATANA_THREAD =   config.getint('KATANA', 'threads')
HTTPX_RATELIMIT = config.getint('HTTPX', 'rate_limit')
HTTPX_THREADS = config.getint('HTTPX', 'threads')
HTTPX_TIMEOUT = config.getint('HTTPX', 'timeout')
logfile = config.get('LOGGING', 'log_file')

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
    
def brokenLinks():
    try:
        print("[+] Scanning for broken links...")
        all_web_path = "result/all_domain.txt"
        if os.path.isfile(all_web_path) and os.path.getsize(all_web_path) > 0:
            with open(logfile, 'a') as log_file:
                result = subprocess.run(
                    ['katana', '-silent', '-list', all_web_path, '-jc', '-kf', 'all', 
                     '-c', str(KATANA_THREAD), '-d', '3', '-o', 'result/katana.txt'],
                    stderr=log_file,
                    stdout=subprocess.DEVNULL,
                )
            with open('result/katana.txt') as f:
                endpoints = [line.strip() for line in f if line.strip()]
                endpoints=set(endpoints)
                parsing_output(endpoints, 'result/katana.json')
                
            if result.returncode != 0: 
                print("[-] Katana encountered an error.")
                return

            with open('result/katana.txt') as f: 
                endpoints = [line.strip() for line in f if line.strip()]

            httpx_command = [
                "httpx", "-follow-redirects", "-random-agent", "-status-code",
                "-threads", str(HTTPX_THREADS), "-rl", str(HTTPX_RATELIMIT),
                "-timeout", str(HTTPX_TIMEOUT), "-silent", "-retries", "2", "-no-color"
            ]
            
            result = subprocess.run(httpx_command, input='\n'.join(endpoints), text=True, capture_output=True)
            
            if result.returncode == 0:
                broken_links = set()
                for line in result.stdout.splitlines():
                    if "[4" in line:
                        broken_links.add(line.split()[0])
                parsing_output(broken_links, 'vulns/broken_links.json')
            else:
                print("httpx encountered an error:", result.stderr)        
    except Exception as e:
        logging.error('Error at brokenLinks function: %s', e)