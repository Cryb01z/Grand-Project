import subprocess
import os
from configparser import ConfigParser

config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
config = ConfigParser()
config.read(config_path)

NUCLEI_RATELIMIT = config.get('NUCLEI', 'rate_limit')
NUCLEI_TEMPLATES_PATH = config.get('NUCLEI', 'templates_path')
# SUBDOMAIN_FILE = config.get('FILE', 'subdomains.txt')

def takeover():
    
    with open('subdomain.txt', 'r') as file:
        subdomains = file.read().splitlines()
    tkoDomains = []
    result = subprocess.run(
        ['nuclei', '-silent', '-nh', '-tags', 'takeover', '-severity', 'info,low,medium,high,critical',
         '-retries', '3', '-rl', f"{NUCLEI_RATELIMIT}", '-t', f"{NUCLEI_TEMPLATES_PATH}"],
        input='\n'.join(subdomains).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.stdout:
        tkoDomains.append(result.stdout.decode('utf-8').splitlines())
    else:
        print("No output")
    if result.stderr:
        print("Error:", result.stderr.decode('utf-8'))
    return tkoDomains
