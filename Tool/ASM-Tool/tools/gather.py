import os
import subprocess
import requests
import json

from tools.crlf import *
from tools.open_redirect import *
from tools.xss import *
from tools.sqli import *


def check_header(domain):
    print(f"[+] Checking header of {domain}")
    url = f"http://{domain}"
    response = get_response(url)
    if response is None:
        url = f"https://{domain}"
        response = get_response(url)
    if response is None:
        return None
    subprocess.run(
        ['wapiti', '-m', 'http_headers,cookieflags,csp', '-u', url,
         '--flush-session', '-f', 'json', '-o', f'vulns/vuln_{domain}.json'],
        stderr=subprocess.PIPE, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    return 0


def get_response(url):
    try:
        response = requests.get(url, verify=False, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
    return None


def scan_CommonVulns():
    domain_files = os.listdir('result/domain_gf')
    if not domain_files:
        return 0
    
    for file in domain_files:
        with open(f'result/domain_gf/{file}', 'r') as f:
            data = json.load(f)
        domain = os.path.splitext(file)[0]
        check_header(domain)
        SQLi(domain, data)
        XSS(domain, data)
        crlf_checks(domain)
        return_openredirect(domain)

# def main():
#     scan_CommonVulns()

# if __name__ == '__main__':
#     main()