import os
import subprocess
import re
import json

from urllib.parse import urlparse, parse_qs, quote_plus



def write_vuln_file(domain, vuln_data, vuln_type):
    filepath = f'vulns/vuln_{domain}.json'
    
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            data = json.load(f)

    if f"{vuln_type}" not in data["vulnerabilities"]:
        data["vulnerabilities"][f"{vuln_type}"] = []
        
    data["vulnerabilities"][f"{vuln_type}"].append(vuln_data)
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    
    print(f"Added vulnerability data to {filepath}")


def SQLi(domain, json_data):
    print(f"[+] Checking SQLi for {domain}")
    sqli_results = next((item["results"] for item in json_data if item["pattern"] == "sqli"), None)
    if not sqli_results:
        return None

    sqlmap_input = f'.temp/sqlmap_{domain}.txt'
    with open(sqlmap_input, 'w') as f:
        f.writelines(f"{result}\n" for result in sqli_results)

    subprocess.run(
        ['sqlmap', '--batch', '--output-dir', '.temp/sqli/', '-m', sqlmap_input, '--flush-session'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    os.remove(sqlmap_input)
    domain_with_port = domain
    if ':' in domain:
        domain = domain.split(':')[0]

    log_path = f'.temp/sqli/{domain}/log'
    try:
        with open(log_path, 'r') as log_file:
            log_data = log_file.read()

        if not log_data:
            return None

        parsed_url = urlparse(sqli_results[0])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        script_path = parsed_url.path.split('/')[-1]
        parameters = parse_qs(parsed_url.query, keep_blank_values=True)

        for match in re.finditer(r'\s*Type:\s*(.*?)\n\s*Title:\s*(.*?)\n\s*Payload:\s*(.*?)\n', log_data, re.DOTALL):
            injection_type, title, payload = map(str.strip, match.groups())
            content_length = len(payload.encode('utf-8'))
            lmao = {
                "method": "POST",
                "path": script_path,
                "info": f"SQL Injection via injection ({injection_type} - {title})",
                "level": 8,
                "parameter": parameters,
                "module": "sql",
                "http_request": (
                    f"POST {script_path} HTTP/1.1\n"
                    f"host: {base_url}\n"
                    "connection: keep-alive\n"
                    "user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0\n"
                    "accept-language: en-US\n"
                    "accept-encoding: gzip, deflate, br\n"
                    "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n"
                    "content-type: application/x-www-form-urlencoded\n"
                    "cookie: PHPSESSID=607cca120f8425d70709c9a9db2e5a20\n"
                    f"content-length: {content_length}\n"
                    "Content-Type: application/x-www-form-urlencoded\n\n"
                    f"{quote_plus(payload)}"
                ),
                "curl_command": (
                    ""
                ),
                "wstg": ["WSTG-INPV-05"]
            }
            write_vuln_file(domain_with_port, lmao, "SQL Injection")
    
    except FileNotFoundError:
        print(f"Log file for {domain_with_port} not found.")
    
    return 0


