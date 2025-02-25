import os
import subprocess
import json


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


def crlf_checks(domain):
    print(f"[+] Scanning for CRLF vulnerabilities in {domain}...")
    os.makedirs('.temp/crlf', exist_ok=True)
    os.makedirs('vulns', exist_ok=True)

    with open('result/katana.json', 'r') as f:
        data = json.load(f)
        urls = data.get(domain, [])

        urls_str = "\n".join(urls)

        with open(f'.temp/crlf/{domain}.txt', 'w') as temp_file:
            temp_file.write(urls_str)

        with open(f'vulns/crlf_{domain}.txt', "w") as outfile:
            subprocess.run(['crlfuzz', '-l', f'.temp/crlf/{domain}.txt', '-o', f'vulns/crlf_{domain}.txt'],
                           stdout=outfile, stderr=subprocess.PIPE)

        if os.path.getsize(f'vulns/crlf_{domain}.txt') == 0:
            print(f"[+] No CRLF vulnerabilities found for {domain}")
            os.remove(f'vulns/crlf_{domain}.txt')
        else:
            json_data = {"vulnerabilities": []}
            with open(f'vulns/crlf_{domain}.txt', 'r') as f:
                for line in f:
                    try:
                        parsed_line = json.loads(line.strip())
                        json_data["vulnerabilities"].append(parsed_line)
                    except json.JSONDecodeError:
                        print(f"Warning: Skipping non-JSON line: {line.strip()}")
            os.remove(f'vulns/crlf_{domain}.txt')
            write_vuln_file(domain, json_data, 'CRLF Injection')


# crlf_checks("example.com")