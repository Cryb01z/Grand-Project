


def XSS(domain, json_data):
    print(f"[+] Checking XSS for {domain}")
    xss_results = next((item["results"] for item in json_data if item["pattern"] == "xss"), None)
    if xss_results:
        print("XSS found.")
    return 0