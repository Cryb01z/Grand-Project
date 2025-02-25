import re
import ssl
import requests
import warnings
import random
import os
import json

from bs4 import BeautifulSoup
from urllib.parse import parse_qs,urlparse,urlunparse
from configparser import ConfigParser

config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
config = ConfigParser()
config.read(config_path)
PAYLOADS = config.get('WORDLIST', 'openredirect_wordlist')
file = open(PAYLOADS, encoding='utf-8').read().splitlines()

user = config.get('USERAGENT', 'USERAGENTS').split(',')

request = requests.Session()

warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context

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

def get_valid_user_agent(user_agents):
    while True:
        chosen_user_agent = random.choice(user_agents)
        parts = chosen_user_agent.split(": ", 1)
        if len(parts) > 1:
            return {"User-Agent": parts[1].strip('"')}
        
header = get_valid_user_agent(user)
VULNERS = {
        "meta_tag": False,
        "header_base_redirect": [],
        "js_redirect": False,
        "js_sources": []
    }
def requester(url, parameters=''):
    webOBJ = request.get(url, allow_redirects=False, headers=header, timeout=10, verify=False, params=parameters)
    return webOBJ

def generator(url,payloads):
    root = urlparse(url).netloc
    regPay = []
    for payload in payloads:
        regPay.append("{}.{}".format(payload,root))
        regPay.append("{}/{}".format(payload,root))
    return regPay

def multitest(url,payloads):
    if urlparse(url).scheme == '': url = 'http://' + url

    regexBypassPayloads = generator(url,payloads)
    if '=' in url:
        if url.endswith('='): url += 'r007'
        parsedQueries = parse_qs(urlparse(url).query)
        keys = [key for key in parsedQueries]
        values = [value for value in parsedQueries.values()]

        parsedURL = list(urlparse(url))
        parsedURL[-2] = ''
        finalURL = urlunparse(parsedURL)

        queries = []
        count = 0
        for key in keys:
            for payload in payloads:
                parsedQueries[key] = payload
                queries.append(parsedQueries.copy())

            for payload in regexBypassPayloads:
                parsedQueries[key] = payload
                queries.append(parsedQueries.copy())

            parsedQueries[key] = values[count]
            count += 1
        return queries,finalURL
    else:
        urls = []
        if not url.endswith('/'):
            url += '/'
            
        for payload in payloads:
            urls.append(url+payload)

        for payload in regexBypassPayloads:
            urls.append(url+payload)
        return urls


def open_redirect(url):
    multi_test_call = multitest(url, file)
    print(f"[+] Scanning for Open Redirect on {url}")

    if isinstance(multi_test_call, tuple):
        for params in multi_test_call[0]:
            if custome_request(multi_test_call[1], params):
                break
    else:
        for url in multi_test_call:
            if custome_request(url):
                break


def custome_request(URI, params=''):
    try:
        page = requester(URI, params)
    except requests.exceptions.Timeout:
        print(f"[Timeout] {URI}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection Error with {URI}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred: {e}")
        return False

    return check(page, page.request.url)

              
def check(resp_obj, final_url):
    payload = "|".join([re.escape(i) for i in file])
    redirect_codes = range(300, 311)
    error_codes = range(400, 411)
    soup = BeautifulSoup(resp_obj.text, 'html.parser')

    google_search = re.search(payload, str(soup.find_all("script")), re.IGNORECASE)
    meta_tags = str(soup.find_all('meta'))
    meta_tag_search = re.search(payload, meta_tags, re.IGNORECASE)

    sourcesSinks = [  
                "location.href",
                "location.hash",
                "location.search",
                "location.pathname",
                "document.URL",
                "window.name",
                "document.referrer",
                "document.documentURI",
                "document.baseURI",
                "document.cookie",
                "location.hostname",
                "jQuery.globalEval",
                "eval",
                "Function",
                "execScript",
                "setTimeout",
                "setInterval",
                "setImmediate",
                "msSetImmediate",
                "script.src",
                "script.textContent",
                "script.text",
                "script.innerText",
                "script.innerHTML",
                "script.appendChild",
                "script.append",
                "document.write",
                "document.writeln",
                "jQuery",
                "jQuery.$",
                "jQuery.constructor",
                "jQuery.parseHTML",
                "jQuery.has",
                "jQuery.init",
                "jQuery.index",
                "jQuery.add",
                "jQuery.append",
                "jQuery.appendTo",
                "jQuery.after",
                "jQuery.insertAfter",
                "jQuery.before",
                "jQuery.insertBefore",
                "jQuery.html",
                "jQuery.prepend",
                "jQuery.prependTo",
                "jQuery.replaceWith",
                "jQuery.replaceAll",
                "jQuery.wrap",
                "jQuery.wrapAll",
                "jQuery.wrapInner",
                "jQuery.prop.innerHTML",
                "jQuery.prop.outerHTML",
                "element.innerHTML",
                "element.outerHTML",
                "element.insertAdjacentHTML",
                "iframe.srcdoc",
                "location.replace",
                "location.assign",
                "window.open",
                "iframe.src",
                "javascriptURL",
                "jQuery.attr.onclick",
                "jQuery.attr.onmouseover",
                "jQuery.attr.onmousedown",
                "jQuery.attr.onmouseup",
                "jQuery.attr.onkeydown",
                "jQuery.attr.onkeypress",
                "jQuery.attr.onkeyup",
                "element.setAttribute.onclick",
                "element.setAttribute.onmouseover",
                "element.setAttribute.onmousedown",
                "element.setAttribute.onmouseup",
                "element.setAttribute.onkeydown",
                "element.setAttribute.onkeypress",
                "element.setAttribute.onkeyup",
                "createContextualFragment",
                "document.implementation.createHTMLDocument",
                "xhr.open",
                "xhr.send",
                "fetch",
                "fetch.body",
                "xhr.setRequestHeader.name",
                "xhr.setRequestHeader.value",
                "jQuery.attr.href",
                "jQuery.attr.src",
                "jQuery.attr.data",
                "jQuery.attr.action",
                "jQuery.attr.formaction",
                "jQuery.prop.href",
                "jQuery.prop.src",
                "jQuery.prop.data",
                "jQuery.prop.action",
                "jQuery.prop.formaction",
                "form.action",
                "input.formaction",
                "button.formaction",
                "button.value",
                "element.setAttribute.href",
                "element.setAttribute.src",
                "element.setAttribute.data",
                "element.setAttribute.action",
                "element.setAttribute.formaction",
                "webdatabase.executeSql",
                "document.domain",
                "history.pushState",
                "history.replaceState",
                "xhr.setRequestHeader",
                "websocket",
                "anchor.href",
                "anchor.target",
                "JSON.parse",
                "localStorage.setItem.name",
                "localStorage.setItem.value",
                "sessionStorage.setItem.name",
                "sessionStorage.setItem.value",
                "element.outerText",
                "element.innerText",
                "element.textContent",
                "element.style.cssText",
                "RegExp",
                "location.protocol",
                "location.host",
                "input.value",
                "input.type",
                "document.evaluate"
            ]
    escaped_sources_sinks = [re.escape(sns) for sns in sourcesSinks]
    sources_match = list(dict.fromkeys(re.findall("|".join(escaped_sources_sinks), str(soup))))

    if resp_obj.status_code in redirect_codes:
        if meta_tag_search and "http-equiv=\"refresh\"" in meta_tags:
            print(f"[+] Meta Tag Redirection")
            VULNERS["meta_tag"] = True
            return True
        elif 'Location' in resp_obj.headers:
            VULNERS["header_base_redirect"].append(final_url + " -> " + resp_obj.headers['Location'])
            print(f"[+] Header Based Redirection : {final_url} -> {resp_obj.headers['Location']}")

    elif resp_obj.status_code == 200:
        if google_search:
            print(f"[+] JavaScript Based Redirection")
            if sources_match:
                VULNERS["js_sources"].append(sources_match)
                print(f"[+] Potentially Vulnerable Source/Sink(s) Found: {' '.join(sources_match)}")
            return True

        if meta_tag_search and "http-equiv=\"refresh\"" in resp_obj.text:
            print(f"[+] Meta Tag Redirection")
            VULNERS["meta_tag"] = True
            return True
        elif "http-equiv=\"refresh\"" in resp_obj.text and not meta_tag_search:
            print(f"[-] The page is only getting refreshed")
            return True

    elif resp_obj.status_code in error_codes:
        print(f"[-] {final_url} [{resp_obj.status_code}]")
        
    return False

def return_openredirect(domain):
    open_redirect(f'{domain}')
    write_vuln_file(f'{domain}', VULNERS, 'Open Redirect')


# return_openredirect('yenbai.gov.vn')  