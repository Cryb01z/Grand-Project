import bs4
import requests
import re
import json
import random
from collections import defaultdict
from Wappalyzer import Wappalyzer, WebPage
# from __init__ import get_config
from tools import get_config

config = get_config()

USERAGENT = config.get('USERAGENT', 'USERAGENTS').split(',')
USERAGENTS = []

for agent in USERAGENT:
    agent = agent.strip()[1:-1]
    USERAGENTS.append(agent)
    

def web_technology_wapplyzer(domain):
    """
    Detect web technology of a domain using Wappalyzer library
    Args:
        domain (str): Domain name
    Returns:
        str: JSON string of technology
    """
    wappalyzer = Wappalyzer.latest()

    def get_response(url):
        try:
            response = requests.get(url, verify=False, timeout=10)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            print(f"Timeout occurred while trying to reach {url}")
        except requests.exceptions.ConnectionError:
            print(f"Connection error while trying to reach {url}")
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as err:
            print(f"An error occurred: {err}")
        return None

    response = get_response(f"https://{domain}")
    if response is None:
        response = get_response(f"http://{domain}")

    if response is None:
        return json.dumps({})

    webpage = WebPage.new_from_response(response)
    analysis = wappalyzer.analyze_with_versions_and_categories(webpage)
    if analysis is None:
        return json.dumps({})
    
    return json.dumps(analysis, indent=4)

def parsing_technology(domain):
    """
    Parsing technology from wappalyzer library
    Args:
        domain (str): Domain name
    Returns:
        list: List of technology
    """
    data = json.loads(web_technology_wapplyzer(domain))
    if data == {}:
        return None
    category_group = defaultdict(list)    
    category_map = {
        "CMS": "Content Management System",
        "Web frameworks": "Server-side Programming Languages",
        "UI frameworks": "CSS Framework",
        "JavaScript libraries": "JavaScript Libraries",
        "Operating systems": "Operating System",
        "Web servers": "Web Servers",
    }

    for technology, details in data.items():
        categories = details.get("categories", [])
        versions = details.get("versions", [])
        version = versions[0] if versions else None
        
        for category in categories:
            category = category_map.get(category, category)
            category_group[category].append({
                "technology": technology,
                "version": version,
                "description": "null"
            })
    
    merged_technologies = [
        {
            "categories": category,
            "subtech": subtechs
        } 
        for category, subtechs in category_group.items()
    ]
    return merged_technologies      


def get_web_technology(domain):
    """
    Return web technology of a domain, subdomain. If subdomain is return to domain result 
    use Wapplyzer first to get the technology, and then compare with result from w3techs
    
    Args:
        main_domain (str): Main domain
        domain (str): Subdomain
    Returns:
        list: List of technology 
    """
    print(f"[+] Getting technology of {domain}")
    si_tech_data = []
    url = f"https://w3techs.com/sites/info/{domain}"
    response = requests.get(url, headers={"User-Agent": random.choice(USERAGENTS)}, verify=False)
    if("Do you want us to crawl it now?" in response.text):
        data = {
            'add_site': 'Crawl now!'
        }
        response = requests.post(f"https://w3techs.com/sites/info/{domain}", headers={"User-Agent":  random.choice(USERAGENTS)}, data=data)
        if response.url != url:
            subdomain_json = parsing_technology(domain)
            return subdomain_json

    html_data = bs4.BeautifulSoup(response.text, "lxml")
    ###################TEST###########################
    # with open("sample/web.txt", "r") as f:
    #     response = f.read()    
    # html_data = bs4.BeautifulSoup(response, "lxml")
    ##################################################
        
    divs = html_data.find_all("div", class_="si_h")
    
    for i in range(0, len(divs)):
        current_div = divs[i]
        technology = {
            "categories": current_div.text,
            "subtech": []
        }
        if i + 1 < len(divs):
            next_div = divs[i+1] 
        else: 
            break 
        
        current_tag = current_div.find_next_sibling()
        info = {}
        while current_tag and current_tag != next_div:
            if current_tag.name == "div" and "si_tech" in current_tag.get("class", []) and "si_tech_np" in current_tag.get("class", []):
                description = current_tag.text.strip()
                
            elif current_tag.name == "p" and "si_tech" in current_tag.get("class", []):
                tech_name = current_tag.find('a').get_text()
                if tech_name == "Windows":
                    tech_name = "Windows Server"
                if tech_name == "Microsoft-IIS":
                    tech_name = "IIS"
                version_match = re.search(r'(\d+(\.\d+){0,2})', current_tag.get_text())
                
                info = {
                    "technology": tech_name,
                    "version": version_match.group(0) if version_match else None,
                    "description": description
                }                
                technology["subtech"].append(info)
            
            current_tag = current_tag.find_next_sibling() 
            
        si_tech_data.append(technology)
    
    return si_tech_data


def compare_technology(main_json, subdomain_json):
    """
    Compare technology between main domain and subdomain.
    If the subdomain has null values in technology details, 
    fill them with values from the main domain.
    
    Args:
        main_json (list): List of technology of main domain.
        subdomain_json (list): List of technology of subdomain.
    
    Returns:
        list: Updated subdomain JSON with filled values from main domain.
    """
    
    main_tech_lookup = {
        (category["categories"], subtech["technology"]): subtech
        for category in main_json
        for subtech in category["subtech"]
    }
    
    for subdomain_category in subdomain_json:
        for subdomain_subtech in subdomain_category["subtech"]:
            key = (subdomain_category["categories"], subdomain_subtech["technology"].replace("Microsoft ", ""))  # Normalize name
            
            if key in main_tech_lookup:
                main_subtech = main_tech_lookup[key]
                
                if subdomain_subtech.get("description") == "null" or not subdomain_subtech["description"]:
                    subdomain_subtech["description"] = main_subtech["description"]
                
                if subdomain_subtech.get("version") == "null" or not subdomain_subtech["version"]:
                    subdomain_subtech["version"] = main_subtech["version"]
    
    return subdomain_json
 
############################################################################
# def main():
#     subdomain_json= parsing_technology("lienhieptchn.yenbai.gov.vn")
#     main_json = get_web_technology("yenbai.gov.vn")
#     subdomain_json = compare_technology(main_json, subdomain_json)
#     print(json.dumps(subdomain_json, indent=4))

# if __name__ == "__main__":
#     main()
#############################################################################