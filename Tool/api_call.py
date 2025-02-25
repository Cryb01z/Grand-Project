from fastapi import FastAPI, HTTPException,BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

from tools.sslLab import *
from tools.technology import *
from tools.subdomains import *
from tools.nmap import *
from tools.vuln import *
    
from vuln import *

from osint.github import *
# from osint.twitter import *

import os
import datetime
import logging
import json
import shutil
import asyncio


from fastapi.responses import StreamingResponse
from concurrent.futures import ThreadPoolExecutor, as_completed
from json_repair import repair_json
from threading import Lock
from typing import Optional

progress_lock = Lock()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UNCOMMON_PORTS_WEB = {
    "81", "300", "591", "593", "832", "981", "1010", "1311", "1099", "2082", "2095", "2096", 
    "2480", "3000", "3001", "3002", "3003", "3128", "3333", "4243", "4567", "4711", "4712", 
    "4993", "5000", "5104", "5108", "5280", "5281", "5601", "5800", "6543", "7000", "7001", 
    "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8060", "8069", "8080", "8081", 
    "8083", "8088", "8090", "8091", "8095", "8118", "8123", "8172", "8181", "8222", "8243", 
    "8280", "8281", "8333", "8337", "8443", "8500", "8834", "8880", "8888", "8983", "9000", 
    "9001", "9043", "9060", "9080", "9090", "9091", "9092", "9200", "9443", "9502", "9800", 
    "9981", "10000", "10250", "11371", "12443", "15672", "16080", "17778", "18091", "18092", 
    "20720", "32000", "55440", "55672"
}

progress_lock = Lock()
scan_status = {}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_url_scheme(domain):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            response = requests.head(url, timeout=5)
            if response.status_code < 400:
                return url
        except requests.RequestException:
            continue
    return None


def scan_individual_url(url, scan_time):
    try:
        url = get_url_scheme(url)
        if url is not None:
            create_scan(url, "Deep Scan", time_limit=scan_time)
    except Exception as e:
        logging.error(f"Error in scanning {url}: {e}")


def deep_vuln_scan(domain):
    """
    Perform a deep vulnerability scan for a given domain by processing related files.

    Args:
        domain (str): The domain to scan.
    """
    # Gather URLs to process by checking the 'vulners' directory
    urls = []
    for filename in os.listdir('vulners'):
        output_file = f'vulns/vuln_{filename.replace(".xml", "")}.json'
        
        if not os.path.exists(output_file) and domain in filename:
            urls.append(filename.replace('.xml', ''))
    
    if not urls:
        logging.info("No new URLs to scan.")
        return
    
    scan_time = calculate_average_scan_time(len(urls))
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_individual_url, url, scan_time) for url in urls]
        
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error processing URL: {e}")


def get_json_files():
    try:
        if not os.path.exists('record'):
            os.makedirs('record', exist_ok=True)
        domain_files = os.listdir('record')
        with open('result/all_domain.txt', 'w') as f:
            for file in domain_files:
                if file.endswith('.json'):
                    with open(f'record/{file}', 'r') as f:
                        data = json.load(f)
                    if data.get('is_online'):
                        ports = [service["port"] for service in data.get("services", [])]
                        for port in ports:
                            if port in UNCOMMON_PORTS_WEB:
                                f.write(f"{data.get('domain')}:{port}\n")
    except Exception as e:
        print(f"Error processing JSON files: {e}")


def vuln_scan():
    get_json_files()
    try:
        initial_scan()
    except Exception as e:
        logging.error(f"Error at vuln_scan: {e}")


def perform_scan(domain: str):
    try:
        with progress_lock:
            scan_status[domain] = {"status": "in progress", "completed": 0, "total": 0}
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = domain.replace("http://", "").replace("https://", "")
        if f'{domain}.json' in os.listdir('result/subdomain'):
            with open(f'result/subdomain/{domain}.json', 'r') as f:
                subdomain_info = json.load(f)
        else:
            subdomain_info = finding_subdomain_information(domain)
            with open(f'result/subdomain/{domain}.json', 'w') as f:
                json.dump(subdomain_info, f, indent=4)
        if subdomain_info == {}:
            with progress_lock:
                scan_status[domain] = {"status": "error: wrong domain", "completed": 0, "total": 0}
            return

        main_json = get_web_technology(domain)
        total_subdomains = len(subdomain_info)

        with progress_lock:
            scan_status[domain]["total"] = total_subdomains

        def scan_subdomain(key, value):
            try:
                if not key or not value:
                    logging.error(f"Invalid key or value: key={key}, value={value}")
                    return

                json_data = json.loads(repair_json(str(value).replace('\'', '\"')))
                asn = json_data.pop('asn', None)
                asn = check_asn(f'{key}')

                subdomain_json = parsing_technology(key)
                if subdomain_json is None:
                    final_data = {
                        "domain": key,
                        "is_online": False,
                        "discovery_reason": "FA24 Internal Attack Surface",
                        "discovery_on": datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                        "ip": json_data.get('a'),
                        "services": None,
                        "ssl": None,
                        "technology": None,
                        "autonomous_system": None,
                        "operating_system": {
                            "vendor": None,
                            "cpe": None,
                            "port": None,
                        },
                        "dns": json_data
                    }
                else:
                    tech = compare_technology(main_json, subdomain_json)
                    ssl = sslinfo(key)
                    operating_system, info_port, port = merge_scan(f'{key}')

                    if info_port is None and port is None:
                        info_port, port, services = "", "", ""
                        operating_system = {"name": "", "cpes": "", "port": ""}
                    else:
                        services = nmap_scan(f'{key}', str(port).replace(', ', ','), info_port)
                        shutil.rmtree(key, ignore_errors=True)

                    final_data = {
                        "domain": key,
                        "discovery_reason": "FA24 Internal Attack Surface",
                        "is_online": True,
                        "discovery_on": datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                        "ip": json_data.get('a'),
                        "services": services,
                        "ssl": ssl,
                        "technology": tech,
                        "autonomous_system": asn,
                        "operating_system": {
                            "vendor": operating_system['name'],
                            "cpe": operating_system['cpes'],
                            "port": operating_system['port'],
                        },
                        "dns": json_data
                    }
                if key.startswith("www."):
                    key = key.replace("www.", "")
                with open(f'record/{key}.json', 'w') as f:
                    json.dump(final_data, f, indent=4)

                with open(f'log/process.log', 'a') as f_log:
                    f_log.write(f"{key} - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

                print(f"Scanned {key}")
            except Exception as e:
                logging.error(f"Error scanning {key}: {e}", exc_info=True)
            finally:
                with progress_lock:
                    scan_status[domain]["completed"] += 1

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_subdomain, key, value) for key, value in subdomain_info.items()]
            for future in futures:
                future.result()
        
        with progress_lock:
            scan_status[domain]["status"] = "finished"

        with open('log/process.log', 'w') as f_log:
            pass
        
        deep_vuln_scan(domain)
    except Exception as e:
        with progress_lock:
            scan_status[domain] = {"status": f"error: {str(e)}", "completed": 0, "total": 0}
        logging.error(f"Error scanning domain {domain}: {e}")


@app.get("/vulnerability/detail", tags=["Vulnerability Information"])
async def get_vulnerability_detail(url: str):
    """
    Retrieve vulnerability details for a given URL.
    Arguments:
    - **url**: The URL of the target to retrieve vulnerability details for.
    Returns:
    - A JSON object with the vulnerability details.
    """
    if url.startswith("http://") or url.startswith("https://"):
        url = url.replace("http://", "").replace("https://", "")

    try:
        with open(f"vulns/vuln_{url}.json") as f:
            data_input = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

    return data_input


@app.get("/vulnerability", tags=["Vulnerability Information"])
async def get_vulnerability(url: str, vuln_id: str = None):
    """
    Retrive details information of a vulnerability.
    Arguments:
    - **url**: The URL of the target to retrieve vulnerability information.
    - **vuln_id**: The ID of the vulnerability to retrieve information for.
    Returns:
    - A JSON object with the vulnerability details.
    """
    if url.startswith("http://") or url.startswith("https://"):
        url = url.replace("http://", "").replace("https://", "")

    try:
        with open(f"vulns/vuln_{url}.json") as f:
            data_input = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

    MyScanID = data_input.get("scan_id")
    MyScanResultID = data_input.get("result_id")
    
    vulnerabilities = data_input.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        if vuln_id and vuln.get("vuln_id") != vuln_id:
            continue

        response = requests.get(
            f"{MyAXURL}/scans/{MyScanID}/results/{MyScanResultID}/vulnerabilities/{vuln_id}",
            headers=MyRequestHeaders,
            json={},
            verify=False
        )

        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to retrieve vulnerability details")
    raise HTTPException(status_code=404, detail="Vulnerability not found")


@app.delete("/vulnerability", tags=["Vulnerability Information"])
async def remove_vulnerability(url: str, vuln_id: str):
    """
    Remove a vulnerability from the list of vulnerabilities.
    Arguments:
    - **url**: The URL of the target to remove the vulnerability from.
    - **vuln_id**: The ID of the vulnerability to remove.
    Returns:
    - A JSON object with the status of the operation.
    """
    if url.startswith("http://") or url.startswith("https://"):
        url = url.replace("http://", "").replace("https://", "")
    
    file_path = f"vulns/vuln_{url}.json"
    updated_file_path = f"vulns/vuln_{url}.json"
    
    try:
        with open(file_path, 'r') as f:
            data_input = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

    vulnerabilities = data_input.get("vulnerabilities", [])
    updated_vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get("vuln_id") != vuln_id]
    
    if len(vulnerabilities) == len(updated_vulnerabilities):
        raise HTTPException(status_code=404, detail=f"Vulnerability with id {vuln_id} not found")

    data_input["vulnerabilities"] = updated_vulnerabilities
    
    os.makedirs(os.path.dirname(updated_file_path), exist_ok=True)
    
    with open(updated_file_path, 'w') as f:
        json.dump(data_input, f, indent=4)
    
    return {"status": "success", "message": f"Vulnerability with id {vuln_id} removed successfully"}


@app.get("/scan/{domain}", tags=["Domain Information"])
async def scan_domain(domain: str, background_tasks: BackgroundTasks):
    with progress_lock:
        if domain in scan_status and scan_status[domain]["status"] == "in progress":
            raise HTTPException(status_code=400, detail="Scan already in progress for this domain.")
        scan_status[domain] = {"status": "started", "completed": 0, "total": 0}

    background_tasks.add_task(perform_scan, domain)
    return {"status": "scan initiated", "domain": domain}


@app.get("/scan/{domain}/status/stream", tags=["Process Scan Status"])
async def stream_scan_status(domain: str):
    async def event_generator():
        while True:
            with progress_lock:
                domain_status = scan_status.get(domain, {"status": "not started", "completed": 0, "total": 0})
            
            status = domain_status["status"]        
            completed = domain_status["completed"]
            total = domain_status["total"]
            
            if status == "in progress" and total > 0:
                percent = (completed / total) * 100
                yield f"data: {{\"status\": \"{percent:.2f}%\", \"completed\": {completed}, \"total\": {total}}}\n\n"
            elif status == "completed":
                yield f"data: {{\"status\": \"completed\", \"completed\": {completed}, \"total\": {total}}}\n\n"
                break
            else:
                yield f"data: {{\"status\": \"{status}\", \"completed\": 0, \"total\": 0}}\n\n"

            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/check/{domain}/all", tags=["Domain Information"])
async def filescan(domain: str):
    try:
        logging.debug("Checking if 'record/' directory exists...")
        if not os.path.exists('record/'):
            logging.error("Directory not found: 'record/'")
            return {"status": "failed", "results": "Directory not found"}

        filenames = os.listdir(f'record/')
        logging.info(f"Files found in 'record/': {filenames}")
        filenamesWithoutJson = []
        
        if not filenames:
            logging.warning("No files found in directory")
            return {"status": "failed", "results": "No files found in directory"}
        for filename in filenames:
            if filename.endswith(".json") and domain in filename:
                filenamesWithoutJson.append(filename.replace(".json", ""))
        return {"status": "success", "results": filenamesWithoutJson}

    except Exception as e:
        logging.error(f"Error at {e}")
        raise HTTPException(status_code=500, detail=f"Error processing: {str(e)}")


@app.get("/info/{domain}",  tags=["Domain Information"])
async def scan_domain(domain: str):
    try:
        file_path = f'record/{domain}.json'
        if not os.path.exists(file_path):
            return {"status": "failed", "results": "File not found"}

        with open(file_path, 'r') as f:
            data = json.load(f)

        return {"status": "success", "results": data}

    except Exception as e:
        logging.error(f"Error at {e}")
        raise HTTPException(status_code=500, detail=f"Error processing {domain}: {str(e)}")



@app.get("/dorking/github/{thing_to_search}", tags=["Dorking"])
async def github_dorking(thing_to_search: str):
    """
    Perform a GitHub dorking search for the specified query.

    Parameters:
    - **thing_to_search**: The query to search for in GitHub's code.

    Returns:
    - A JSON object with search results containing potentially exposed information.
    """
    github_results = await perform_github_dorking(thing_to_search)
    if github_results:
        return {"status": "success", "results": github_results}
    else:
        return {"status": "failed", "results": "No results found"}


@app.get("/ransomware/groups", tags=["Ransomware"])
async def ransomware_groups():
    """
    Retrieve a list of ransomware groups.

    Returns:
    - A JSON object with a list of ransomware groups.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get('https://www.ransomlook.io/api/groups')
    return {"status": "success", "results": response.text}


@app.get("/ransomware/groups/{name}", tags=["Ransomware"])
async def ransomware_group(name: str):
    """
    Retrieve information about a specific ransomware group.
    
    Arguments:
    - **name**: The name of the ransomware group to retrieve information for.
    
    Returns:
    - A JSON object with information about the specified ransomware group.
    """
    url = f'https://www.ransomlook.io/api/group/{name}'
    async with httpx.AsyncClient() as client:
        response = await client.get(url)       
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to retrieve group data")

    return {"status": "success", "results": response.text}

@app.get('/result/domain/all', tags=['Domain Information'])
async def get_all_file_scan_result(domain: str):
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.replace("http://", "").replace("https://", "")
    file = os.listdir('record')
    array = []  # Move array declaration outside of the loop
    for filename in file:
        if filename.endswith('.json') and domain in filename:
            with open(f'record/{filename}', 'r') as f:
                array.append(json.load(f))
    return {"status": "success", "results": array}



@app.get('/result/domain/vuln/all', tags=['Vulnerability Information'])
async def get_all_vuln_scan_result(domain: str):
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.replace("http://", "").replace("https://", "")
    file = os.listdir('vulns')
    array = []
    for filename in file:
        if filename.endswith('.json') and domain in filename:
            with open(f'vulns/{filename}', 'r') as f:
                array.append(json.load(f))
    return {"status": "success", "results": array}


# @app.get("/twitter/search/{query}")
# async def twitter_search(query: str, count: Optional[int] = 10):
#     """
#     Search for tweets based on a query and return tweet details.  

#     Parameters:
#     - **query**: The search term to query on Twitter.
#     - **count**: The number of tweets to return (default is 10).

#     Returns:
#     - A JSON list of tweets containing user name, profile image URL, and tweet text.
#     """
#     tweet_results = await get_tweet(query, count)
#     return {"status": "success", "results": tweet_results}
    
    
    
    
#uvicorn test:app --host 0.0.0.0 --port 8000 --workers 4
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_call:app", host="0.0.0.0", port=65534, workers=4)
