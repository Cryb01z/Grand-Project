import json
import requests
import ssl
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MyAXURL = "https://192.168.100.224:3443/api/v1"
MyAPIKEY = "1986ad8c0a5b3df4d7028d5f3c06e936cdc53fd70c5f94975a66946bf2c3dee73"
MyTargetURL = "http://testhtml5.vulnweb.com/"
MyTargetDESC = "Testing for aborting scan"
FullScanProfileID = "11111111-1111-1111-1111-111111111111"
MyRequestHeaders = {'X-Auth': MyAPIKEY, 'Content-Type': 'application/json'}

def calculate_average_scan_time(total_domains, total_minutes=20, num_threads=5):
    total_seconds = total_minutes * 60
    
    if total_domains == num_threads:
        return total_seconds
    
    elif total_domains % num_threads == 0:
        return total_seconds / (total_domains // num_threads)
    
    else:
        return int(total_seconds / (total_domains // num_threads + 1)/30)


def create_scan(target, description,time_limit, disable_schedule=True, start_date = "", time_sensitive=""):
    MyRequestBody = {
        "address": target,
        "description": description,
        "type": "default",
        "criticality": 10
    }
    MyTargetIDResponse = requests.post(MyAXURL + '/targets', json=MyRequestBody, headers=MyRequestHeaders, verify=False)
    MyTargetIDjson = json.loads(MyTargetIDResponse.content)
    MyTargetID = MyTargetIDjson["target_id"]
    MyRequestBody = {
        "profile_id": "11111111-1111-1111-1111-111111111111",
        "incremental": False,
        "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        "user_authorized_to_scan": "yes",
        "target_id": MyTargetID
    }
    MyScanIDResponse = requests.post(MyAXURL + '/scans', json=MyRequestBody, headers=MyRequestHeaders, verify=False)
    MyScanID = MyScanIDResponse.headers["Location"].replace("/api/v1/scans/", "")
    
    def cleanup():
        requests.delete(MyAXURL + '/scans/' + MyScanID, headers=MyRequestHeaders, verify=False)
        requests.delete(MyAXURL + '/targets/' + MyTargetID, headers=MyRequestHeaders, verify=False)
    count = 0
    LoopCondition = True
    while LoopCondition:
        MyScanStatusResponse = requests.get(MyAXURL + '/scans/' + MyScanID, headers=MyRequestHeaders, verify=False)
        MyScanStatusjson = json.loads(MyScanStatusResponse.content)
        MyScanStatus = MyScanStatusjson["current_session"]["status"]
        if count <= time_limit:
            if MyScanStatus == "processing":
                print(f"Scan Status: Processing {target} - waiting 30 seconds...")
                count += 1
            elif MyScanStatus == "scheduled":
                print(f"Scan Status: Scheduled {target} - waiting 30 seconds...")
                count +=1
            elif MyScanStatus == "completed":
                LoopCondition = False
            else:
                print("Invalid Scan Status: Aborting")
                cleanup()
                exit()
        else:
            MyScanStatusResponse = requests.post(MyAXURL + '/scans/' + MyScanID + "/abort", headers=MyRequestHeaders, verify=False) 
            LoopCondition = False     
            break
            
        MyScanStatus = ""
        time.sleep(30)
    MyScanSessionResponse = requests.get(MyAXURL + '/scans/' + MyScanID, headers=MyRequestHeaders, verify=False)
    MyScanSessionjson = json.loads(MyScanSessionResponse.content)
    MyScanSessionID = MyScanSessionjson["current_session"]["scan_session_id"]

    MyScanResultResponse = requests.get(MyAXURL + '/scans/' + MyScanID + "/results", headers=MyRequestHeaders, verify=False)
    MyScanResultjson = json.loads(MyScanResultResponse.content)
    MyScanResultID = MyScanResultjson["results"][0]["result_id"]

    MyScanVulnerabilitiesResponse = requests.get(
        MyAXURL + '/scans/' + MyScanID + '/results/' + MyScanResultID + '/vulnerabilities',
        headers=MyRequestHeaders,
        verify=False
    )
    data = json.loads(MyScanVulnerabilitiesResponse.content)
    data['scan_id'] = MyScanID
    data['result_id'] = MyScanResultID
    
    with open(f'vulns/vuln_{str(target).replace("http://", "").replace("https://", "").replace("/", "")}.json', 'w') as f:
        json.dump(data, f, indent=4)
   

# create_scan(MyTargetURL, MyTargetDESC) #done
def get_vuln(url: str, vuln_id=None):
    if url.startswith("http://") or url.startswith("https://"):
        url = url.replace("http://", "").replace("https://", "")
    try:
        with open(f"vuln_{url}.json") as f:
            data_input = json.load(f)
    except FileNotFoundError:
        print("File not found")   
        
    MyScanID = data_input.get("scan_id")
    MyScanResultID = data_input.get("result_id")
    
    vulnerabilities = data_input.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        if vuln_id and vuln.get("vuln_id") != vuln_id:
            continue
        MyScanVulnerabilitiesResponse = requests.get(
            MyAXURL + '/scans/' + f'{MyScanID}' + '/results/' + f'{MyScanResultID}' + f'/vulnerabilities/{vuln_id}',
            headers=MyRequestHeaders,
            json= {},
            verify=False
        )
        print(MyScanVulnerabilitiesResponse.content.decode('utf-8'))
        break


def remove_vuln(url: str, vuln_id=None):    
    if url.startswith("http://") or url.startswith("https://"):
        url = url.replace("http://", "").replace("https://", "")
    try:
        with open(f"vuln_{url}.json", 'r') as f:
            data_input = json.load(f)
    except FileNotFoundError:
        print("File not found")
        return

    vulnerabilities = data_input.get("vulnerabilities", [])
    updated_vulnerabilities = [vuln for vuln in vulnerabilities if vuln.get("vuln_id") != vuln_id]
    data_input["vulnerabilities"] = updated_vulnerabilities
    with open(f"vulns/vuln_{url}.json", 'w') as f:
        json.dump(data_input, f, indent=4)


create_scan('http://bank.fa24asm.tech',"Deep Scan",time_limit=1200)

# get_vuln('testhtml5.vulnweb.com','3499089189473879452')




    
    












# MyScanVulnerabilitiesResponse = requests.get(
#     MyAXURL + '/targets/' + 'be0b60ca-5516-47af-93b3-8c90f0af6609',
#     headers=MyRequestHeaders,
#     verify=False
# )
# print(MyScanVulnerabilitiesResponse.content.decode('utf-8'))





    
# MyScanID = MyScanVulnerabilitiesResponse.headers["Location"].replace("/api/v1/scans/", "")

# print('Scan ID:', MyScanID)
# print(MyScanVulnerabilitiesResponse.content.decode('utf-8'))


# MyScanResultResponse = requests.get(MyAXURL + '/scans/' + "78a9d8dc-323b-41f3-b6dc-d583e8f44475" + "/results", headers=MyRequestHeaders, verify=False)
# MyScanResultjson = json.loads(MyScanResultResponse.content)
# MyScanResultID = MyScanResultjson["results"][0]["result_id"]

# MyScanVulnerabilitiesResponse = requests.get(
#     MyAXURL + '/scans/' + '2a2b13bf-b8c5-4a59-8550-067acaa9420f' + '/results/' + f'{MyScanResultID}' + '/vulnerabilities/3494506960160556668',
#     headers=MyRequestHeaders,
#     verify=False
# )

# print(MyScanVulnerabilitiesResponse.content.decode('utf-8'))

#show vuln
# MyScanVulnerabilitiesResponse = requests.get(
#     MyAXURL + '/scans/' + '4cf421f7-8c8c-4851-8595-2271172d60b0' + '/results/' + f'{MyScanResultID}' + '/vulnerabilities',
#     headers=MyRequestHeaders,
#     verify=False
# )
# print(MyScanVulnerabilitiesResponse.content.decode('utf-8'))
