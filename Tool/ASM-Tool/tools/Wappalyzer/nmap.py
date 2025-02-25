import subprocess
import xml.etree.ElementTree as ET

def nmap_command(command: list):
    full_command = ['nmap'] + command
    try:
        result = subprocess.run(full_command, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"Error: {result.stderr}")
            return None
    except Exception as e:
        print("Exception in nmap_command:", e)
        return None


def nmap_scan_os(ip: str):
    """
    Scan the OS of the target IP using Nmap and capture the output.
    Args:
        ip (str): The IP address to scan.
        is_window (bool): True if the OS is Windows, False otherwise.
    Returns:
        str: The XML output from the Nmap scan.
    """
    command = f"-O {ip} -oX -"
    command = command.split(' ')
    return nmap_command(command)


def extract_os_field(xml_output: str):
    """
    Extract the OS information from the XML output.
    Args:
        xml_output (str): The XML output from the Nmap scan.
    Returns:
        None
    """
    root = ET.fromstring(xml_output)

    os_info = root.find('.//os')
    if os_info is not None:
        osmatch = os_info.findall('osmatch')[0]
        name = osmatch.get('name')        
        osclass = osmatch.findall('osclass')[0]
        osfamily = osclass.get('osfamily')
        cpe = osclass.findall('cpe')[0]
        result = {
            f"{osfamily}": {
                "versions": name,
                "categories": [
                    "Operating systems"
                ],
                "cpe": [cpe.text] 
            }
        }
        return result
    else:
        print("No OS information available in the scan results.")
        return {}



def main():    
    xml_output = nmap_scan_os('96.30.193.123')
    # xml_output = nmap_scan_os('192.168.195.128', is_window=True)
    # xml_output = nmap_scan_os('14.231.204.171', is_window=True)
    if xml_output:
        print(extract_os_field(xml_output))
    else:
        print("Failed to retrieve Nmap scan results.")


if __name__ == "__main__":
    main()