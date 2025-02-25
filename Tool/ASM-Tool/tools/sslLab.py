import subprocess
import json
import uuid
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from tools import get_config
# from __init__ import get_config

config = get_config()
GO_BIN = config.get('GO_PATH', 'GO_BINARIES')

def check_key_certificate(certificate_pem):
    """
    Return the certificate key
    Arg: 
        certificate_pem: str
    Return:
        public_key_length: int
    """
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
    public_key = certificate.public_key()
    public_key_length = public_key.key_size 
    return public_key_length


def key_exchange_rating(key_strength):
    """
    Calculate key exchange score based on key exchange method and strength.
    Args:
        key_strength: int
    Return:
        score: int
    """
    if key_strength < 512:
        return 20
    elif key_strength < 1024:
        return 40
    elif key_strength < 2048:
        return 80
    elif key_strength < 4096:
        return 90
    else:
        return 100


def check_protocol_support(domain):
    """
    Check the supported protocol of the domain by min-max version
    Args:
        domain: str
    Return:
        score: int
    """
    protocols = {'ssl30': 80, 'tls10': 85, 'tls11': 90, 'tls12': 95, 'tls13': 100}
    min_protocol = None
    max_protocol = None
    for protocol in list(protocols.keys()):
        result = subprocess.run(
            [f"{GO_BIN}tlsx", "-u", domain, "-silent", '-min-version', protocol],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"Error executing command for {protocol}: {result.stderr}")
            return None
        if result.stdout.strip():
            min_protocol = protocol
            break

    if min_protocol is None:
        print("No supported protocol found.")
        return None

    if min_protocol == 'tls13':
        max_protocol = min_protocol
    else:
        for protocol in list(protocols.keys())[list(protocols.keys()).index(min_protocol):]:
            result = subprocess.run(
                [f"{GO_BIN}tlsx", "-u", domain, "-silent", '-max-version', protocol],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                print(f"Error executing command for {protocol}: {result.stderr}")
                return None
            if result.stdout.strip(): 
                max_protocol = protocol

    min_score = protocols[min_protocol]
    max_score = protocols[max_protocol]
    return (min_score + max_score) // 2
       

def cipher_strength(cipher):
    """
    Check the cipher strength of the domain by calling API check of that cipher
    Args:
        cipher: str
    Return:
        score: int
    """
    response = requests.get(f'https://ciphersuite.info/api/cs/{cipher}') 
    data = response.json()
    trust = data[cipher].get("security")
    if trust == "insecure":
        return 20
    elif trust == "weak":
        return 50
    elif trust == "secure":
        return 80
    elif trust == "recommended":
        return 100
    else:
        return 0

    
def safe_get(value, default=""):
    """Returns the value if it's not None, otherwise returns the default."""
    return value if value is not None else default


def ssl_grading(domain, key_size, cipher):
    """
    Grading SSL certificate based on key exchange, cipher strength and protocol support
    Args:
        domain: str
        key_size: int
        cipher: str
    Return:
        grade: str
    """
    result = subprocess.run(
        [f"{GO_BIN}tlsx", "-u", domain, "-expired", "-silent", '-self-signed',"-mismatched", "-revoked", "-untrusted"],
        capture_output=True,
        text=True
    )   
    if result.returncode != 0:
        print(f"Error executing command: {result.stderr}")
        return None
    
    output = result.stdout
    if '[' in output:
        return 'F'

    key_score = key_exchange_rating(key_size)
    cipher_score = cipher_strength(cipher)
    protocol_score = check_protocol_support(domain)
    
    total = key_score * 0.3 + cipher_score * 0.4 + protocol_score * 0.3
    
    if total >= 80: 
        return 'A'
    elif total >= 65:
        return 'B'
    elif total >= 50:
        return 'C'
    elif total >= 35:
        return 'D'
    elif total >= 20:
        return 'E'
    else:
        return 'F'
    
    

def sslinfo(domain: str):
    """
    Get SSL certificate information of the domain
    Args:
        domain: str
    Return:
        detail: dict
    """
    print(f"[+] Checking ssl of {domain}")
    result = subprocess.run(
        [f"{GO_BIN}tlsx", "-u", domain, "-json", "-silent", '-cert'],
        capture_output=True,
        text=True
    )   
    if result.returncode != 0:
        print(f"Error executing command: {result.stderr}")
        return {}
    
    output = result.stdout
    if len(output) == 0:
        return {}
    cert = json.loads(output)
    
    command = f"openssl s_client -connect {domain}:443 -showcerts < /dev/null | openssl x509 -text -noout | grep \"Signature Algorithm\" | sed 's/.*: //'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode != 0:
        print(f"Error executing command: {result.stderr}")
        return {}
    if "failure" in result.stderr:
        print(f"Cannot determine ssl {result.stderr}")
        return {}
    try:
        sigAlg = result.stdout.splitlines()[0]
    except:
        sigAlg = None
    key_size = check_key_certificate(cert.get('certificate').strip())
    cipher = safe_get(cert.get('cipher'))
    grade = ssl_grading(domain, key_size,cipher)
    detail = {
            "host" : safe_get(cert.get('host')),
            "expiry_date": safe_get(cert.get('not_after')),
            "issue_date": safe_get(cert.get('not_before')),
            "id": safe_get(str(uuid.uuid1())),
            "cipher": safe_get(cert.get('cipher')),
            "grade": grade,
            "issuerSubject": safe_get(cert.get('subject_dn')),
            "subject_alt_names": safe_get(cert.get('subject_an', [])),
            "subject_cn": safe_get(cert.get('issuer_dn', [])),
            "serialNumber": safe_get(cert.get('serial')),
            "raw": safe_get(cert.get('certificate')),
            "sigAlg": safe_get(sigAlg),
            "subject": safe_get(cert.get('issuer_cn')),
            "validationType": safe_get(cert.get('validationType')),
            "version": safe_get(cert.get('tls_version'))
        }
    return detail

###################################################
# This is the test section for the above functions
# sslinfo('yenbai.gov.vn')
# print(sslinfo("congan.yenbai.gov.vn"))
