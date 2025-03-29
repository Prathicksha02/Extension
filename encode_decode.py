import base64
import requests
import time

# API Key
API_KEY = "ac36ab87684121682e604436f67be021f9fa0c6d0290fcb2499e518be6bd8ec9"

# URL Scan API
SCAN_URL = "https://www.virustotal.com/api/v3/urls"

def decode_base64_url(encoded_url):
    try:
        decoded_bytes = base64.b64decode(encoded_url)
        decoded_url = decoded_bytes.decode("utf-8")
        return decoded_url
    except Exception as e:
        return None

def scan_url(url):
    headers = {"x-apikey": API_KEY}
    data = {"url": url}
    response = requests.post(SCAN_URL, headers=headers, data=data)

    if response.status_code == 200:
        result = response.json()
        analysis_id = result["data"]["id"]
        return get_scan_results(analysis_id)
    else:
        return "error"

def get_scan_results(analysis_id):
    headers = {"x-apikey": API_KEY}
    result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for _ in range(10):  # Retry for 10 seconds
        response = requests.get(result_url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            status = result["data"]["attributes"]["status"]

            if status == "completed":
                malicious_count = result["data"]["attributes"]["stats"]["malicious"]
                suspicious_count = result["data"]["attributes"]["stats"]["suspicious"]
                undetected_count = result["data"]["attributes"]["stats"]["undetected"]

                if malicious_count > 0 or suspicious_count > 0:
                    return "MALICIOUS"
                elif undetected_count > 0:
                    return "SAFE"
                else:
                    return "Malicious." 
        time.sleep(1)  

    return "Malicious."


# User Input
encoded_url = input("Enter a Base64-encoded URL: ")
decoded_url = decode_base64_url(encoded_url)

if decoded_url:
    print(f"Decoded URL: {decoded_url}")
    result = scan_url(decoded_url)
    
    # Final Verdict
    if result == "SAFE":
        print(f"✅ SAFE: The URL '{decoded_url}' is safe.")
    elif result == "MALICIOUS":
        print(f"🚨 MALICIOUS: The URL '{decoded_url}' is dangerous! DO NOT VISIT.")
    
else:
    print("❌ Malicious.")
