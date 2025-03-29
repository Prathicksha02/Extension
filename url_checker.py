import re
import requests
import urllib.parse
import tldextract
import socket
from urllib.parse import urlparse

# 🔑 Insert your  API Key 
API_KEY = "ac36ab87684121682e604436f67be021f9fa0c6d0290fcb2499e518be6bd8ec9"

def is_encoded_url(url):
    """Check if URL is encoded."""
    return urllib.parse.unquote(url) != url

def decode_url(url):
    """Decode URL if it's encoded."""
    return urllib.parse.unquote(url)

def is_ip_address(url):
    """Check if a URL contains an IP address instead of a domain."""
    try:
        parsed_url = urlparse(url)
        ip = parsed_url.netloc.split(':')[0]  # Remove port if present
        socket.inet_aton(ip)  # Validate IP
        return True
    except (socket.error, ValueError):
        return False

def check(url):
    """Check URL reputation using  API."""
    headers = {
        "x-apikey": API_KEY
    }
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

    if response.status_code != 200:
        print(f"⚠️  API Error: {response.status_code} - {response.text}")
        return {"known_malicious": True, "reputation_score": 30}  # Treat unknown as riskier

    response_data = response.json()
    analysis_id = response_data.get("data", {}).get("id")

    if not analysis_id:
        print(f"⚠️ API Error: No analysis ID found.")
        return {"known_malicious": True, "reputation_score": 30}

    # Get analysis results
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    analysis_response = requests.get(analysis_url, headers=headers)
    
    if analysis_response.status_code != 200:
        print(f"⚠️ API Error: Failed to retrieve analysis results.")
        return {"known_malicious": True, "reputation_score": 30}

    analysis_data = analysis_response.json()
    
    # Extract malicious detection count
    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
    malicious_count = stats.get("malicious", 0)

    return {
        "known_malicious": malicious_count > 0,
        "reputation_score": 100 - (malicious_count * 10)
    }

def analyze_url(url):
    """Analyze URL for phishing indicators."""
    result = {
        'is_malicious': False,
        'suspicious_elements': [],
        'safety_score': 100,
        'details': {
            'domain': None,
            'ip_address': False,
            'https': False,
            'redirects': 0,
            'suspicious_keywords': [],
            'blacklisted': False
        }
    }
    
    # Decode URL if necessary
    url = decode_url(url)
    
    # Check if URL uses HTTPS
    if url.startswith('https://'):
        result['details']['https'] = True
    else:
        result['suspicious_elements'].append('not_https')
        result['safety_score'] -= 15

    # Extract domain information
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    result['details']['domain'] = domain
    
    # Check for IP address usage
    if is_ip_address(url):
        result['details']['ip_address'] = True
        result['suspicious_elements'].append('ip_address')
        result['safety_score'] -= 25

    # Check for suspicious keywords in URL
    suspicious_keywords = ['login', 'signin', 'account', 'secure', 'banking', 'password', 'verify']
    found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
    
    if found_keywords:
        result['details']['suspicious_keywords'] = found_keywords
        result['suspicious_elements'].extend([f'keyword_{kw}' for kw in found_keywords])
        result['safety_score'] -= len(found_keywords) * 5

    # Check URL length (phishing URLs tend to be long)
    if len(url) > 100:
        result['suspicious_elements'].append('long_url')
        result['safety_score'] -= 10

    # Check for multiple subdomains
    subdomain_count = extracted.subdomain.count('.')
    if subdomain_count > 2:
        result['suspicious_elements'].append('multiple_subdomains')
        result['safety_score'] -= 15

    # Check for non-standard ports
    parsed_url = urlparse(url)
    if parsed_url.port and parsed_url.port not in [80, 443]:
        result['suspicious_elements'].append('non_standard_port')
        result['safety_score'] -= 15

    # Reputation Check
    vt_result = check(url)
    if vt_result["known_malicious"]:
        result['suspicious_elements'].append('virustotal_flagged')
        result['safety_score'] -= 100

    # Determine if malicious based on safety score
    result['is_malicious'] = result['safety_score'] < 70

    return result

# Test Example
if __name__ == "__main__":
    url = input("url check  ")
    analysis_result = analyze_url(url)

    # Display the results
    print("\n🔍 **Analysis Details:**")
    print(f"Malicious: {analysis_result['is_malicious']}")
    print(f"Suspicious Elements: {analysis_result['suspicious_elements']}")
    print(f"Safety Score: {analysis_result['safety_score']} / 100")

    # Final verdict
    if analysis_result['is_malicious']:
        print(f"\n🚨 WARNING: The URL '{url}' is MALICIOUS! 🚨")
    else:
        print(f"\n✅ SAFE: The URL '{url}' is SAFE to visit. ✅")
