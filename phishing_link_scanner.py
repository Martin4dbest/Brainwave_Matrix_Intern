import requests
from urllib.parse import urlparse
import re
import socket

# VirusTotal API settings (replace with your actual API key)
API_KEY = "ba10bc5bc3751d63bb88c59a4da6ebe1965c2488f6a72cb0403c47cb88369c77"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# Common phishing keywords to check for in URLs
PHISHING_KEYWORDS = ['login', 'secure', 'bank', 'update', 'account', 'verify', 'confirm', 'signin', 'free', 'gift', 'money', 'win']

# Function to check for typosquatting (common domain impersonation techniques)
def is_typosquatting(domain):
    # Example of checking for common phishing domains (can expand this with more checks)
    common_domains = ["google.com", "paypal.com", "facebook.com", "apple.com"]
    
    for legitimate_domain in common_domains:
        if re.sub(r'[0o]', '0', domain) == legitimate_domain:
            return True, "Possible typosquatting on a well-known domain"
    
    return False, "No typosquatting detected"

# Function to check for suspicious keywords in the URL
def has_suspicious_keywords(url):
    for keyword in PHISHING_KEYWORDS:
        if keyword in url.lower():
            return True, f"Suspicious keyword detected: '{keyword}'"
    return False, "No suspicious keywords found"

# Function to check if an IP address is used in the URL instead of a domain
def has_ip_in_url(url):
    try:
        hostname = urlparse(url).hostname
        if hostname:
            # Try to resolve the hostname to an IP address
            ip = socket.gethostbyname(hostname)
            # If IP is resolved, it means it's a domain, not an IP in the URL
            return False, "URL does not contain an IP address"
    except socket.error:
        # If there's an error, it means the hostname couldn't be resolved
        return False, "Hostname could not be resolved to an IP address"
    
    return False, "No IP address detected in URL"

# Function to query VirusTotal for URL reputation
def check_virustotal(url):
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get(VIRUSTOTAL_URL, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result.get("positives", 0) > 0:
            return True, "URL flagged by VirusTotal"
    
    return False, "URL not flagged by VirusTotal"

# Function to check URL structure and domain for phishing signs
def is_suspicious(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check for long URLs
    if len(url) > 100:
        return True, "URL length is suspicious"
    
    # Check for multiple subdomains
    domain_parts = domain.split('.')
    if len(domain_parts) > 3:
        return True, "Suspicious subdomains"
    
    # Check for HTTP instead of HTTPS
    if parsed_url.scheme != "https":
        return True, "Non-HTTPS URL"
    
    # Check for typosquatting
    typosquatting, reason = is_typosquatting(domain)
    if typosquatting:
        return True, reason
    
    # Check for phishing keywords
    keyword_flagged, reason = has_suspicious_keywords(url)
    if keyword_flagged:
        return True, reason
    
    # Check if the URL contains an IP address
    ip_flagged, reason = has_ip_in_url(url)
    if ip_flagged:
        return True, reason
    
    return False, "URL seems safe"

# Main function to run the phishing link scanner
def phishing_link_scanner(url):
    suspicious, reason = is_suspicious(url)
    if suspicious:
        return f"Phishing suspected due to: {reason}"
    
    # Check against VirusTotal database
    vt_flagged, vt_reason = check_virustotal(url)
    if vt_flagged:
        return f"Phishing detected! Reason: {vt_reason}"
    
    return "URL is safe."

# Sample usage
if __name__ == "__main__":
    test_url = input("Enter a URL to check: ")
    result = phishing_link_scanner(test_url)
    print(result)
