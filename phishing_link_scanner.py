import requests
from urllib.parse import urlparse
import re
import socket
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

# VirusTotal API settings (replace with your actual API key)
API_KEY = "ba10bc5bc3751d63bb88c59a4da6ebe1965c2488f6a72cb0403c47cb88369c77"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# Common phishing keywords to check for in URLs
PHISHING_KEYWORDS = ['login', 'secure', 'bank', 'update', 'account', 'verify', 'confirm', 'signin', 'free', 'gift', 'money', 'win']

# Function to check for typosquatting (common domain impersonation techniques)
def is_typosquatting(domain):
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
            ip = socket.gethostbyname(hostname)
            return False, "URL does not contain an IP address"
    except socket.error:
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
    if len(url) > 100:
        return True, "URL length is suspicious"
    domain_parts = domain.split('.')
    if len(domain_parts) > 3:
        return True, "Suspicious subdomains"
    if parsed_url.scheme != "https":
        return True, "Non-HTTPS URL"
    typosquatting, reason = is_typosquatting(domain)
    if typosquatting:
        return True, reason
    keyword_flagged, reason = has_suspicious_keywords(url)
    if keyword_flagged:
        return True, reason
    ip_flagged, reason = has_ip_in_url(url)
    if ip_flagged:
        return True, reason
    return False, "URL seems safe"

# Flask route to handle the URL check
@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'result': 'No URL provided', 'isSafe': False})
    
    is_safe, result = is_suspicious(url)
    return jsonify({'result': result, 'isSafe': is_safe})

# Route to serve the HTML file
@app.route('/')
def index():
    return send_from_directory('', 'index.html')

# Main function to run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
