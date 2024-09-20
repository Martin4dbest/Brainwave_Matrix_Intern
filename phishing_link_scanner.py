from flask import Flask, request, jsonify, send_from_directory
from decouple import config
import requests
from urllib.parse import urlparse
import re
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# VirusTotal API settings
API_KEY = config('VIRUSTOTAL_API_KEY', default=None)
if not API_KEY:
    raise RuntimeError("VirusTotal API key is missing. Please set the VIRUSTOTAL_API_KEY environment variable.")
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
    hostname = urlparse(url).hostname
    if hostname:
        # Regex to check if the hostname is an IP address
        if re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', hostname):
            return True, "URL contains an IP address"
        return False, "No IP address detected in URL"
    return False, "Invalid URL"

# Function to query VirusTotal for URL reputation
def check_virustotal(url):
    params = {'apikey': API_KEY, 'resource': url}
    try:
        response = requests.get(VIRUSTOTAL_URL, params=params, timeout=10)  # 10 seconds timeout
        response.raise_for_status()  # Will raise an HTTPError for bad responses
        result = response.json()

        if result.get("positives", 0) > 0:
            return True, "URL flagged by VirusTotal"
        return False, "URL not flagged by VirusTotal"
    except requests.exceptions.HTTPError as http_err:
        return False, f"HTTP error occurred: {http_err}"
    except Exception as err:
        return False, f"An error occurred: {err}"

# Function to check URL structure and domain for phishing signs
def is_suspicious(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    reasons = []

    if len(url) > 100:
        reasons.append("URL length is suspicious")
    if len(domain.split('.')) > 3:
        reasons.append("Suspicious subdomains")
    if parsed_url.scheme != "https":
        reasons.append("Non-HTTPS URL")

    typosquatting, reason = is_typosquatting(domain)
    if typosquatting:
        reasons.append(reason)

    keyword_flagged, reason = has_suspicious_keywords(url)
    if keyword_flagged:
        reasons.append(reason)

    ip_flagged, reason = has_ip_in_url(url)
    if ip_flagged:
        reasons.append(reason)

    vt_flagged, vt_reason = check_virustotal(url)
    if vt_flagged:
        reasons.append(vt_reason)

    if reasons:
        return True, reasons
    return False, "URL seems safe"

# Flask route to handle the URL check
@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'result': 'No URL provided', 'isSafe': False}), 400  # Bad Request

    is_safe, result = is_suspicious(url)
    
    # Log the results for debugging purposes
    app.logger.info(f"Checked URL: {url}")
    app.logger.info(f"Is Safe: {not is_safe}")
    app.logger.info(f"Result: {result}")
    
    if isinstance(result, list):
        return jsonify({'result': result, 'isSafe': not is_safe})  # Return the list of reasons
    return jsonify({'result': [result], 'isSafe': not is_safe})  # Wrap single result in a list

# Route to serve the HTML file
@app.route('/')
def index():
    return send_from_directory('', 'index.html')

# Main function to run the Flask app
if __name__ == "__main__":
    app.run(debug=config('FLASK_DEBUG', default=False))
