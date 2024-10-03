# Phishing Link Scanner

## Project Description
This project is developed by me, Martin Agoha during my internship at Brainwave Matrix Solutions, is a Python-based phishing link scanner. It evaluates URLs to determine if they might be phishing attempts. The scanner employs various checks, including analyzing common phishing keywords, inspecting URL structures, detecting typosquatting, and integrating with VirusTotal to assess URL reputation.

## Features
- Detects phishing URLs based on common keywords.
- Identifies potential typosquatting on well-known domains.
- Checks for suspicious URL structures and non-HTTPS URLs.
- Queries VirusTotal API to check URL reputation.
- Detects the use of IP addresses in URLs.

## Requirements
- Python 3.x
- Requests library (`pip install requests`)
- A VirusTotal API key (replace the placeholder in the script with your actual API key)

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/Martin4dbest/Brainwave_Matrix_Intern.git
   cd phishing-link-scanner
2. Install the required Python packages:
pip install requests

3. Configuration
    Obtain a VirusTotal API key from the VirusTotal website.
    Replace the placeholder API key in the script with your actual API key:

    API_KEY = "your_actual_api_key_here"

4. Usage
    Run the script from the command line to check a URL:
    
    python phishing_link_scanner.py

5. You will be prompted to enter a URL to check. The script will output whether the URL is suspected of phishing or not.
    Example:
    Enter a URL to check: https://example.com
    URL is safe.

6. Testing
    You can test the script with predefined suspicious URLs by modifying the phishing_link_scanner.py file:

    test_urls = [
    "http://login.secure.example.com.fakebank.com",
    "http://update.youraccount-now.com",
    "http://free-gift-money123.com",
    "http://yourbank.example1234.com",
    "https://1.1.1.1/login",
    "https://secure-google.com"
]

for url in test_urls:
    result = phishing_link_scanner(url)
    print(f"URL: {url}\nResult: {result}\n")

7. Contributing
    If you have suggestions or improvements, feel free to open an issue or submit a pull request.

    License
    This project is licensed under the MIT License - see the LICENSE file for details.

    Acknowledgments
    VirusTotal for URL reputation checking.
    Python Requests library for HTTP requests.

# Phishing Link Scanner

.PHONY: install run test clean

## Install required Python packages
install:
	pip install requests

## Run the phishing link scanner
run:
	python phishing_link_scanner.py

## Test the script with predefined URLs
test:
	python -c "from phishing_link_scanner import phishing_link_scanner; \
test_urls = [ \
	'http://login.secure.example.com.fakebank.com', \
	'http://update.youraccount-now.com', \
	'http://free-gift-money123.com', \
	'http://yourbank.example1234.com', \
	'https://1.1.1.1/login', \
	'https://secure-google.com' \
]; \
for url in test_urls: \
	result = phishing_link_scanner(url); \
	print(f'URL: {url}\\nResult: {result}\\n')"

## Clean up files (add any clean-up commands if needed)
clean:
	rm -f *.pyc


