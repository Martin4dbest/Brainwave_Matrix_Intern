# Project Summary

## Overview
This repository contains two security-related projects developed by Martin Agoha during my internship at Brainwave Matrix Solutions. These projects are designed to enhance online security by addressing common vulnerabilities: password strength and phishing attempts.

## Projects

### 1. Password Strength Checker
The **Password Strength Checker** is a Python-based tool that evaluates user-entered passwords to determine their strength. It provides feedback on how to improve security by analyzing password length, complexity, and common patterns.

#### Features
- Analyzes password length and character diversity.
- Detects common patterns and sequences.
- Provides user-friendly feedback on password strength.

#### Requirements
- Python 3.x
- Flask framework

#### Installation
1. Clone the repository.
2. Install the required Python packages.
3. Run the Flask application and access the interface via a web browser.

---

### 2. Phishing Link Scanner
The **Phishing Link Scanner** is a Python-based tool that evaluates URLs to determine potential phishing attempts. It employs various checks, including analyzing common phishing keywords, inspecting URL structures, and integrating with the VirusTotal API for reputation checks.

#### Features
- Detects phishing URLs based on keywords.
- Identifies potential typosquatting on known domains.
- Queries VirusTotal API to assess URL reputation.

#### Requirements
- Python 3.x
- Requests library
- A VirusTotal API key

#### Installation
1. Clone the repository.
2. Install the required Python packages.
3. Replace the placeholder API key in the script with your actual API key and run the script from the command line.

## Contributing
If you have suggestions or improvements for either project, feel free to open an issue or submit a pull request.

## License
Both projects are licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- Flask for the Password Strength Checker.
- VirusTotal for URL reputation checking in the Phishing Link Scanner.
- Python Requests library for HTTP requests.
