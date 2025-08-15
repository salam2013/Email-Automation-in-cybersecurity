# Email-Automation-in-cybersecurity

---

# BNS Cybersecurity Automation Project – Automated Email Phishing Detector

**Prepared by:** Salami Shuaib
**Date:** 10th August 2025

---

## Overview

The **Cybersecurity Automation Project** is a Python-based system designed to automate the detection and analysis of phishing emails and other malicious communications.
The tool streamlines the process of collecting, parsing, and assessing incoming emails while integrating with threat intelligence sources for proactive defense.
This hands-on implementation showcases a complete cybersecurity automation workflow, from email ingestion to actionable threat verdicts.

---

##  Features

* **Email Collection & Storage** – Processes `.eml` email files and stores them securely for analysis.
* **Header & Spoofing Checks** – Compares `From`, `Return-Path`, and `Reply-To` fields to detect spoofing.
* **Link Analysis** – Scans embedded URLs against live threat intelligence feeds.
* **Attachment Inspection** – Extracts and hashes attachments (SHA-256) for malware reputation checks.
* **VirusTotal API Integration** – Retrieves malicious, suspicious, and harmless detection counts.
* **Structured CSV Reporting** – Outputs all analysis results in an easy-to-read format for SIEM integration.

---

##  Project Structure

```
automated_email_phishing_detector/
│
├── main.py                  # Main script for running the analysis
├── analyzers.py              # Helper functions for parsing and threat detection
├── emails/                   # Sample .eml email files
├── task1.csv                 # Sample output CSV report
├── .env                      # API keys and configuration variables
```

---

## Technologies & Tools

* **Python 3** – Core programming language
* **VirusTotal API** – Malware and URL threat intelligence
* **python-dotenv** – Secure API key handling
* **Requests** – HTTP API communication
* **CSV Module** – Structured result export

---

##  Installation

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/automated_email_phishing_detector.git
cd automated_email_phishing_detector
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Set up environment variables**
   Create a `.env` file with:

```
VT_API_KEY=your_api_key_here
```

---

## Usage

Run the tool on a folder of `.eml` files:

```bash
python main.py --input emails/
```

The output will be saved as a CSV file summarizing:

* Sender details
* Header mismatches
* Attachment hashes
* VirusTotal verdicts

---

## 📊 Sample Output

| From                                            | Return-Path                                     | Reply-To                                        | Verdict   | SHA-256 Hash | VT Malicious Count |
| ----------------------------------------------- | ----------------------------------------------- | ----------------------------------------------- | --------- | ------------ | ------------------ |
| [sender@example.com](mailto:sender@example.com) | [sender@example.com](mailto:sender@example.com) | [sender@example.com](mailto:sender@example.com) | SAFE      | abc123...    | 0                  |
| [attacker@evil.com](mailto:attacker@evil.com)   | [hacker@evil.com](mailto:hacker@evil.com)       | [scam@evil.com](mailto:scam@evil.com)           | MALICIOUS | xyz456...    | 5                  |

---

## 🔮 Future Enhancements

* Implement **URL extraction and scanning** from email bodies
* Integrate **ClamAV** for local attachment scanning
* Provide **JSON + CSV** outputs for SIEM ingestion
* Enable **live IMAP monitoring** for continuous scanning
* Add **machine learning** classification for phishing prediction

---

## 📜 License

This project is licensed under the MIT License.

---

If you’d like, I can now **insert this README.md directly into your extracted ZIP folder** so it’s ready for upload to GitHub.
Do you want me to do that?
