# Email-Automation-in-cybersecurity

---

# Cybersecurity Automation Project – Automated Email Phishing Detector

**Prepared by:** Salami Shuaib A. Cybersecurity Analyst
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



## Automated Workflow Breakdown


<img width="941" height="705" alt="Screenshot 2025-08-10 210721" src="https://github.com/user-attachments/assets/a661bb18-0f4d-4cc8-832a-2c0cd5f000c9" />






### **Phase 1 – Email Collection & Secure Storage**  
- Analyzed email messages in `.eml` format.  
- Stored all collected emails in an isolated repository to preserve integrity and prevent tampering.  


### **Phase 2 – Email Parsing & Data Structuring**  
- Extracted critical components such as headers, body text, sender information, and attachments.  
- Converted the extracted data into a structured format for automated scanning and analysis.  


### **Phase 3 – Comprehensive Threat Analysis**  
**Header & Spoofing Verification**  
- Verified sender details.  
- Flagged `Return-Path` and `Reply-To` mismatches as potential spoofing indicators.  

**Link Assessment**  
- Checked embedded URLs against live threat intelligence feeds to detect phishing or malicious links.  

**Attachment Inspection**  
- Extracted attachments and generated SHA-256 hashes.  
- Queried VirusTotal for known malware signatures and suspicious activity.  


### **Phase 4 – Threat Intelligence Correlation**  
- Cross-referenced email threat indicators with known attack signatures using a Security Information and Event Management (SIEM) platform.  
- Used real-time intelligence feeds to match URLs, file hashes, and email patterns with active cyber threat campaigns.  

## Core Features Implemented  
- **Attachment Extraction** – Identifies and extracts all non-empty attachments from suspicious emails.  
- **SHA-256 Hashing** – Generates unique hashes for file verification and VirusTotal lookups.  
- **VirusTotal Integration** – Retrieves malicious, suspicious, and harmless detection counts; flags unknown files for manual review.  
- **Header Analysis** – Compares `From`, `Return-Path`, and `Reply-To` fields to detect spoofing attempts.  



## Sample Output

| From                                            | Return-Path                                     | Reply-To                                        | Verdict   | SHA-256 Hash | VT Malicious Count |
| ----------------------------------------------- | ----------------------------------------------- | ----------------------------------------------- | --------- | ------------ | ------------------ |
| [sender@example.com](mailto:sender@example.com) | [sender@example.com](mailto:sender@example.com) | [sender@example.com](mailto:sender@example.com) | SAFE      | abc123...    | 0                  |
| [attacker@evil.com](mailto:attacker@evil.com)   | [hacker@evil.com](mailto:hacker@evil.com)       | [scam@evil.com](mailto:scam@evil.com)           | MALICIOUS | xyz456...    | 5                  |




## Technologies & Tools  
- **Python** – Email parsing, hashing, API integration  
- **VirusTotal API** – Threat intelligence  
- **python-dotenv** – Secure API key handling  
- **Requests library** – HTTP API calls  
- **CSV Reports** – Structured result storage



## CSV Report Summary  
The CSV report contains:  
- Email header details  
- Mismatch flags  
- Attachment details and SHA-256 hashes  
- VirusTotal detection statistics


<img width="1513" height="134" alt="image" src="https://github.com/user-attachments/assets/8fe4c236-785b-4f76-9651-34bf4253badf" />



<img width="1497" height="550" alt="Screenshot 2025-08-14 222425" src="https://github.com/user-attachments/assets/8b2f76d8-d2d7-4810-a708-cb98705247ef" />


---

## Future Enhancements

* Implement **URL extraction and scanning** from email bodies
* Integrate **ClamAV** for local attachment scanning
* Provide **JSON + CSV** outputs for SIEM ingestion
* Enable **live IMAP monitoring** for continuous scanning
* Add **machine learning** classification for phishing prediction




## Conclusion  
This project demonstrates how targeted automation can significantly improve phishing email and malware detection.  
By integrating secure email collection, structured parsing, threat intelligence lookups, and SIEM correlation, it provides a scalable, efficient, and proactive threat detection framework.  


---


---

