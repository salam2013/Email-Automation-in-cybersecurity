import os
import re
import email
import requests
import base64
import time
import argparse
import pandas as pd
from email import policy
from email.parser import BytesParser
from dotenv import load_dotenv
from analyzers import (
    extract_attachments,
    hash_sha256,
    check_file_hash_virustotal,
    analyze_headers
)

# Load API key securely
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Parses the email using the email library
def parse_eml(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg['subject']
    sender = msg['from']
    to = msg['to']

    body = ""

    # Handle both multipart and non-multipart safely
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Skip attachments
            if "attachment" in content_disposition:
                continue

            if content_type == "text/plain":
                try:
                    body = part.get_content()
                    break
                except:
                    continue
    else:
        try:
            body_part = msg.get_body(preferencelist=('plain'))
            if body_part:
                body = body_part.get_content()
            else:
                body = msg.get_content()
        except:
            body = ""

    return sender, to, subject, body, msg

# Extracts url using the regex library
def extract_urls(text):
    return re.findall(r'https?://\S+', text)

#Checks URL on VirusTotal using our API Key
def check_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}

    try:
        # Submit the URL for scanning
        scan_url = "https://www.virustotal.com/api/v3/urls"
        post_resp = requests.post(scan_url, headers=headers, data={"url": url})

        if post_resp.status_code != 200:
            return {"error": f"POST failed: {post_resp.status_code} - {post_resp.text}"}

        # VirusTotal returns an ID we need to use to query analysis
        url_id = post_resp.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"

        # Wait for scan results to be available (Free tier can be slow)
        time.sleep(15)

        get_resp = requests.get(analysis_url, headers=headers)

        if get_resp.status_code != 200:
            return {"error": f"GET failed: {get_resp.status_code} - {get_resp.text}"}

        result = get_resp.json()
        stats = result["data"]["attributes"]["stats"]
        return stats

    except Exception as e:
        return {"error": str(e)}

    #Gives verdicts from scan and notifies is url is malicious    
def verdict_from_stats(stats):
    if not isinstance(stats, dict):
        return "ERROR"
    if stats.get("malicious", 0) > 0:
        return "MALICIOUS"
    elif stats.get("suspicious", 0) > 0:
        return "SUSPICIOUS"
    elif stats.get("harmless", 0) > 0 or stats.get("undetected", 0) > 10:
        return "CLEAN"
    else:
        return "UNKNOWN"

#process all mails in the enmail directory
def process_eml_file(filepath):
    report = []

    print(f"Processing {filepath}...")
    sender, to, subject, body, msg = parse_eml(filepath)

    # Header spoofing analysis
    header_analysis = analyze_headers(msg)
    if header_analysis.get("return_path_mismatch") or header_analysis.get("reply_to_mismatch"):
        report.append({
            "filename": os.path.basename(filepath),
            "sender": sender,
            "to": to,
            "subject": subject,
            "url": "[Header Spoofing Check]",
            "vt_result": header_analysis,
            "verdict": "SUSPICIOUS"
        })

    # URL analysis
    urls = extract_urls(body)
    for url in urls:
        vt_result = check_url_virustotal(url)
        report.append({
            "filename": os.path.basename(filepath),
            "sender": sender,
            "to": to,
            "subject": subject,
            "url": url,
            "vt_result": vt_result,
            "verdict": verdict_from_stats(vt_result)
        })

    # Attachment analysis
    attachments = extract_attachments(msg)
    for fname, payload in attachments:
        file_hash = hash_sha256(payload)
        vt_result = check_file_hash_virustotal(file_hash)
        verdict = verdict_from_stats(vt_result)
    if verdict == "UNKNOWN":
        vt_result = {"verdict": "Not found in VirusTotal database"}

        report.append({
            "filename": os.path.basename(filepath),
            "sender": sender,
            "to": to,
            "subject": subject,
            "url": f"[Attachment: {fname}]",
            "vt_result": vt_result,
            "verdict": verdict
        })

    return pd.DataFrame(report)

def summarize_report(df):
    verdict_counts = df['verdict'].value_counts()
    malicious = verdict_counts.get("MALICIOUS", 0)
    suspicious = verdict_counts.get("SUSPICIOUS", 0)
    clean = verdict_counts.get("CLEAN", 0)
    unknown = verdict_counts.get("UNKNOWN", 0)

    print("\n🔍 Scan Summary:")
    print(f"  ⚠️  Malicious items  : {malicious}")
    print(f"  ❗ Suspicious items  : {suspicious}")
    print(f"  ✅ Clean items       : {clean}")
    print(f"  ❓ Unknown verdicts  : {unknown}")

    spoofing_alerts = df[df["url"] == "[Header Spoofing Check]"]
    if not spoofing_alerts.empty:
        print(f"  📬 Header spoofing alerts: {len(spoofing_alerts)}")


def process_all_emails(directory):
    all_reports = []
    for file in os.listdir(directory):
        if file.endswith(".eml"):
            filepath = os.path.join(directory, file)
            df = process_eml_file(filepath)
            all_reports.append(df)
    return pd.concat(all_reports, ignore_index=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Email phishing scanner")
    parser.add_argument("--input", required=True, help="Path to .eml file or folder")
    parser.add_argument("--output", default="report.csv", help="Output CSV file path")
    args = parser.parse_args()

    if os.path.isdir(args.input):
        final_df = process_all_emails(args.input)
    elif os.path.isfile(args.input) and args.input.endswith(".eml"):
        final_df = process_eml_file(args.input)
    else:
        print("❌ Input path is invalid. Must be a folder or .eml file.")
        exit(1)

    # Optional: summarize
    summarize_report(final_df)

    final_df.to_csv(args.output, index=False)
    print(f"\n✅ Report saved to {args.output}")


