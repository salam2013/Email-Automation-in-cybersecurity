import hashlib
import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_FILE_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/"

def extract_attachments(msg):
    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if filename and payload:
            attachments.append((filename, payload))
    return attachments

def hash_sha256(data):
    return hashlib.sha256(data).hexdigest()

def check_file_hash_virustotal(file_hash):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(VT_FILE_LOOKUP_URL + file_hash, headers=headers)

    if response.status_code == 200:
        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return stats
        except:
            return {"error": "Unable to parse VT response"}
    elif response.status_code == 404:
        return {"verdict": "UNKNOWN"}
    else:
        return {"error": f"{response.status_code}: {response.text}"}

def analyze_headers(msg):
    results = {}

    from_hdr = msg['from']
    return_path = msg['Return-Path']
    reply_to = msg['Reply-To']

    if from_hdr and return_path and return_path not in from_hdr:
        results['return_path_mismatch'] = True
    if from_hdr and reply_to and reply_to not in from_hdr:
        results['reply_to_mismatch'] = True

    results['from'] = from_hdr
    results['return_path'] = return_path
    results['reply_to'] = reply_to

    return results

