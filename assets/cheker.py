import requests
from assets.config import API_KEY
from pathlib import Path

def ip_checker(ip_address):
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    url_ip = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    response_ip = requests.get(url_ip, headers=headers)

    if response_ip.status_code != 200:
        return {"error": "IP report not found"}

    data_ip = response_ip.json()
    attributes = data_ip["data"]["attributes"]
    stats = attributes["last_analysis_stats"]

    url_comments = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/comments?limit=10"
    response_comments = requests.get(url_comments, headers=headers)

    comments = []

    if response_comments.status_code == 200:
        data_comments = response_comments.json()

        for item in data_comments.get("data", []):
            text = item["attributes"].get("text", "")
            comments.append(text)

    return {
        "ip": ip_address,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "asn": attributes.get("asn", "Unknown"),
        "as_owner": attributes.get("as_owner", "Unknown"),
        "country": attributes.get("country", "Unknown"),
        "network": attributes.get("network", "Unknown"),
        "comments": comments
    }

def url_cheker(target_url):
    api_url = "https://www.virustotal.com/api/v3/urls"

    payload = {"url": target_url}
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": API_KEY
    }

    response = requests.post(api_url, data=payload, headers=headers)

    if response.status_code not in (200, 201):
        return {"error": "Url report not found"}

    data = response.json()

    return {
        "url": target_url,
        "id": data["data"]["id"],
        "analysis_url": data["data"]["links"]["self"]
    }

def domain_checker(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": "Domain report not found"}

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    return {
        "domain": data.get("data", {}).get("id", domain),
        "registrar": attributes.get("registrar", "Unknown"),
        "reputation": attributes.get("reputation", "Unknown"),
        "total_votes": attributes.get("total_votes", {"harmless": 0, "malicious": 0}),
        "last_analysis_stats": attributes.get("last_analysis_stats", {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}),
        "url": data.get("data", {}).get("links", {}).get("self", f"https://www.virustotal.com/gui/domain/{domain}")
    }


def send_file_to_virustotal(file_path: Path):
    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "x-apikey": API_KEY
    }

    with open(file_path, "rb") as f:
        files = {
            "file": (file_path.name, f)
        }

        response = requests.post(url, headers=headers, files=files)

    if response.status_code != 200:
        return {"error": "Upload failed"}

    data = response.json()
    return {
        "analysis_id": data["data"]["id"],
        "analysis_url": data["data"]["links"]["self"]
    }


def analysis_report(analysis_id: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "status": attributes.get("status", "unknown"),
        "permalink": f"https://www.virustotal.com/gui/analysis/{analysis_id}"
    }




