import requests
import os, json, re
import time

HEADERS = {"User-Agent": "Mozilla/5.0"}
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
BASE_URL = "https://cert.ssi.gouv.fr"
INDEXES = {
    "avis":   f"{BASE_URL}/avis/json/",
    "alerte": f"{BASE_URL}/alerte/json/",
}


def fetch_catalogue():
    catalogue = []
    for type_bulletin, url in INDEXES.items():
        items = requests.get(url, headers=HEADERS).json()
        for it in items:
            catalogue.append({
                "type": type_bulletin,
                "id": it["reference"],
                "titre": it["title"],
                "date": it["last_revision_date"],
                "json_url": BASE_URL + it["json_url"],
            })
    return catalogue


def extract_cves(bulletin_json):
    """Pull CVE ids from a bulletin's detail JSON (official key + regex fallback)."""
    from_key = [c["name"] for c in bulletin_json.get("cves", [])]
    from_regex = re.findall(CVE_PATTERN, str(bulletin_json))
    return sorted(set(from_key + from_regex))

def enrich_with_cves(catalogue):
    """Apply extract_cves to every bulletin in the catalogue."""
    for bulletin in catalogue:
        try:
            data = requests.get(bulletin["json_url"], headers=HEADERS).json()
            bulletin["cves"] = extract_cves(data)
            bulletin["raw"] = data
        except Exception as e:
            bulletin["cves"] = []
            print(f"Échec {bulletin['id']}: {e}")
    return catalogue

catalogue = fetch_catalogue()
print(f"Attaching cves, estimated time : {len(catalogue)*2} seconds")
catalogue = enrich_with_cves(catalogue)
print(catalogue[0]["cves"])