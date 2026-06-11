import requests


HEADERS = {"User-Agent": "Mozilla/5.0"}

indexes = {
    "avis":   "https://cert.ssi.gouv.fr/avis/json/",
    "alerte": "https://cert.ssi.gouv.fr/alerte/json/",
}

catalogue = []
for type_bulletin, url in indexes.items():
    items = requests.get(url, headers=HEADERS).json()
    for it in items:
        catalogue.append({
            "type": type_bulletin,
            "id": it["reference"],
            "titre": it["title"],
            "date": it["last_revision_date"],
            "json_url": "https://cert.ssi.gouv.fr" + it["json_url"],
        })

print(f"{len(catalogue)} bulletins au total")
print(catalogue[0])