"""
ANSSI CVE project - Steps 1 to 4 (fully local, no network calls).

Pipeline:
  1. Load the bulletin catalogue from local files (avis + alertes)
  2. Extract the CVEs referenced in each bulletin
  3. Enrich each CVE with CVSS / CWE / EPSS from the local mitre/ and first/ folders
  4. Consolidate everything into a pandas DataFrame and export to CSV

Expected folder layout:
  data/
    Avis/      -> bulletin JSON files, named by reference (e.g. CERTFR-2023-AVI-0001)
    alertes/   -> bulletin JSON files, named by reference
    mitre/     -> MITRE data, one file per CVE (e.g. CVE-2022-45143)
    first/     -> EPSS data,  one file per CVE
"""

import os
import re
import json
import pandas as pd




DATA_DIR = "data"
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
FOLDERS = {"avis": "Avis", "alerte": "alertes"}

_cache = {}



def extract_cves(bulletin_json):
    """Pull CVE ids from a bulletin JSON (official 'cves' key + regex fallback)."""
    from_key = [c["name"] for c in bulletin_json.get("cves", [])]
    from_regex = re.findall(CVE_PATTERN, str(bulletin_json))
    return sorted(set(from_key + from_regex))



def load_local_catalogue():
    """Read every bulletin file from data/Avis and data/alertes."""
    catalogue = []
    for type_bulletin, folder in FOLDERS.items():
        folder_path = os.path.join(DATA_DIR, folder)
        for filename in os.listdir(folder_path):
            path = os.path.join(folder_path, filename)
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Echec lecture {filename}: {e}")
                continue

            revisions = data.get("revisions", [])
            date = revisions[-1]["revision_date"] if revisions else None

            catalogue.append({
                "type": type_bulletin,
                "id": data.get("reference", filename),
                "titre": data.get("title"),
                "date": date,
                "cves": extract_cves(data),
                "raw": data,
            })
    return catalogue



def enrich_mitre_local(cve_id):
    """Read CVSS / CWE / affected products for one CVE from data/mitre/<cve_id>."""
    path = os.path.join(DATA_DIR, "mitre", cve_id)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    cna = data["containers"]["cna"]

    description = cna["descriptions"][0]["value"]

    cvss = None
    for metric in cna.get("metrics", []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                cvss = metric[key].get("baseScore")
                break
        if cvss is not None:
            break

    cwe = None
    problemtypes = cna.get("problemTypes", [])
    if problemtypes and problemtypes[0].get("descriptions"):
        cwe = problemtypes[0]["descriptions"][0].get("cweId")

    produits = []
    for p in cna.get("affected", []):
        produits.append({
            "vendor": p.get("vendor"),
            "product": p.get("product"),
            "versions": [v.get("version") for v in p.get("versions", [])
                         if v.get("status") == "affected"],
        })

    return {"description": description, "cvss": cvss, "cwe": cwe, "produits": produits}


def enrich_epss_local(cve_id):
    """Read the EPSS score for one CVE from data/first/<cve_id>."""
    path = os.path.join(DATA_DIR, "first", cve_id)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    rows = data.get("data", [])
    return float(rows[0]["epss"]) if rows else None


def cvss_to_severity(score):
    """Map a CVSS base score to a severity label."""
    if score is None:
        return None
    if score >= 9:
        return "Critique"
    if score >= 7:
        return "Elevee"
    if score >= 4:
        return "Moyenne"
    return "Faible"


def enrich_cve(cve_id):
    """Enrich one CVE (cached). Missing local files just yield None values."""
    if cve_id in _cache:
        return _cache[cve_id]

    result = {"cvss": None, "cwe": None, "epss": None,
              "description": None, "produits": []}

    try:
        result.update(enrich_mitre_local(cve_id))
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"MITRE parse echec {cve_id}: {e}")

    try:
        result["epss"] = enrich_epss_local(cve_id)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"EPSS parse echec {cve_id}: {e}")

    result["base_severity"] = cvss_to_severity(result["cvss"])
    _cache[cve_id] = result
    return result



def build_dataframe(catalogue):
    """One row per bulletin-CVE pair, enriched and consolidated."""
    rows = []
    for bulletin in catalogue:
        lien = f"https://cert.ssi.gouv.fr/{bulletin['type']}/{bulletin['id']}/"
        cves = bulletin["cves"] or [None]          # keep CVE-less bulletins as one row

        for cve in cves:
            row = {
                "ID ANSSI": bulletin["id"],
                "Titre ANSSI": bulletin["titre"],
                "Type": bulletin["type"],
                "Date": bulletin["date"],
                "CVE": cve,
                "CVSS": None,
                "Base Severity": None,
                "CWE": None,
                "EPSS": None,
                "Lien": lien,
                "Description": None,
                "Editeur": None,
                "Produit": None,
                "Versions affectees": None,
            }

            if cve:
                info = enrich_cve(cve)
                row["CVSS"] = info["cvss"]
                row["Base Severity"] = info["base_severity"]
                row["CWE"] = info["cwe"]
                row["EPSS"] = info["epss"]
                row["Description"] = info["description"]

                vendors = sorted({p["vendor"] for p in info["produits"] if p.get("vendor")})
                produits = sorted({p["product"] for p in info["produits"] if p.get("product")})
                versions = sorted({v for p in info["produits"]
                                   for v in p.get("versions", []) if v})
                row["Editeur"] = ", ".join(vendors) or None
                row["Produit"] = ", ".join(produits) or None
                row["Versions affectees"] = ", ".join(versions) or None

            rows.append(row)

    return pd.DataFrame(rows)



def main():
    catalogue = load_local_catalogue()
    print(f"{len(catalogue)} bulletins charges")

    df = build_dataframe(catalogue)
    print(f"DataFrame: {df.shape[0]} lignes, {df.shape[1]} colonnes")
    print(df.head())

    df.to_csv("donnees_consolidees.csv", index=False, encoding="utf-8-sig")
    print("CSV exporte: donnees_consolidees.csv")
    return df


if __name__ == "__main__":
    df = main()