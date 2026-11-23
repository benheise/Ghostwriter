"""Small, well-formed KEV and EPSS documents for tests."""

# Standard Libraries
import gzip
import json


def kev_entry(cve_id, **overrides):
    entry = {
        "cveID": cve_id,
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": f"Example Product vulnerability {cve_id}",
        "dateAdded": "2026-11-01",
        "shortDescription": "An example vulnerability.",
        "requiredAction": "Apply the vendor's update.",
        "dueDate": "2026-11-22",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "https://example.com/advisory",
        "cwes": ["CWE-502"],
    }
    entry.update(overrides)
    return entry


def kev_document(entries, version="2026.11.20", released="2026-11-20T17:48:39.1516Z"):
    return json.dumps(
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": version,
            "dateReleased": released,
            "count": len(entries),
            "vulnerabilities": entries,
        }
    ).encode()


def epss_document(rows, score_date="2026-11-22", model="v2026.06.15", compress=True):
    lines = [f"#model_version:{model},score_date:{score_date}T12:03:04Z", "cve,epss,percentile"]
    lines += [f"{cve_id},{epss},{percentile}" for cve_id, epss, percentile in rows]
    data = ("\n".join(lines) + "\n").encode()
    return gzip.compress(data) if compress else data


def epss_api_document(rows, status="OK"):
    return json.dumps(
        {
            "status": status,
            "status-code": 200,
            "version": "1.0",
            "total": len(rows),
            "data": [
                {"cve": cve_id, "epss": epss, "percentile": percentile, "date": score_date}
                for cve_id, epss, percentile, score_date in rows
            ],
        }
    ).encode()
