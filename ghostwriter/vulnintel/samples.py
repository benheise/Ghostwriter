"""Sample KEV and EPSS values for the report template linter. Kept free of model imports."""

SAMPLE_FINDING = {
    "vuln_intel": [
        {
            "cve": "CVE-2021-44228",
            "kev": {
                "vendor": "Apache",
                "product": "Log4j2",
                "name": "Apache Log4j2 Remote Code Execution Vulnerability",
                "date_added": "Dec 10, 2021",
                "date_added_iso": "2021-12-10",
                "due_date": "Dec 24, 2021",
                "due_date_iso": "2021-12-24",
                "known_ransomware": True,
                "short_description": "Apache Log4j2 contains a remote code execution vulnerability.",
                "required_action": "Apply updates per vendor instructions.",
                "notes": "",
                "cwes": ["CWE-917", "CWE-20"],
            },
            "epss": {
                "score": 0.99999,
                "percentile": 1.0,
                "score_date": "Nov 22, 2026",
                "score_date_iso": "2026-11-22",
                "model_version": "v2026.06.15",
            },
        }
    ],
    "kev": True,
    "kev_cves": ["CVE-2021-44228"],
    "kev_ransomware": True,
    "kev_due_date": "Dec 24, 2021",
    "kev_due_date_iso": "2021-12-24",
    "epss_max": 0.99999,
    "epss_max_percentile": 1.0,
    "epss_max_cve": "CVE-2021-44228",
    "epss_over_threshold": True,
}

SAMPLE_REPORT = {
    "cves": ["CVE-2021-44228"],
    "kev_cves": ["CVE-2021-44228"],
    "kev_catalog_version": "2026.11.20",
    "kev_released": "Nov 20, 2026",
    "kev_updated": "Nov 22, 2026",
    "epss_score_date": "Nov 22, 2026",
    "epss_score_date_iso": "2026-11-22",
    "epss_model_version": "v2026.06.15",
    "epss_threshold": 0.1,
}

SAMPLE_TOTALS = {
    "findings_kev": 1,
    "findings_kev_ransomware": 1,
    "findings_epss_over": 1,
}
