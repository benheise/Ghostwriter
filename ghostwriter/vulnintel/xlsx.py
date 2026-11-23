"""KEV and EPSS columns for the Excel report."""

HEADERS = ["KEV", "KEV Due Date", "Known Ransomware Use", "Highest EPSS", "EPSS Percentile"]


def write_cells(workbook, worksheet, row, col, finding, text_format, cache):
    """Write a finding's KEV and EPSS columns starting at ``col`` and return the next column."""
    if "percent" not in cache:
        percent = workbook.add_format({"num_format": "0.00%"})
        percent.set_align("vcenter")
        cache["percent"] = percent

    worksheet.write_string(row, col, ", ".join(finding.get("kev_cves") or []), text_format)
    worksheet.write_string(row, col + 1, finding.get("kev_due_date") or "", text_format)
    worksheet.write_string(row, col + 2, "Yes" if finding.get("kev_ransomware") else "", text_format)
    for offset, key in ((3, "epss_max"), (4, "epss_max_percentile")):
        value = finding.get(key)
        if isinstance(value, (int, float)):
            worksheet.write_number(row, col + offset, value, cache["percent"])
        else:
            worksheet.write_string(row, col + offset, "", text_format)
    return col + len(HEADERS)
