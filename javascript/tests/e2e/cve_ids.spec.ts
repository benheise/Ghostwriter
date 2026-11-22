import { expect, test } from "@playwright/test";

import {
    CVE_ID_DELIMITERS,
    CVE_ID_PATTERN,
    cleanCves,
    cvesToJsonb,
    normalizeCve,
} from "../../src/services/cve";

test("CVE identifiers are normalized before they are checked", () => {
    expect(normalizeCve("  cve-2021-44228 ")).toBe("CVE-2021-44228");
    expect(CVE_ID_PATTERN.test(normalizeCve("cve-2021-44228"))).toBe(true);
    for (const value of ["CVE-21-44228", "CVE-2021-123", "Log4Shell", ""]) {
        expect(CVE_ID_PATTERN.test(normalizeCve(value))).toBe(false);
    }
});

test("cleanCves keeps valid identifiers, sorted by year and number", () => {
    expect(
        cleanCves([
            "CVE-2021-10000",
            "cve-2021-9999",
            "CVE-2014-0160",
            "CVE-2021-9999",
            "not a CVE",
            7,
            null,
        ])
    ).toEqual(["CVE-2014-0160", "CVE-2021-9999", "CVE-2021-10000"]);
    expect(cleanCves(null)).toEqual([]);
    expect(cleanCves({ cve: "CVE-2021-44228" })).toEqual([]);
});

test("typed identifiers split on commas, semicolons, and whitespace", () => {
    const delimiters = new RegExp(CVE_ID_DELIMITERS);
    expect(
        "CVE-2021-44228, CVE-2014-0160;CVE-2023-4966\nCVE-2019-19781"
            .split(delimiters)
            .map(normalizeCve)
    ).toEqual([
        "CVE-2021-44228",
        "CVE-2014-0160",
        "CVE-2023-4966",
        "CVE-2019-19781",
    ]);
});

test("cvesToJsonb passes the list through unchanged", () => {
    const cves = ["CVE-2021-44228"];
    expect(cvesToJsonb(cves)).toBe(cves);
});
