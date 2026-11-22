/// CVE identifier helpers shared by the collaboration server and the browser forms.

/** A CVE identifier: the year, then a sequence number of at least four digits. */
export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;

/** Characters that separate CVE identifiers typed or pasted into the editor. */
export const CVE_ID_DELIMITERS = "[,;\\s]+";

/** Upper-cases and trims a typed CVE identifier. */
export function normalizeCve(value: string): string {
    return value.trim().toUpperCase();
}

function sortKey(cve: string): [number, number] {
    const [, year, number] = cve.split("-");
    return [parseInt(year, 10), parseInt(number, 10)];
}

/**
 * Returns the valid CVE identifiers in `value`, normalized, de-duplicated, and sorted
 * by year and number. Anything that is not a CVE identifier is dropped.
 */
export function cleanCves(value: unknown): string[] {
    if (!Array.isArray(value)) return [];
    const valid = new Set<string>();
    for (const item of value) {
        if (typeof item !== "string") continue;
        const cve = normalizeCve(item);
        if (CVE_ID_PATTERN.test(cve)) valid.add(cve);
    }
    return Array.from(valid).sort((a, b) => {
        const [ay, an] = sortKey(a);
        const [by, bn] = sortKey(b);
        return ay - by || an - bn;
    });
}

/**
 * Prepares CVE identifiers for a GraphQL mutation. The generated types describe every
 * `jsonb` column as an object, but the `cves` column holds a JSON array.
 */
export function cvesToJsonb(cves: string[]): Record<string, unknown> {
    return cves as unknown as Record<string, unknown>;
}
