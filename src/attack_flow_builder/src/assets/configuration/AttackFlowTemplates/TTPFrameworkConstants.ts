export type FrameworkEntry = [code: string, label: string];

export const TTP_FRAMEWORKS: FrameworkEntry[] = [
    ["ENT", "MITRE ATT&CK Enterprise (ENT)"],
    ["MOB", "MITRE ATT&CK Mobile (MOB)"],
    ["ICS", "MITRE ATT&CK ICS (ICS)"],
    ["ATL", "MITRE ATLAS (ATL)"],
    ["D3F", "MITRE D3FEND (D3F)"],
    ["F3", "MITRE F3 (F3)"]
];

export const FRAMEWORK_LABELS = new Map<string, string>(TTP_FRAMEWORKS);

export const frameworkFullName = (code?: string) => {
    if (!code) { return undefined; }
    const label = FRAMEWORK_LABELS.get(code);
    if (!label) { return code; }
    return label;
};

// For example: /^\[(ENT|MOB|ICS|ATL|D3F|F3)\]/
export const TTP_FRAMEWORK_REGEX: RegExp = new RegExp(
    `^\\[(${TTP_FRAMEWORKS.map(([code]) => code).join("|")})\\]`
);
