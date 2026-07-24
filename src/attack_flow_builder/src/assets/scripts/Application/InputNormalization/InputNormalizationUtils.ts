import type { InputNormalizedContentStats } from "./InputNormalizationContracts";

/**
 * Normalizes text deterministically without paraphrasing or rewriting it.
 * Line endings are normalized, outer whitespace is trimmed, and repeated
 * blank lines are collapsed while preserving paragraph boundaries.
 */
export function normalizeInputText(text: string): string {
    const normalizedLines = text
        .replace(/\r\n?/g, "\n")
        .split("\n")
        .map(line => line.trimEnd());

    const collapsedLines: string[] = [];
    let previousWasBlank = false;

    for (const line of normalizedLines) {
        const isBlank = line.trim().length === 0;
        if (isBlank) {
            if (previousWasBlank || collapsedLines.length === 0) {
                previousWasBlank = true;
                continue;
            }
            collapsedLines.push("");
            previousWasBlank = true;
            continue;
        }

        collapsedLines.push(line);
        previousWasBlank = false;
    }

    return collapsedLines.join("\n").trim();
}

/**
 * Counts normalized lines after deterministic cleanup.
 */
export function countNormalizedLines(text: string): number {
    const normalized = normalizeInputText(text);
    if (!normalized) {
        return 0;
    }

    return normalized.split("\n").length;
}

/**
 * Counts normalized paragraphs separated by single blank lines.
 */
export function countNormalizedParagraphs(text: string): number {
    const normalized = normalizeInputText(text);
    if (!normalized) {
        return 0;
    }

    return normalized
        .split("\n\n")
        .map(paragraph => paragraph.trim())
        .filter(Boolean)
        .length;
}

/**
 * Builds the lightweight stats package for normalized text.
 */
export function buildNormalizedContentStats(normalizedText: string): InputNormalizedContentStats {
    return {
        characterCount: normalizedText.length,
        wordCount: normalizedText ? normalizedText.split(/\s+/).filter(Boolean).length : 0,
        lineCount: countNormalizedLines(normalizedText),
        paragraphCount: countNormalizedParagraphs(normalizedText)
    };
}
