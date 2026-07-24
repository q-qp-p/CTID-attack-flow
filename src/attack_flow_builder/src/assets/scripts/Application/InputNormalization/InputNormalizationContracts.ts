export const INPUT_NORMALIZED_SOURCE_TYPES = ["text", "pdf"] as const;

export type InputNormalizedSourceType = typeof INPUT_NORMALIZED_SOURCE_TYPES[number];

/**
 * Basic source metadata preserved in the shared normalized input package.
 */
export interface InputNormalizedMetadata {
    title?: string;
    filename?: string;
    sourceName?: string;
    pageCount?: number;
}

/**
 * Lightweight content statistics for deterministic downstream use.
 */
export interface InputNormalizedContentStats {
    characterCount?: number;
    wordCount?: number;
    lineCount?: number;
    paragraphCount?: number;
}

/**
 * Shared browser-side normalized input package for raw text and extracted PDF text.
 */
export interface NormalizedInputPackage {
    sourceType: InputNormalizedSourceType;
    normalizedText: string;
    metadata: InputNormalizedMetadata;
    contentStats?: InputNormalizedContentStats;
}
