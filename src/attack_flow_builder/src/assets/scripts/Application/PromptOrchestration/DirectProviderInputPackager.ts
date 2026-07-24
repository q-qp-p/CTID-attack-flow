import type {
    InputNormalizedContentStats,
    InputNormalizedMetadata,
    NormalizedInputPackage
} from "../InputNormalization";
import type { DirectProviderInputPayload } from "./DirectProviderRequestModels";

/**
 * Builds the provider-facing input payload from the normalized browser-side
 * package without adding ATT&CK semantics or other interpretation.
 */
export function buildDirectProviderInputPayload(
    normalizedInput: NormalizedInputPackage
): DirectProviderInputPayload {
    return {
        sourceType: normalizedInput.sourceType,
        normalizedText: normalizedInput.normalizedText,
        metadata: cloneMetadata(normalizedInput.metadata),
        contentStats: cloneContentStats(normalizedInput.contentStats)
    };
}

function cloneMetadata(metadata: InputNormalizedMetadata): InputNormalizedMetadata {
    return {
        title: metadata.title,
        filename: metadata.filename,
        sourceName: metadata.sourceName,
        pageCount: metadata.pageCount
    };
}

function cloneContentStats(
    contentStats: InputNormalizedContentStats | undefined
): InputNormalizedContentStats | undefined {
    if (!contentStats) {
        return undefined;
    }

    return {
        characterCount: contentStats.characterCount,
        wordCount: contentStats.wordCount,
        lineCount: contentStats.lineCount,
        paragraphCount: contentStats.paragraphCount
    };
}
