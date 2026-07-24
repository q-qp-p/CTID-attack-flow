import {
    type StructuredExtractionValidationFailure,
    type StructuredExtractionValidationResult
} from "./StructuredExtractionValidationContracts";
import {
    validateStructuredExtractionOutput,
    type StructuredExtractionValidatorInput
} from "./StructuredExtractionValidator";

const REPAIR_FAILURE_MESSAGES = {
    failed: "single structural repair pass did not produce valid structured extraction output"
} as const;

export interface StructuredExtractionRepairResult {
    validation: StructuredExtractionValidationResult;
}

/**
 * Runs validation and, when practical, performs one bounded structural repair
 * pass before re-validating.
 */
export function validateAndRepairStructuredExtractionOutput(
    output: StructuredExtractionValidatorInput
): StructuredExtractionRepairResult {
    const initialValidation = validateStructuredExtractionOutput(output);
    if (initialValidation.status !== "repairable") {
        return { validation: initialValidation };
    }

    const repairedInput = attemptSingleStructuralRepair(output);
    if (repairedInput === null) {
        return {
            validation: markAsUnrecoverable(initialValidation, [buildRepairFailure("structured_extraction_repair_failed", REPAIR_FAILURE_MESSAGES.failed)])
        };
    }

    const repairedValidation = validateStructuredExtractionOutput(repairedInput);
    if (repairedValidation.status === "valid") {
        return {
            validation: {
                ...repairedValidation,
                repairAttempted: true
            }
        };
    }

    return {
        validation: markAsUnrecoverable(repairedValidation, [
            buildRepairFailure(
                "structured_extraction_repair_failed",
                REPAIR_FAILURE_MESSAGES.failed
            )
        ])
    };
}

function attemptSingleStructuralRepair(
    output: StructuredExtractionValidatorInput
): StructuredExtractionValidatorInput | null {
    if (typeof output.outputText !== "string") {
        return null;
    }

    const repairedText = extractLikelyJsonObject(output.outputText);
    if (repairedText === null || repairedText === output.outputText) {
        return null;
    }

    return {
        ...output,
        outputText: repairedText
    };
}

function extractLikelyJsonObject(text: string): string | null {
    const trimmed = text.trim();
    if (!trimmed) {
        return null;
    }

    const withoutFence = stripMarkdownCodeFence(trimmed);
    const firstBrace = withoutFence.indexOf("{");
    const lastBrace = withoutFence.lastIndexOf("}");
    if (firstBrace < 0 || lastBrace <= firstBrace) {
        return null;
    }

    return withoutFence.slice(firstBrace, lastBrace + 1).trim();
}

function stripMarkdownCodeFence(text: string): string {
    if (!text.startsWith("```") && !text.endsWith("```")) {
        return text;
    }

    return text
        .replace(/^```(?:json)?\s*/i, "")
        .replace(/\s*```$/i, "")
        .trim();
}

function markAsUnrecoverable(
    validation: StructuredExtractionValidationResult,
    extraFailures: StructuredExtractionValidationFailure[]
): StructuredExtractionValidationResult {
    const failures = [...validation.failures, ...extraFailures].map((failure) => ({
        ...failure,
        repairAttempted: true
    }));
    return {
        status: "unrecoverable",
        repairAttempted: true,
        failures,
        message: failures[0]?.message ?? "structured extraction output is unrecoverable after one repair pass",
        result: undefined
    };
}

function buildRepairFailure(
    code: string,
    message: string
): StructuredExtractionValidationFailure {
    return {
        code,
        category: "repair",
        message,
        repairAttempted: true
    };
}
