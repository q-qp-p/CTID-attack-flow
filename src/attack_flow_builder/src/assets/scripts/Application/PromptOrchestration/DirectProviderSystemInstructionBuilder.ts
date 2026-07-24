import {
    DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES
} from "./DirectProviderAfbIntermediateShape";
import { STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION } from "../StructuredExtraction/StructuredExtractionContracts";
import {
    DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
    type DirectProviderPromptConstraints,
    type DirectProviderSystemInstructionModel
} from "./DirectProviderRequestModels";

export const DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT = [
    "You are a deterministic extraction system for Direct Provider Mode.",
    "Follow these rules exactly:",
    "1. Do not infer ATT&CK tactics or techniques.",
    "2. Only preserve ATT&CK references that are explicit in the source.",
    "3. Attack-action steps are allowed even when no technique is available.",
    "4. Attack-action descriptions must be verbatim source excerpts only.",
    "5. Do not paraphrase, summarize, rewrite, or otherwise change source text meaning.",
    "6. Use only AND or OR for attack-operator values.",
    "7. Use only true or false for attack-condition values.",
    "8. Do not invent branching or inferred control flow.",
    "9. Return a single JSON object that fits the pinned AFB-compatible extraction output shape.",
    `10. Set schema_version exactly to ${STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION}.`,
    "11. Do not use version or schemaName fields in the output.",
    "12. Every attack-action, attack-condition, attack-operator, and attack-asset item must include spec_version = \"2.1\".",
    "13. Every confidence value must be a decimal number between 0 and 1, never a percentage.",
    "14. Every attack-action must include id, type, spec_version, name, description, and confidence.",
    "15. Every attack-condition must include id, type, spec_version, description, value, and confidence.",
    "16. Every attack-operator must include id, type, spec_version, operator, and confidence.",
    "17. Every attack-asset must include id, type, spec_version, name, and confidence.",
    "18. Every attack-action, attack-condition, attack-operator, and attack-asset must include evidence with source and excerpt.",
    "19. For attack-action and attack-condition, evidence excerpt must exactly match the description.",
    "20. Keep authors, external references, evidence/citations, and confidence source-grounded and deterministic."
].join("\n");

export interface DirectProviderSystemInstructionBundle {
    version: typeof DIRECT_PROVIDER_REQUEST_MODEL_VERSION;
    schemaName: typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME;
    systemInstructions: DirectProviderSystemInstructionModel;
    text: string;
    allowedOperatorValues: readonly typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES[number][];
    allowedConditionValues: readonly typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES[number][];
}

/**
 * Builds the deterministic instruction bundle used to encode the hard
 * extraction constraints for Direct Provider Mode.
 */
export function buildDirectProviderSystemInstructionBundle(): DirectProviderSystemInstructionBundle {
    return {
        version: DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION,
        schemaName: DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME,
        systemInstructions: buildDirectProviderSystemInstructionModel(),
        text: DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT,
        allowedOperatorValues: DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES,
        allowedConditionValues: DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES
    };
}

/**
 * Returns the stable system instruction text for the AFA-95 request path.
 */
export function buildDirectProviderSystemInstructionModel(): DirectProviderSystemInstructionModel {
    return {
        version: DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
        constraints: buildDirectProviderPromptConstraints()
    };
}

/**
 * Returns the exact system instruction text used by the request builder.
 */
export function buildDirectProviderSystemInstructionText(): string {
    return DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT;
}

/**
 * Returns the hard constraint flags mirrored by the system instructions.
 */
export function buildDirectProviderPromptConstraints(): DirectProviderPromptConstraints {
    return {
        noAttackInference: true,
        explicitAttackRefsOnly: true,
        allowStepsWithoutTechniques: true,
        descriptionsMustBeVerbatimExcerpts: true,
        onlyAndOrOperators: true,
        onlyTrueFalseConditions: true,
        noInferredBranching: true,
        outputMustFitPinnedIntermediateShape: true
    };
}
