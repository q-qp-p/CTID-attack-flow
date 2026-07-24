import type { StructuredResponseFormat } from "../Providers";
import type {
    InputNormalizedContentStats,
    InputNormalizedMetadata,
    InputNormalizedSourceType,
    NormalizedInputPackage
} from "../InputNormalization";

export const DIRECT_PROVIDER_ORCHESTRATION_MODES = ["direct_provider"] as const;

export type DirectProviderOrchestrationMode = typeof DIRECT_PROVIDER_ORCHESTRATION_MODES[number];

export const DIRECT_PROVIDER_ALLOWED_OPERATOR_VALUES = ["AND", "OR"] as const;

export const DIRECT_PROVIDER_ALLOWED_CONDITION_VALUES = ["true", "false"] as const;

export const DIRECT_PROVIDER_REQUEST_MODEL_VERSION = "v1" as const;

/**
 * Deterministic system-instruction payload used by Direct Provider Mode.
 * Prompt text is not rendered here; only the structured instruction contract
 * is defined for later assembly.
 */
export interface DirectProviderSystemInstructionModel {
    version: typeof DIRECT_PROVIDER_REQUEST_MODEL_VERSION;
    constraints: DirectProviderPromptConstraints;
}

/**
 * Constraint flags that will be encoded into the prompt at a later stage.
 */
export interface DirectProviderPromptConstraints {
    noAttackInference: true;
    explicitAttackRefsOnly: true;
    allowStepsWithoutTechniques: true;
    descriptionsMustBeVerbatimExcerpts: true;
    onlyAndOrOperators: true;
    onlyTrueFalseConditions: true;
    noInferredBranching: true;
    outputMustFitPinnedIntermediateShape: true;
}

/**
 * Normalized source payload consumed by the prompt/orchestration builder.
 */
export interface DirectProviderInputPayload {
    sourceType: InputNormalizedSourceType;
    normalizedText: string;
    metadata: InputNormalizedMetadata;
    contentStats?: InputNormalizedContentStats;
}

/**
 * Declarative response-shape expectation for the downstream provider call.
 */
export interface DirectProviderResponseSchemaExpectation {
    format: StructuredResponseFormat;
    schemaName?: string;
}

/**
 * Provider-agnostic structured generation request payload for Direct Provider Mode.
 */
export interface DirectProviderStructuredGenerationRequestModel {
    version: typeof DIRECT_PROVIDER_REQUEST_MODEL_VERSION;
    mode: DirectProviderOrchestrationMode;
    sourceType: InputNormalizedSourceType;
    systemInstructions: DirectProviderSystemInstructionModel;
    input: DirectProviderInputPayload;
    responseSchema?: DirectProviderResponseSchemaExpectation;
    modelOverride?: string;
    metadata?: Record<string, string>;
}

/**
 * Snapshot of the normalized input package in request-model form.
 */
export type DirectProviderNormalizedInputSnapshot = Pick<
    NormalizedInputPackage,
    "sourceType" | "normalizedText" | "metadata" | "contentStats"
>;
