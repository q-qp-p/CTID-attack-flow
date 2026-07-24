import type { RuntimeProviderConfig } from "../Configuration";
import type { StructuredGenerationRequest } from "../Providers";
import { STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION } from "../StructuredExtraction/StructuredExtractionContracts";
import {
    DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME
} from "./DirectProviderAfbIntermediateShape";
import {
    DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
    type DirectProviderStructuredGenerationRequestModel
} from "./DirectProviderRequestModels";
import { buildDirectProviderSystemInstructionText } from "./DirectProviderSystemInstructionBuilder";

export const DIRECT_PROVIDER_REQUEST_TEMPERATURE = 0 as const;
export const DIRECT_PROVIDER_REQUEST_TIMEOUT_SECONDS = 300 as const;

export interface DirectProviderStructuredGenerationRequestBuilderParams {
    provider: Pick<RuntimeProviderConfig, "providerType" | "endpoint" | "apiKey" | "model" | "useAzure" | "azureApiVersion" | "extraHeaders">;
    request: DirectProviderStructuredGenerationRequestModel;
    providerId?: string;
    timeoutSeconds?: number;
    temperature?: number;
    maxOutputTokens?: number;
}

/**
 * Builds the provider-agnostic structured generation request used by AFA-95.
 * The request carries normalized input, deterministic instructions, and the
 * pinned structured extraction output shape, but does not invoke any provider.
 */
export function buildDirectProviderStructuredGenerationRequest(
    params: DirectProviderStructuredGenerationRequestBuilderParams
): StructuredGenerationRequest {
    const requestModel = params.request;
    const targetShape = buildDirectProviderAfbIntermediateOutputShape();
    const model = requestModel.modelOverride?.trim() || params.provider.model.trim();

    return {
        providerId: params.providerId,
        providerType: params.provider.providerType,
        endpoint: params.provider.endpoint.trim(),
        apiKey: params.provider.apiKey,
        model,
        useAzure: params.provider.useAzure,
        azureApiVersion: params.provider.azureApiVersion,
        prompt: buildDirectProviderStructuredPrompt({
            requestModel,
            systemInstructionText: buildDirectProviderSystemInstructionText(),
            inputPayload: requestModel.input,
            targetShape
        }),
        responseFormat: requestModel.responseSchema?.format ?? "json_object",
        temperature: params.temperature ?? DIRECT_PROVIDER_REQUEST_TEMPERATURE,
        maxOutputTokens: params.maxOutputTokens,
        timeoutSeconds: params.timeoutSeconds ?? DIRECT_PROVIDER_REQUEST_TIMEOUT_SECONDS,
        extraHeaders: params.provider.extraHeaders,
        metadata: {
            ...requestModel.metadata,
            request_version: DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
            schema_name: requestModel.responseSchema?.schemaName ?? DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME,
            schema_version: STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION,
            mode: requestModel.mode,
            source_type: requestModel.sourceType,
            system_instruction_version: requestModel.systemInstructions.version
        }
    };
}

function buildDirectProviderStructuredPrompt(params: {
    requestModel: DirectProviderStructuredGenerationRequestModel;
    systemInstructionText: string;
    inputPayload: DirectProviderStructuredGenerationRequestModel["input"];
    targetShape: DirectProviderStructuredExtractionPromptShape;
}): string {
    return [
        "SYSTEM_INSTRUCTIONS:",
        params.systemInstructionText,
        "",
        "TARGET_OUTPUT_SHAPE:",
        stableJsonStringify(params.targetShape),
        "",
        "PACKAGED_INPUT:",
        stableJsonStringify({
            version: params.requestModel.version,
            mode: params.requestModel.mode,
            sourceType: params.requestModel.sourceType,
            input: params.inputPayload
        })
    ].join("\n");
}

/**
 * Builds the structured extraction output shape template referenced by the
 * request prompt.
 */
function buildDirectProviderAfbIntermediateOutputShape(): DirectProviderStructuredExtractionPromptShape {
    return {
        schema_version: STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION,
        validation_state: "valid",
        repair_attempted: false,
        provider_invoked: true,
        provider_id: null,
        model: null,
        attack_flow: {
            id: "attack-flow--generated",
            type: "attack-flow",
            spec_version: "2.1",
            name: "Generated Attack Flow",
            scope: "incident",
            orchestration_mode: "direct_provider",
            source_classification: "narrative_text"
        },
        attack_actions: [],
        attack_conditions: [],
        attack_operators: [],
        attack_assets: [],
        deterministic_attack_refs: [],
        deterministic_entities: [],
        deterministic_relationships: []
    };
}

interface DirectProviderStructuredExtractionPromptShape {
    schema_version: typeof STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION;
    validation_state: "valid";
    repair_attempted: false;
    provider_invoked: true;
    provider_id: null;
    model: null;
    attack_flow: {
        id: string;
        type: "attack-flow";
        spec_version: "2.1";
        name: string;
        scope: string;
        orchestration_mode: string;
        source_classification: string;
    };
    attack_actions: [];
    attack_conditions: [];
    attack_operators: [];
    attack_assets: [];
    deterministic_attack_refs: [];
    deterministic_entities: [];
    deterministic_relationships: [];
}

function stableJsonStringify(value: unknown): string {
    return JSON.stringify(value, null, 2);
}
