import { describe, expect, it } from "vitest";
import {
    buildDirectProviderPromptConstraints,
    buildDirectProviderSystemInstructionBundle,
    buildDirectProviderSystemInstructionModel,
    buildDirectProviderSystemInstructionText,
    DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT
} from "./DirectProviderSystemInstructionBuilder";

describe("DirectProviderSystemInstructionBuilder", () => {
    it("builds deterministic system instruction text", () => {
        expect(buildDirectProviderSystemInstructionText()).toBe(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT);
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Do not infer ATT&CK tactics or techniques.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Only preserve ATT&CK references that are explicit in the source.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Attack-action steps are allowed even when no technique is available.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Attack-action descriptions must be verbatim source excerpts only.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Do not paraphrase, summarize, rewrite, or otherwise change source text meaning.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Use only AND or OR for attack-operator values.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Use only true or false for attack-condition values.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("pinned AFB-compatible extraction output shape");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Set schema_version exactly to afb-v2-intermediate.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Do not use version or schemaName fields in the output.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Every attack-action, attack-condition, attack-operator, and attack-asset item must include spec_version = \"2.1\".");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Every confidence value must be a decimal number between 0 and 1, never a percentage.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Every attack-action must include id, type, spec_version, name, description, and confidence.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Every attack-action, attack-condition, attack-operator, and attack-asset must include evidence with source and excerpt.");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Do not invent branching or inferred control flow.");
    });

    it("builds deterministic instruction models and bundle metadata", () => {
        expect(buildDirectProviderPromptConstraints()).toEqual({
            noAttackInference: true,
            explicitAttackRefsOnly: true,
            allowStepsWithoutTechniques: true,
            descriptionsMustBeVerbatimExcerpts: true,
            onlyAndOrOperators: true,
            onlyTrueFalseConditions: true,
            noInferredBranching: true,
            outputMustFitPinnedIntermediateShape: true
        });

        expect(buildDirectProviderSystemInstructionModel()).toEqual({
            version: "v1",
            constraints: {
                noAttackInference: true,
                explicitAttackRefsOnly: true,
                allowStepsWithoutTechniques: true,
                descriptionsMustBeVerbatimExcerpts: true,
                onlyAndOrOperators: true,
                onlyTrueFalseConditions: true,
                noInferredBranching: true,
                outputMustFitPinnedIntermediateShape: true
            }
        });

        expect(buildDirectProviderSystemInstructionBundle()).toMatchObject({
            version: "v1",
            schemaName: "direct_provider_afb_intermediate",
            text: DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT,
            allowedOperatorValues: ["AND", "OR"],
            allowedConditionValues: ["true", "false"]
        });
    });
});
