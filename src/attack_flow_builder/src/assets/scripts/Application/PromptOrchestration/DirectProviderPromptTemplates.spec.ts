import { describe, expect, it } from "vitest";
import { DIRECT_PROVIDER_OUTPUT_SCHEMA } from "./DirectProviderOutputSchema";
import {
    buildDirectProviderEmptyExtractionRepromptBundle,
    buildDirectProviderPromptTemplateBundle,
    composeDirectProviderPrompt,
    pythonCompatibleJsonStringify
} from "./DirectProviderPromptTemplates";

describe("DirectProviderPromptTemplates", () => {
    it("matches the API full-extraction prompt behavior", () => {
        const bundle = buildDirectProviderPromptTemplateBundle({
            mode: "full_extraction",
            sourceType: "narrative_text",
            normalizedText: "Observed command: whoami",
            metadata: {
                authors: ["analyst-a"],
                external_references: ["https://example.com"]
            }
        }, DIRECT_PROVIDER_OUTPUT_SCHEMA);

        expect(bundle.systemInstruction).toContain("ATT&CK v19.1");
        expect(bundle.systemInstruction).toContain("Do not omit technique for an attack-action");
        expect(bundle.systemInstruction).toContain("corresponding ATT&CK tactic");
        expect(bundle.systemInstruction).toContain("Merge contiguous substeps");
        expect(bundle.systemInstruction).toContain("multiple documented follow-on outcomes");
        expect(bundle.systemInstruction).toContain("ATT&CK technique table, appendix, or matrix");
        expect(bundle.systemInstruction).toContain("For every non-terminal action, use effect_refs");
        expect(bundle.userPrompt).toContain("\"mode\": \"full_extraction\"");
        expect(bundle.userPrompt).toContain("\"attack_version\": \"19.1\"");
        expect(bundle.userPrompt).toContain("\"structured_summary\": {}");
        expect(bundle.userPrompt).toContain("\"stix_context\": {");
        expect(bundle.userPrompt).toContain("\"prefer_attached_stix_catalog_objects\": true");
        expect(bundle.userPrompt).toContain("\"explicit_attack_refs_only\": false");
        expect(bundle.userPrompt).toContain("\"no_missing_technique_inference\": false");
        expect(bundle.userPrompt).toContain("\"allow_actions_without_techniques\": false");
        expect(bundle.userPrompt).toContain("\"require_tactic_for_attack_technique\": true");
        expect(bundle.userPrompt).toContain("\"consolidate_contiguous_same_technique_substeps\": true");
        expect(bundle.userPrompt).toContain("\"default_entities_to_supported_stix_types\": true");
        expect(bundle.userPrompt).toContain("\"use_attack_technique_table_when_present\": true");
        expect(bundle.userPrompt).toContain("\"use_or_operator_for_documented_alternatives\": true");
        expect(bundle.userPrompt).toContain("\"use_operators_for_multiple_documented_outcomes\": true");
        expect(bundle.userPrompt).toContain("\"model_multiple_documented_outcomes_with_operators\": true");
        expect(bundle.userPrompt).toContain("\"next_step_field\": \"attack_actions[*].effect_refs\"");
        expect(bundle.userPrompt).toContain("\"windows_registry_key\"");
    });

    it("matches the API enrichment prompt behavior", () => {
        const bundle = buildDirectProviderPromptTemplateBundle({
            mode: "enrichment",
            sourceType: "stix_structured",
            normalizedText: "Narrative from report",
            structuredSummary: { bundle_metadata: { id: "bundle--1" } },
            deterministicAttackRefs: [{ technique_id: "T1059" }],
            deterministicEntities: [{ object_id: "malware--1" }],
            deterministicRelationships: [{ relationship_id: "relationship--1" }],
            provenance: { narrative_source_object_ids: ["report--1"] }
        }, DIRECT_PROVIDER_OUTPUT_SCHEMA);

        expect(bundle.userPrompt).toContain("\"mode\": \"enrichment\"");
        expect(bundle.userPrompt).toContain("\"deterministic_findings\": {");
        expect(bundle.userPrompt).toContain("\"preserve_deterministic_findings\": true");
        expect(bundle.userPrompt).toContain("\"do_not_drop_or_rewrite_deterministic_attack_refs\": true");
        expect(bundle.userPrompt).toContain("\"allow_actions_without_techniques\": false");
        expect(bundle.userPrompt).toContain("\"require_tactic_for_attack_technique\": true");
        expect(bundle.userPrompt).toContain("\"use_operators_for_multiple_documented_outcomes\": true");
        expect(bundle.userPrompt).not.toContain("\"prefer_attached_stix_catalog_objects\"");
    });

    it("builds the API empty-extraction reprompt", () => {
        const bundle = buildDirectProviderEmptyExtractionRepromptBundle({
            mode: "full_extraction",
            sourceType: "narrative_text",
            normalizedText: "Execution phase\nC2 communication"
        }, DIRECT_PROVIDER_OUTPUT_SCHEMA, ["C2 communication"]);

        expect(bundle.userPrompt).toContain("extract every clearly supported attack action");
        expect(bundle.userPrompt).toContain("Strong source cues to focus on:\n- C2 communication");
        expect(bundle.userPrompt).toContain("PACKAGED_INPUT:");
    });

    it("sorts keys and escapes non-ASCII text like Python JSON rendering", () => {
        expect(pythonCompatibleJsonStringify({ z: "café", a: { d: 2, b: 1 } })).toBe(
            "{\n  \"a\": {\n    \"b\": 1,\n    \"d\": 2\n  },\n  \"z\": \"caf\\u00e9\"\n}"
        );
    });

    it("composes the API provider prompt envelope", () => {
        const prompt = composeDirectProviderPrompt(buildDirectProviderPromptTemplateBundle({
            mode: "full_extraction",
            sourceType: "narrative_text",
            normalizedText: "Alpha"
        }, DIRECT_PROVIDER_OUTPUT_SCHEMA));

        expect(prompt).toContain("SYSTEM_INSTRUCTION:\n");
        expect(prompt).toContain("\n\n\nUSER_PROMPT:\n");
        expect(prompt).toContain("\nOUTPUT_SCHEMA:\n");
        expect(prompt.endsWith("\n")).toBe(true);
    });
});
