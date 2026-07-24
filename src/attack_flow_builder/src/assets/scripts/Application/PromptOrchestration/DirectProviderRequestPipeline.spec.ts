import { describe, expect, it } from "vitest";
import { buildDirectProviderRequestPipeline } from "./DirectProviderRequestPipeline";

describe("DirectProviderRequestPipeline", () => {
    it("builds a provider-agnostic request from normalized input", () => {
        const request = buildDirectProviderRequestPipeline({
            normalizedInput: {
                sourceType: "text",
                normalizedText: "Alpha",
                metadata: {
                    sourceName: "Pasted Text"
                }
            },
            provider: {
                providerType: "openai_compatible",
                endpoint: "https://example.com/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            }
        });

        expect(request).toMatchObject({
            providerType: "openai_compatible",
            endpoint: "https://example.com/v1",
            apiKey: "secret",
            model: "gpt-4o-mini",
            responseFormat: "json_object",
            temperature: 0,
            metadata: {
                request_version: "v1",
                schema_name: "direct_provider_afb_intermediate",
                schema_version: "afb-v2-intermediate",
                mode: "direct_provider",
                source_type: "text",
                system_instruction_version: "v1"
            }
        });
        expect(request.prompt).toContain("SYSTEM_INSTRUCTIONS:");
        expect(request.prompt).toContain("PACKAGED_INPUT:");
    });

    it("builds a provider-agnostic request from normalized pdf input", () => {
        const request = buildDirectProviderRequestPipeline({
            normalizedInput: {
                sourceType: "pdf",
                normalizedText: "Alpha\n\nBeta",
                metadata: {
                    filename: "report.pdf",
                    sourceName: "PDF Upload",
                    pageCount: 2
                },
                contentStats: {
                    characterCount: 11,
                    wordCount: 2,
                    lineCount: 3,
                    paragraphCount: 2
                }
            },
            provider: {
                providerType: "openai_compatible",
                endpoint: "https://example.com/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            }
        });

        expect(request).toMatchObject({
            providerType: "openai_compatible",
            endpoint: "https://example.com/v1",
            apiKey: "secret",
            responseFormat: "json_object",
            temperature: 0,
            metadata: {
                schema_name: "direct_provider_afb_intermediate",
                mode: "direct_provider",
                source_type: "pdf",
                schema_version: "afb-v2-intermediate"
            }
        });
        expect(request.prompt).toContain("\"sourceType\": \"pdf\"");
        expect(request.prompt).toContain("\"filename\": \"report.pdf\"");
        expect(request.prompt).toContain("\"pageCount\": 2");
    });

    it("is deterministic for the same input", () => {
        const params = {
            normalizedInput: {
                sourceType: "text" as const,
                normalizedText: "Alpha\n\nBeta",
                metadata: {
                    sourceName: "Pasted Text"
                }
            },
            provider: {
                providerType: "openai_compatible" as const,
                endpoint: "https://example.com/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            }
        };

        const first = buildDirectProviderRequestPipeline(params);
        const second = buildDirectProviderRequestPipeline(params);

        expect(first).toEqual(second);
    });
});
