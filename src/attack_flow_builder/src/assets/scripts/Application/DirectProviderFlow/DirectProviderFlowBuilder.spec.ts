// @vitest-environment jsdom

import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DictionaryProperty, EnumProperty, MultiSelectProperty, StringProperty, TTPTupleProperty } from "@OpenChart/DiagramModel";
import { useApplicationStore } from "@/stores/ApplicationStore";
import { buildDirectProviderDiagramFile } from "./DirectProviderFlowBuilder";

vi.hoisted(() => {
    const canvasContext = new Proxy({}, {
        get: (_target, prop) => {
            if (prop === "canvas") {
                return null;
            }
            return () => undefined;
        },
        set: () => true
    });
    if (typeof HTMLCanvasElement !== "undefined") {
        Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
            value: () => canvasContext,
            configurable: true
        });
    }
    if (typeof window !== "undefined" && !window.matchMedia) {
        window.matchMedia = () => ({
            matches: false,
            media: "",
            onchange: null,
            addEventListener: () => undefined,
            removeEventListener: () => undefined,
            addListener: () => undefined,
            removeListener: () => undefined,
            dispatchEvent: () => false
        } as unknown as MediaQueryList);
    }
    return null;
});

const fontStoreMock = vi.hoisted(() => ({
    loadFont: async () => undefined,
    getFont: () => ({
        measureWidth: () => 0,
        measure: () => ({ width: 0, ascent: 0, descent: 0, height: 0 }),
        wordWrap: (text: string) => [text]
    })
}));

vi.mock("@/assets/scripts/OpenChart/Utilities/FontStore", () => ({
    GlobalFontStore: fontStoreMock
}));

vi.mock("@OpenChart/Utilities/FontStore", () => ({
    GlobalFontStore: fontStoreMock
}));

describe("DirectProviderFlowBuilder", () => {
    beforeEach(() => {
        setActivePinia(createPinia());
    });

    it("builds an editable diagram file from validated structured extraction", async () => {
        const app = useApplicationStore();
        app.settings.view.diagram.theme = "light_theme";
        const file = await buildDirectProviderDiagramFile(app, {
            schema_version: "afb-v2-intermediate",
            validation_state: "valid",
            repair_attempted: false,
            provider_invoked: true,
            attack_flow: {
                id: "attack-flow--1",
                type: "attack-flow",
                spec_version: "2.1",
                name: "Incident Flow",
                scope: "incident",
                orchestration_mode: "direct_provider",
                source_classification: "narrative_text",
                authors: ["Analyst"],
                external_references: ["https://example.com/report"]
            },
            attack_actions: [{
                id: "attack-action--1",
                type: "attack-action",
                spec_version: "2.1",
                name: "Launch process",
                description: "Spawn a process",
                confidence: 0.72,
                technique: {
                    technique_id: "T1059",
                    confidence: 0.8,
                    grounded_by: "report"
                },
                tactic: {
                    tactic_id: "execution",
                    confidence: 0.8,
                    grounded_by: "report"
                },
                asset_refs: ["attack-asset--1"],
                effect_refs: ["attack-condition--1"]
            }],
            attack_conditions: [{
                id: "attack-condition--1",
                type: "attack-condition",
                spec_version: "2.1",
                description: "If the process starts",
                value: "true",
                confidence: 0.4,
                on_true_refs: ["attack-operator--1"]
            }],
            attack_operators: [{
                id: "attack-operator--1",
                type: "attack-operator",
                spec_version: "2.1",
                operator: "AND",
                confidence: 0.55,
                effect_refs: ["attack-asset--1"]
            }],
            attack_assets: [{
                id: "attack-asset--1",
                type: "attack-asset",
                spec_version: "2.1",
                name: "Victim Host",
                description: "Endpoint",
                tags: { host: true, internal: false },
                object_ref: null,
                confidence: 0.9
            }],
            deterministic_attack_refs: [],
            deterministic_entities: [],
            deterministic_relationships: []
        });

        expect(file.canvas.properties.get("name", StringProperty)?.value).toBe("Incident Flow");
        expect(file.canvas.properties.get("author", DictionaryProperty)?.get("name", StringProperty)?.value).toBe("Analyst");
        expect(file.canvas.properties.get("external_references")?.isDefined()).toBe(true);
        expect(file.canvas.blocks).toHaveLength(4);
        expect(file.canvas.lines).toHaveLength(4);

        const action = file.canvas.blocks[0];
        expect(action.properties.get("confidence", EnumProperty)?.value).toBe("probable");
        expect(action.properties.get("ttp", TTPTupleProperty)?.toJson()).toMatchObject({
            tactic: "execution",
            technique: "T1059"
        });

        const asset = file.canvas.blocks[3];
        expect(asset.properties.get("tags", MultiSelectProperty)?.toJson()).toEqual({ host: true });

        const condition = file.canvas.blocks[1];
        const operator = file.canvas.blocks[2];
        expect(file.canvas.lines[0].source.anchor).toBe(action.anchors.get("0"));
        expect(file.canvas.lines[0].target.anchor).toBe(asset.anchors.get("180"));
        expect(file.canvas.lines[1].source.anchor).toBe(action.anchors.get("270"));
        expect(file.canvas.lines[1].target.anchor).toBe(condition.anchors.get("90"));
        expect(file.canvas.lines[2].source.anchor).toBe(condition.anchors.get("branch:True"));
        expect(file.canvas.lines[2].target.anchor).toBe(operator.anchors.get("90"));
        expect(file.canvas.lines[3].source.anchor).toBe(operator.anchors.get("0"));
        expect(file.canvas.lines[3].target.anchor).toBe(asset.anchors.get("180"));
    });

    it("creates a sequential connector chain when actions omit effect references", async () => {
        const app = useApplicationStore();
        app.settings.view.diagram.theme = "light_theme";
        const file = await buildDirectProviderDiagramFile(app, {
            schema_version: "afb-v2-intermediate",
            validation_state: "valid",
            repair_attempted: false,
            provider_invoked: true,
            attack_flow: {
                id: "attack-flow--1",
                type: "attack-flow",
                spec_version: "2.1",
                name: "Sequential Flow",
                scope: "incident",
                orchestration_mode: "direct_provider",
                source_classification: "narrative_text"
            },
            attack_actions: [
                {
                    id: "attack-action--1",
                    type: "attack-action",
                    spec_version: "2.1",
                    name: "First action",
                    description: "First",
                    confidence: 0.8
                },
                {
                    id: "attack-action--2",
                    type: "attack-action",
                    spec_version: "2.1",
                    name: "Second action",
                    description: "Second",
                    confidence: 0.8
                },
                {
                    id: "attack-action--3",
                    type: "attack-action",
                    spec_version: "2.1",
                    name: "Third action",
                    description: "Third",
                    confidence: 0.8
                }
            ],
            attack_conditions: [],
            attack_operators: [],
            attack_assets: [],
            deterministic_attack_refs: [],
            deterministic_entities: [],
            deterministic_relationships: []
        });

        expect(file.canvas.lines).toHaveLength(2);
        expect(file.canvas.lines[0].source.anchor).toBe(file.canvas.blocks[0].anchors.get("270"));
        expect(file.canvas.lines[0].target.anchor).toBe(file.canvas.blocks[1].anchors.get("90"));
        expect(file.canvas.lines[1].source.anchor).toBe(file.canvas.blocks[1].anchors.get("270"));
        expect(file.canvas.lines[1].target.anchor).toBe(file.canvas.blocks[2].anchors.get("90"));
    });
});
