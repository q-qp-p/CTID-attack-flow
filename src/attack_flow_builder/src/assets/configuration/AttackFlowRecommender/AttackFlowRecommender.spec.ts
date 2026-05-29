import { beforeEach, describe, expect, it, vi } from "vitest";
import { AttackFlowRecommender } from "./AttackFlowRecommender";
import { SpawnAction } from "@OpenChart/DiagramEditor/Commands/index.commands";
import { ThemeLoader } from "@OpenChart/ThemeLoader";
import { AnchorPosition, BlockView, DiagramObjectViewFactory, DiagramViewFile, LineView, type LatchView } from "@OpenChart/DiagramView";
import { MultiSelectProperty } from "@OpenChart/DiagramModel";
import { AttackFlow, AttackFlowObjects, BaseObjects } from "@/assets/configuration/AttackFlowTemplates";
import { LightTheme } from "@/assets/configuration/AttackFlowThemes/LightTheme";
import type { DiagramViewEditor } from "@OpenChart/DiagramEditor";

const tie = vi.hoisted(() => ({
    createEngine: vi.fn(),
    predict: vi.fn()
}));

vi.mock("tie-inference-web", () => ({
    createEngine: tie.createEngine
}));

async function createAttackFlowFile(): Promise<DiagramViewFile> {
    const theme = await ThemeLoader.load(LightTheme);
    const factory = new DiagramObjectViewFactory({
        id: "attack_flow_v2",
        canvas: AttackFlow,
        templates: [
            ...AttackFlowObjects,
            ...BaseObjects
        ]
    }, theme);
    return new DiagramViewFile(factory);
}

function createDanglingTargetLatch(file: DiagramViewFile, techniqueId: string): LatchView {
    const spawn = new SpawnAction(file, techniqueId, 10, 10);
    spawn.execute();

    const action = spawn.object as BlockView;
    const actionAnchor = action.anchors.get(AnchorPosition.D0)!;
    const line = file.factory.createNewDiagramObject("dynamic_line", LineView);
    file.canvas.addObject(line);
    line.source.link(actionAnchor);

    return line.target;
}

function startRecommender(file: DiagramViewFile, latch: LatchView): AttackFlowRecommender {
    const recommender = new AttackFlowRecommender();
    recommender.start({ file } as DiagramViewEditor, latch);
    return recommender;
}

function genericRecommendationIds(recommenderIds: string[]): string[] {
    return recommenderIds.filter(id => !id.startsWith("T"));
}

describe("AttackFlowRecommender", () => {
    beforeEach(() => {
        tie.createEngine.mockReset();
        tie.predict.mockReset();
        tie.createEngine.mockResolvedValue({
            warmup: vi.fn(),
            predict: tie.predict
        });
        tie.predict.mockResolvedValue([
            { id: "T1059.001", score: 0.9 },
            { id: "AML.T0000", score: 0.8 },
            { id: "T1059.003", score: 0.7 },
            { id: "T1055", score: 0.6 },
            { id: "T1110", score: 0.5 },
            { id: "T1027", score: 0.4 },
            { id: "T1003", score: 0.3 }
        ]);
    });

    it("adds top Enterprise TIE recommendations under the generic action recommendation", async () => {
        const file = await createAttackFlowFile();
        const latch = createDanglingTargetLatch(file, "T1059");
        const recommender = startRecommender(file, latch);

        const recommendations = await recommender.getRecommendations();
        const actionIndex = recommendations.items.findIndex(item => item.id === "action");
        const tieRecommendations = recommendations.items.filter(item => item.isTieRecommendation);

        expect(actionIndex).toBeGreaterThanOrEqual(0);
        expect(tie.createEngine).toHaveBeenCalledWith(
            "app.trained.model.zip",
            "app.enrichment.json",
            false
        );
        expect(tie.predict).toHaveBeenCalledWith(["T1059"]);
        expect(tieRecommendations.map(item => item.id)).toEqual([
            "T1059.001",
            "T1059.003",
            "T1055",
            "T1110",
            "T1027"
        ]);
        expect(recommendations.items.slice(actionIndex + 1, actionIndex + 6)).toEqual(tieRecommendations);
        expect(tieRecommendations[0]).toMatchObject({
            id: "T1059.001",
            name: "T1059.001 PowerShell",
            subtitle: "Predicted action",
            parentId: "action",
            isTieRecommendation: true
        });
    });

    it("falls back to generic recommendations for non-Enterprise techniques", async () => {
        const file = await createAttackFlowFile();
        const latch = createDanglingTargetLatch(file, "AML.T0000");
        const recommender = startRecommender(file, latch);

        const recommendations = await recommender.getRecommendations();

        expect(recommendations.items.some(item => item.isTieRecommendation)).toBe(false);
        expect(genericRecommendationIds(recommendations.items.map(item => item.id))).toEqual([
            "action",
            "mitigation",
            "asset",
            "condition",
            "OR_operator",
            "AND_operator"
        ]);
        expect(tie.createEngine).not.toHaveBeenCalled();
    });

    it("falls back to generic recommendations when Enterprise ATT&CK is disabled", async () => {
        const file = await createAttackFlowFile();
        const frameworks = file.canvas.properties.get("ttp_frameworks", MultiSelectProperty)!;
        frameworks.setSelections(["MOB", "ICS"]);
        const latch = createDanglingTargetLatch(file, "T1059");
        const recommender = startRecommender(file, latch);

        const recommendations = await recommender.getRecommendations();

        expect(recommendations.items.some(item => item.isTieRecommendation)).toBe(false);
        expect(genericRecommendationIds(recommendations.items.map(item => item.id))).toEqual([
            "action",
            "mitigation",
            "asset",
            "condition",
            "OR_operator",
            "AND_operator"
        ]);
        expect(tie.createEngine).not.toHaveBeenCalled();
    });
});
