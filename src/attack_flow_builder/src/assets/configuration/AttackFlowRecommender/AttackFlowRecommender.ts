import { BasicRecommender } from "@OpenChart/DiagramEditor";
import { CanvasView, LatchView, LineView } from "@OpenChart/DiagramView";
import { MultiSelectProperty, StringProperty, TTPTupleProperty } from "@OpenChart/DiagramModel";
import { getTechniqueNameFromLabel } from "../AttackFlowTemplates";
import type { DiagramViewEditor, ObjectRecommendation, ObjectRecommendations } from "@OpenChart/DiagramEditor";
import type { DiagramObjectView } from "@OpenChart/DiagramView";
import type { TieEngine, TiePrediction } from "tie-inference-web";

type TechniqueInfo = {
    techniqueId: string;
    technique: StringProperty;
};

const ENTERPRISE_FRAMEWORK = "ENT";
const ENTERPRISE_LABEL_PREFIX = "[ENT]";
const TIE_RECOMMENDATION_LIMIT = 5;

export class AttackFlowRecommender extends BasicRecommender {

    /**
     * The recommender's active target.
     */
    private target: DiagramObjectView | null;

    /**
     * The TIE engine.
     */
    private engine: Promise<TieEngine> | null;

    /**
     * Cached predictions by technique id.
     */
    private predictions: Map<string, Promise<TiePrediction[]>>;


    /**
     * Creates a new {@link AttackFlowRecommender}.
     */
    constructor() {
        super();
        this.target = null;
        this.engine = null;
        this.predictions = new Map();
    }

    /**
     * Starts the recommender.
     * @param editor
     *  The recommender's editor.
     * @param object
     *  The recommender's active target.
     */
    public override start(editor: DiagramViewEditor, object: DiagramObjectView) {
        super.start(editor, object);
        this.target = object;
    }

    /**
     * Stops the recommender.
     */
    public override shutdown() {
        super.shutdown();
        this.target = null;
    }

    /**
     * Returns the set of recommendations.
     * @returns
     *  A Promise that resolves with the recommendations.
     */
    public override async getRecommendations(): Promise<ObjectRecommendations> {
        const recommendations = await super.getRecommendations();
        const techniqueInfo = this.getTechniqueInfo();
        if (!techniqueInfo) {
            return recommendations;
        }

        const actionIndex = recommendations.items.findIndex(item => item.id === "action");
        if (actionIndex === -1) {
            return recommendations;
        }

        const predictionRows = await this.getPredictionRows(techniqueInfo, recommendations.items[actionIndex]);
        if (!predictionRows.length) {
            return recommendations;
        }

        const items = [...recommendations.items];
        items.splice(actionIndex + 1, 0, ...predictionRows);
        return { items };
    }

    /**
     * Gets the Enterprise ATT&CK technique that should drive TIE.
     * @returns
     *  The technique information, or null if generic recommendations should be used.
     */
    private getTechniqueInfo(): TechniqueInfo | null {
        if (!this.isEnterpriseFrameworkEnabled()) {
            return null;
        }
        if (!(this.target instanceof LatchView) || !this.target.isTarget()) {
            return null;
        }
        if (!(this.target.parent instanceof LineView)) {
            return null;
        }

        const actionObject = this.target.parent.sourceObject;
        if (actionObject?.id !== "action") {
            return null;
        }

        const ttp = actionObject.properties.get("ttp", TTPTupleProperty);
        const technique = ttp?.get("technique", StringProperty);
        if (!technique?.value) {
            return null;
        }

        const label = technique.options?.value.get(technique.value)?.toString();
        if (!label?.startsWith(ENTERPRISE_LABEL_PREFIX)) {
            return null;
        }

        return {
            techniqueId: technique.value,
            technique
        };
    }

    /**
     * Tests if the flow currently has Enterprise ATT&CK enabled.
     * @returns
     *  True if Enterprise ATT&CK is enabled, false otherwise.
     */
    private isEnterpriseFrameworkEnabled(): boolean {
        const canvas = this.getCanvas();
        const frameworks = canvas?.properties.get("ttp_frameworks", MultiSelectProperty);
        return frameworks?.values.has(ENTERPRISE_FRAMEWORK) ?? false;
    }

    /**
     * Gets the active target's canvas.
     * @returns
     *  The target's canvas, or null if it cannot be resolved.
     */
    private getCanvas(): CanvasView | null {
        let object = this.target;
        while (object?.parent) {
            object = object.parent as DiagramObjectView;
        }
        return object instanceof CanvasView ? object : null;
    }

    /**
     * Gets prediction rows for a technique.
     * @param techniqueInfo
     *  The technique information.
     * @param actionRecommendation
     *  The generic action recommendation.
     * @returns
     *  The prediction rows.
     */
    private async getPredictionRows(
        techniqueInfo: TechniqueInfo,
        actionRecommendation: ObjectRecommendation
    ): Promise<ObjectRecommendation[]> {
        const predictions = await this.getPredictions(techniqueInfo.techniqueId);
        return this.formatPredictionRows(predictions, techniqueInfo, actionRecommendation);
    }

    /**
     * Gets TIE predictions for a technique.
     * @param techniqueId
     *  The technique id.
     * @returns
     *  The TIE predictions.
     */
    private async getPredictions(techniqueId: string): Promise<TiePrediction[]> {
        if (!this.predictions.has(techniqueId)) {
            this.predictions.set(techniqueId, this.predictTechniques(techniqueId));
        }
        return this.predictions.get(techniqueId)!;
    }

    /**
     * Predicts techniques for a technique.
     * @param techniqueId
     *  The technique id.
     * @returns
     *  The TIE predictions.
     */
    private async predictTechniques(techniqueId: string): Promise<TiePrediction[]> {
        try {
            const engine = await this.getEngine();
            return await engine.predict([techniqueId]);
        } catch (error) {
            console.warn("Unable to load TIE recommendations.", error);
            return [];
        }
    }

    /**
     * Formats TIE predictions as object recommender rows.
     * @param predictions
     *  The TIE predictions.
     * @param techniqueInfo
     *  The technique information.
     * @param actionRecommendation
     *  The generic action recommendation.
     * @returns
     *  The formatted rows.
     */
    private formatPredictionRows(
        predictions: TiePrediction[],
        techniqueInfo: TechniqueInfo,
        actionRecommendation: ObjectRecommendation
    ): ObjectRecommendation[] {
        const rows: ObjectRecommendation[] = [];
        for (const prediction of predictions) {
            const label = techniqueInfo.technique.options?.value.get(prediction.id)?.toString();
            if (!label?.startsWith(ENTERPRISE_LABEL_PREFIX)) {
                continue;
            }
            const name = getTechniqueNameFromLabel(label);
            rows.push({
                id: prediction.id,
                color: actionRecommendation.color,
                name: `${prediction.id} ${name}`,
                subtitle: "Predicted action",
                isTieRecommendation: true,
                parentId: actionRecommendation.id
            });
            if (rows.length === TIE_RECOMMENDATION_LIMIT) {
                break;
            }
        }
        return rows;
    }

    /**
     * Gets the TIE engine.
     * @returns
     *  The TIE engine.
     */
    private getEngine(): Promise<TieEngine> {
        if (!this.engine) {
            this.engine = import("tie-inference-web").then(
                ({ createEngine }) => createEngine(
                    "app.trained.model.zip",
                    "app.enrichment.json",
                    false
                )
            );
        }
        return this.engine;
    }

}
