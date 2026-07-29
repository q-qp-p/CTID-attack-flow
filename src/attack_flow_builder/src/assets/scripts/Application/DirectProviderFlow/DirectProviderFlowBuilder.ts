import Configuration from "@/assets/configuration/app.configuration";
import { Branch, DiagramObjectViewFactory, DiagramViewFile } from "@OpenChart/DiagramView";
import {
    DictionaryProperty,
    EnumProperty,
    ListProperty,
    MultiSelectProperty,
    StringProperty,
    TTPTupleProperty
} from "@OpenChart/DiagramModel";
import type { ApplicationStore } from "@/stores/ApplicationStore";
import type { DiagramObjectView } from "@OpenChart/DiagramView";
import type {
    StructuredExtractionAttackActionNode,
    StructuredExtractionResult
} from "../StructuredExtraction";

interface AnchorLike {
    link(anchor: AnchorLike): void;
}

interface NodeBlock extends DiagramObjectView {
    anchors: Map<string, AnchorLike>;
}

interface DynamicLineBlock extends DiagramObjectView {
    source: AnchorLike;
    target: AnchorLike;
}

type PropertyValue = unknown;

function getProperty(object: DiagramObjectView, key: string, ctor: unknown): PropertyValue | undefined {
    return (object.properties as unknown as {
        get(key: string, ctor: unknown): PropertyValue | undefined;
    }).get(key, ctor);
}

const confidenceBuckets = [
    [0, "speculative"],
    [10, "very-doubtful"],
    [30, "doubtful"],
    [50, "even-odds"],
    [70, "probable"],
    [90, "very-probable"],
    [100, "certain"]
] as const;

function toTrimmedString(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function confidenceToEditorKey(confidence: number | undefined): string | undefined {
    if (typeof confidence !== "number" || Number.isNaN(confidence)) {
        return undefined;
    }

    const scaled = confidence <= 1 ? confidence * 100 : confidence;
    let bestKey: string | undefined;
    let bestDistance = Number.POSITIVE_INFINITY;
    for (const [bucket, key] of confidenceBuckets) {
        const distance = Math.abs(scaled - bucket);
        if (distance < bestDistance) {
            bestDistance = distance;
            bestKey = key;
        }
    }

    return bestKey;
}

function setStringProperty(object: DiagramObjectView, key: string, value: unknown): void {
    const prop = getProperty(object, key, StringProperty) as StringProperty | undefined;
    const text = toTrimmedString(value);
    if (prop && text) {
        prop.setValue(text);
    }
}

function setEnumProperty(object: DiagramObjectView, key: string, value: string | undefined): void {
    const prop = getProperty(object, key, EnumProperty) as EnumProperty | undefined;
    if (prop && value) {
        prop.setValue(value);
    }
}

function setMultiSelectProperty(object: DiagramObjectView, key: string, values: Record<string, boolean> | null | undefined): void {
    const prop = getProperty(object, key, MultiSelectProperty) as MultiSelectProperty | undefined;
    if (!prop || !values) {
        return;
    }

    prop.setSelections(Object.entries(values).filter(([, selected]) => selected).map(([id]) => id));
}

function setConfidenceProperty(object: DiagramObjectView, confidence: number | undefined): void {
    setEnumProperty(object, "confidence", confidenceToEditorKey(confidence));
}

function setTtpProperty(object: DiagramObjectView, action: StructuredExtractionAttackActionNode): void {
    const techniqueId = toTrimmedString(action.technique?.technique_id ?? action.technique?.technique_ref);
    const tacticId = toTrimmedString(action.tactic?.tactic_id ?? action.tactic?.tactic_ref);
    const prop = getProperty(object, "ttp", TTPTupleProperty) as TTPTupleProperty | undefined;
    if (!prop || (!techniqueId && !tacticId)) {
        return;
    }

    const values: [string, string][] = [];
    if (tacticId) {
        values.push(["tactic", tacticId]);
    }
    if (techniqueId) {
        values.push(["technique", techniqueId]);
    }
    prop.setValue(values);
}

function setAuthor(canvas: DiagramObjectView, authors: string[] | undefined): void {
    const author = getProperty(canvas, "author", DictionaryProperty) as DictionaryProperty | undefined;
    const name = toTrimmedString(authors?.[0]) ?? "AI Generated";
    author?.get("name", StringProperty)?.setValue(name);
}

function setExternalReferences(canvas: DiagramObjectView, refs: string[] | undefined): void {
    const list = getProperty(canvas, "external_references", ListProperty) as ListProperty | undefined;
    if (!list || !refs?.length) {
        return;
    }

    for (const ref of refs) {
        const url = toTrimmedString(ref);
        if (!url) {
            continue;
        }

        const item = list.createListItem();
        if (item instanceof DictionaryProperty) {
            item.get("source_name", StringProperty)?.setValue(url);
            item.get("url", StringProperty)?.setValue(url);
        }
        list.addProperty(item);
    }
}

function createBlock(file: DiagramViewFile, template: string): NodeBlock {
    const block = file.factory.createNewDiagramObject(template) as unknown as NodeBlock;
    file.canvas.addObject(block);
    return block;
}

function getAnchor(block: NodeBlock, key: string): AnchorLike {
    const anchor = block.anchors.get(key);
    if (!anchor) {
        throw new Error(`Block '${block.id}' is missing anchor '${key}'.`);
    }
    return anchor;
}

function connect(
    file: DiagramViewFile,
    source: NodeBlock,
    target: NodeBlock,
    sourceAnchorKey: string,
    targetAnchorKey: string
): void {
    const line = file.factory.createNewDiagramObject("dynamic_line") as DynamicLineBlock;
    line.source.link(getAnchor(source, sourceAnchorKey));
    line.target.link(getAnchor(target, targetAnchorKey));
    file.canvas.addObject(line);
}

/**
 * Builds an editable Attack Flow diagram from validated structured extraction.
 * @param context
 *  The application context.
 * @param extraction
 *  The validated structured extraction payload.
 * @returns
 *  The generated diagram file.
 */
export async function buildDirectProviderDiagramFile(
    context: ApplicationStore,
    extraction: StructuredExtractionResult
): Promise<DiagramViewFile> {
    const theme = await context.themeRegistry.getTheme(context.settings.view.diagram.theme);
    const factory = new DiagramObjectViewFactory(Configuration.schema, theme);
    const file = new DiagramViewFile(factory);
    const nodeMap = new Map<string, NodeBlock>();
    const connectionKeys = new Set<string>();

    const flow = extraction.attack_flow;
    setStringProperty(file.canvas, "name", flow.name);
    setStringProperty(file.canvas, "description", flow.description);
    setEnumProperty(file.canvas, "scope", flow.scope);
    setAuthor(file.canvas, flow.authors);
    setExternalReferences(file.canvas, flow.external_references);

    for (const action of extraction.attack_actions ?? []) {
        const block = createBlock(file, "action");
        nodeMap.set(action.id.trim(), block);
        setStringProperty(block, "name", action.name);
        setStringProperty(block, "description", action.description);
        setConfidenceProperty(block, action.confidence);
        setTtpProperty(block, action);
    }

    for (const condition of extraction.attack_conditions ?? []) {
        const block = createBlock(file, "condition");
        nodeMap.set(condition.id.trim(), block);
        setStringProperty(block, "description", condition.description);
    }

    for (const operator of extraction.attack_operators ?? []) {
        const block = createBlock(file, `${operator.operator}_operator`);
        nodeMap.set(operator.id.trim(), block);
    }

    for (const asset of extraction.attack_assets ?? []) {
        const block = createBlock(file, "asset");
        nodeMap.set(asset.id.trim(), block);
        setStringProperty(block, "name", asset.name);
        setStringProperty(block, "description", asset.description);
        setMultiSelectProperty(block, "tags", asset.tags);
    }

    const connectNodes = (
        sourceId: string,
        targetId: string,
        sourceAnchorKey: string,
        targetAnchorKey: string
    ): void => {
        const normalizedSourceId = sourceId.trim();
        const normalizedTargetId = targetId.trim();
        const source = nodeMap.get(normalizedSourceId);
        const target = nodeMap.get(normalizedTargetId);
        const connectionKey = `${normalizedSourceId}\u0000${normalizedTargetId}\u0000${sourceAnchorKey}\u0000${targetAnchorKey}`;
        if (!source || !target || connectionKeys.has(connectionKey)) {
            return;
        }

        connect(file, source, target, sourceAnchorKey, targetAnchorKey);
        connectionKeys.add(connectionKey);
    };

    for (const action of extraction.attack_actions ?? []) {
        for (const targetId of action.asset_refs ?? []) {
            connectNodes(action.id, targetId, "0", "180");
        }

        for (const targetId of action.effect_refs ?? []) {
            connectNodes(action.id, targetId, "270", "90");
        }
    }

    for (const condition of extraction.attack_conditions ?? []) {
        for (const targetId of condition.on_true_refs ?? []) {
            connectNodes(condition.id, targetId, Branch("True"), "90");
        }

        for (const targetId of condition.on_false_refs ?? []) {
            connectNodes(condition.id, targetId, Branch("False"), "90");
        }
    }

    for (const operator of extraction.attack_operators ?? []) {
        for (const targetId of operator.effect_refs ?? []) {
            connectNodes(operator.id, targetId, "0", "180");
        }
    }

    for (const asset of extraction.attack_assets ?? []) {
        const targetId = toTrimmedString(asset.object_ref ?? undefined);
        if (targetId) {
            connectNodes(asset.id, targetId, "0", "180");
        }
    }

    const actions = extraction.attack_actions ?? [];
    for (let index = 1; index < actions.length; index += 1) {
        connectNodes(actions[index - 1].id, actions[index].id, "270", "90");
    }

    return file;
}
