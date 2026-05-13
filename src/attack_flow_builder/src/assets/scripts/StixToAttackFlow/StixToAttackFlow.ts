import { StixToTemplate } from "./StixToTemplate";
import { populateProperties } from "./PopulateBlockProperties";
import { GraphEdge, GraphNode } from "../SegmentLayoutEngine";
import { DiagramObjectSerializer } from "@OpenChart/DiagramModel";
import { resolveEmbeddedRelationships } from "./ResolveEmbeddedRelationships";
import { Canvas, Block, DiagramObject, Line } from "../OpenChart/DiagramModel/DiagramObject";
import type { Constructor } from "@OpenChart/Utilities";
import type { StixBundle, StixObject, StixObjectType } from "./StixTypes";
import type { Anchor, DiagramModelExport, DiagramObjectFactory } from "@OpenChart/DiagramModel";
import { AnchorPosition } from "../OpenChart/DiagramView";

export class StixToAttackFlowConverter {

    /**
     * The diagram factory to use.
     */
    private factory: DiagramObjectFactory;


    /**
     * Creates a new {@link StixToAttackFlowConverter}.
     * @remarks
     *  `factory` MUST be configured with the Attack Flow schema.
     * @param factory
     *  The diagram factory to use.
     */
    constructor(factory: DiagramObjectFactory) {
        this.factory = factory;
    }


    /**
     * Converts a STIX bundle to a {@link DiagramViewExport}.
     * @param bundle
     *  The STIX bundle to convert.
     * @returns
     *  The converted Attack Flow diagram.
     */
    public convert(stix: StixBundle): DiagramModelExport {
        // Create canvas
        const canvas = this.factory.createNewDiagramObject(this.factory.canvas, Canvas);
        // Populate root (canvas) properties from the STIX attack-flow and its referenced author
        this.populateRootFromBundle(stix, canvas);
        // Create graph of diagram objects from STIX
        const [nodes, edges, nodes_to_stix] = this.parseStixGraph(stix);
        // Mirror graph structure onto nodes
        this.mirrorConnections(nodes, nodes_to_stix);

        // Add objects to canvas
        for (const o of [...nodes, ...edges]) {
            canvas.addObject(o.object);
        }
        // Prepare export
        return {
            schema  : this.factory.id,
            objects : DiagramObjectSerializer.exportObjects([canvas])
        };
    }


    ////////////////////////////////////////////////////////////////////////////
    //  1. Graph Construction  /////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////


    /**
     * Converts a STIX bundle to an abstract graph of diagram {@link Block}s and
     * {@link Lines}.
     * @param bundle
     *  The STIX bundle.
     * @returns
     *  The graph's nodes and edges, as well as a map from nodes to stix objects.
     */
    private parseStixGraph(bundle: StixBundle): [GraphNode[], GraphEdge[], Map<string, StixObject>] {
        // Generate node map
        const nodes = new Map<string, GraphNode>();
        const edges = [];
        const graph_nodes_to_stix_objects = new Map<string, StixObject>();
        for (const obj of bundle.objects) {
            switch (obj.type) {
                case "relationship":
                case "sighting":
                    continue;
                default:
                    const object = this.translateStix(obj, Block);
                    if (object) {
                        nodes.set(obj.id, new GraphNode(object));
                    }
            }
        }
        // Generate relationship edges
        for (const rel of bundle.objects) {
            switch (rel.type) {
                case "relationship":
                    const object = this.translateStix(rel, Line);
                    if (object) {
                        const edge = new GraphEdge(object);
                        nodes.get(rel.source_ref)?.addOutEdge(edge);
                        nodes.get(rel.target_ref)?.addInEdge(edge);
                        edges.push(edge);
                    }
                case "sighting":
                default:
                    continue;
            }
        }
        // Generate embedded relationship edges
        for (const srcObj of bundle.objects) {
            const srcBlock = nodes.get(srcObj.id);
            if (srcBlock) {
                graph_nodes_to_stix_objects.set(srcBlock.id, srcObj);
            }

            // Skip relationships
            switch (srcObj.type as StixObjectType) {
                case "relationship":
                case "sighting":
                case "attack-flow":
                case "extension-definition":
                case "language-content":
                case "marking-definition":
                    continue;
            }
            // Process objects
            const objectIds = resolveEmbeddedRelationships(srcObj);
            for (const dstObj of objectIds) {
                if (dstObj == srcObj.id) {
                    // Skip relationships from nodes to themselves.
                    continue;
                }
                const line = this.factory.createNewDiagramObject("dynamic_line", Line);
                const edge = new GraphEdge(line);
                nodes.get(srcObj.id)?.addOutEdge(edge);
                nodes.get(dstObj)?.addInEdge(edge);
                edges.push(edge);
            }
        }



        return [[...nodes.values()], edges, graph_nodes_to_stix_objects];
    }

    /**
     * Translates a {@link StixObject} to a {@link DiagramObject}.
     * @param stix
     *  The {@link StixObject}.
     * @param type
     *  The expected {@link DiagramObject} sub-type.
     *  (Default: `DiagramObject`)
     * @returns
     *  The translate {@link DiagramObject}.
     */
    private translateStix<T extends DiagramObject>(stix: StixObject, type?: Constructor<T>): T | null {
        // Resolve template
        let template = StixToTemplate[stix.type as keyof typeof StixToTemplate];
        if (stix.type === "attack-operator") {
            if (stix.operator == "AND") {
                template = "AND_operator";
            } else if (stix.operator == "OR") {
                template = "OR_operator";
            } else {
                return null;
            }
        }
        if (template === null) {
            return null;
        }
        // Create object
        const object = this.factory.createNewDiagramObject(template, type);
        // Set properties
        populateProperties(stix, object.properties);
        // Return
        return object;
    }

    /**
     * Populate the root canvas properties from a STIX bundle by reading the attack-flow SDO
     * and its referenced author identity.
     * @param bundle The STIX bundle
     * @param canvas The canvas object whose properties should be populated
     */
    private populateRootFromBundle(bundle: StixBundle, canvas: Canvas): void {
        // Find the attack-flow SDO in the bundle
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const flow = bundle.objects.find((o: any) => o && o.type === "attack-flow") as any | undefined;
        if (!flow) {
            return; // nothing to populate; keep defaults
        }

        // Build a plain object that matches the canvas schema keys
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const root: any = { type: "attack-flow" };

        const keys = [
            "name",
            "description",
            "scope",
            "classification",
            "ttp_frameworks",
            "external_references",
            "created"
        ];
        for (const k of keys) {
            if (flow[k] !== undefined) {
                root[k] = flow[k];
            }
        }

        // Resolve author from created_by_ref (identity SDO)
        if (flow.created_by_ref) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const author = bundle.objects.find((o: any) => o && o.id === flow.created_by_ref && o.type === "identity") as any | undefined;
            if (author) {
                root.author = {
                    name: author.name,
                    identity_class: author.identity_class ?? "unknown",
                    contact_information: author.contact_information
                };
            }
        }

        // Populate onto the canvas using the existing property population utility
        populateProperties(root as unknown as StixObject, canvas.properties);
    }


    ////////////////////////////////////////////////////////////////////////////
    //  2. Mirror Connections  /////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////


    /**
     * Mirrors a graph's structure onto the underlying {@link DiagramObject}s.
     * @param nodes
     *  The graph's nodes.
     * @param nodes_to_stix
     * A map of graph nodes to their STIX objects.
     */
    private mirrorConnections(nodes: GraphNode[], nodes_to_stix: Map<string, StixObject>) {
        const visitedEdges = new Set();
        const unvisitedNodes = new Map(nodes.map(o => [o.id, o]));
        while (unvisitedNodes.size) {
            // Select node with smallest in-degree
            const root = [...unvisitedNodes.values()].reduce(
                (a, b) => b.inDegree < a.inDegree ? b : a
            );
            // Traverse graph
            const queue = [root];
            unvisitedNodes.delete(root.id);
            while (queue.length) {
                const node = queue.shift()!;
                // Traverse forward
                for (const edge of node.next) {
                    if (!edge.target || visitedEdges.has(edge.id)) {
                        continue;
                    }
                    visitedEdges.add(edge.id);
                    // Link nodes
                    this.connectBlocks(
                        node.object,
                        edge.target.object,
                        edge.object,
                        nodes_to_stix.get(node.id),
                        nodes_to_stix.get(edge.target.id)
                    );
                    // Traverse
                    if (unvisitedNodes.has(edge.target.id)) {
                        unvisitedNodes.delete(edge.target.id);
                        queue.push(edge.target);
                    }
                }
                // Traverse backward
                for (const edge of node.prev) {
                    if (!edge.source || visitedEdges.has(edge.id)) {
                        continue;
                    }
                    visitedEdges.add(edge.id);
                    // Link nodes
                    this.connectBlocks(
                        edge.source.object,
                        node.object,
                        edge.object,
                        nodes_to_stix.get(edge.source.id),
                        nodes_to_stix.get(node.id)
                    );
                    if (unvisitedNodes.has(edge.source.id)) {
                        // Traverse
                        unvisitedNodes.delete(edge.source.id);
                        queue.push(edge.source);
                    }

                }
            }
        }
    }

    /**
     * Get an available anchor from a side of a block if possible. If no anchors are available,
     * the least-overlapped one will be chosen. A priority between middle and neighboring anchors
     * is established if all else fails.
     *
     * Note: Asking for available anchors on the southern side of a condition block will throw an error.
     * @param block The block to find available anchors on.
     * @param side The side to look on.
     * @returns an anchor
     */
    private getAvailableAnchor(block: Block, side: "n" | "s" | "e" | "w"): Anchor {
        let result: Anchor | null = null;

        // Map anchor key to number of latches.
        const latches_per_anchor : { [K in AnchorPosition]?: number } = {};

        for (const [anchor_key, anchor] of block.anchors.entries()) {
            latches_per_anchor[anchor_key as AnchorPosition] = anchor.latches.length;
        }

        /**
         * Get the best anchor key based on which is most empty. To evaluate ties, the list is assumed
         * to be in priority order.
         * @param side_anchor_keys list of anchor keys to evaluate
         * @returns the winning anchor key
         */
        function evaluate_anchors(side_anchor_keys: AnchorPosition[]): AnchorPosition {
            let best_anchor_key : AnchorPosition;

            const counts : number[] = side_anchor_keys.map(k => latches_per_anchor[k] as number);

            if (counts[0] <= counts[1] && counts[0] <= counts[2]) {
                best_anchor_key = side_anchor_keys[0];
            } else if (counts[1] <= counts[2]) {
                best_anchor_key = side_anchor_keys[1];
            } else {
                best_anchor_key = side_anchor_keys[2];
            }

            return best_anchor_key;
        }

        let best_key : AnchorPosition = AnchorPosition.D0;
        switch (side) {
            case "n":
                best_key = evaluate_anchors([AnchorPosition.D90, AnchorPosition.D120, AnchorPosition.D60]);
                break;
            case "s":
                if (block.id === "condition") {
                    throw new Error("Cannot assume true or false anchors on condition blocks.");
                }
                best_key = evaluate_anchors([AnchorPosition.D270, AnchorPosition.D240, AnchorPosition.D300]);
                break;
            case "e":
                best_key = evaluate_anchors([AnchorPosition.D0, AnchorPosition.D30, AnchorPosition.D330]);
                break;
            case "w":
                best_key = evaluate_anchors([AnchorPosition.D180, AnchorPosition.D150, AnchorPosition.D210]);
                break;
        }

        result = block.anchors.get(best_key) as Anchor;

        return result;
    }

    /**
     * Connects a parent and child block with a line.
     * @param parent
     *  The parent block.
     * @param child
     *  The child block.
     * @param line
     *  The line.
     * @param parent_stix
     * The STIX object representation of the parent block.
     */
    private connectBlocks(parent: Block, child: Block, line: Line, parent_stix: StixObject | undefined, child_stix: StixObject | undefined) {
        const place_below = new Set(["action", "AND_operator", "OR_operator", "condition"]);

        let parent_anchor = this.getAvailableAnchor(parent, "w");
        let child_anchor = child.anchors.get(AnchorPosition.D0);

        if (place_below.has(child.id)) {
            child_anchor = child.anchors.get(AnchorPosition.D90);
            // Special case: Determine anchors to connect for condition blocks.
            if (parent.id === "condition") {
                // Default to a side anchor.
                parent_anchor = this.getAvailableAnchor(parent, "w");
                if (parent_stix && child_stix) {
                    const true_refs : Array<string> | undefined = "on_true_refs" in parent_stix ? parent_stix.on_true_refs : undefined;
                    const false_refs : Array<string> | undefined = "on_false_refs" in parent_stix ? parent_stix.on_false_refs : undefined;
                    if (Array.isArray(true_refs) && true_refs.includes(child_stix.id)) {
                        parent_anchor = parent.anchors.get("branch:True") as Anchor;
                    } else if (Array.isArray(false_refs) && false_refs.includes(child_stix.id)) {
                        parent_anchor = parent.anchors.get("branch:False") as Anchor;
                    }
                }
            } else {
                parent_anchor = this.getAvailableAnchor(parent, "s");
            }
        }

        parent_anchor?.link(line.source);
        child_anchor?.link(line.target);

    }


}
