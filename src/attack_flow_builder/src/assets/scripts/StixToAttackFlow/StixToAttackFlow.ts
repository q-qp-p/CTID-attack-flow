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
        // Create graph of diagram objects from STIX
        const [nodes, edges] = this.parseStixGraph(stix);
        // Mirror graph structure onto nodes
        this.mirrorConnections(nodes);

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
     *  The graph's nodes and edges.
     */
    private parseStixGraph(bundle: StixBundle): [GraphNode[], GraphEdge[]] {
        // Generate node map
        const nodes = new Map<string, GraphNode>();
        const edges = [];
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

        return [[...nodes.values()], edges];
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


    ////////////////////////////////////////////////////////////////////////////
    //  2. Mirror Connections  /////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////


    /**
     * Mirrors a graph's structure onto the underlying {@link DiagramObject}s.
     * @param nodes
     *  The graph's nodes.
     */
    private mirrorConnections(nodes: GraphNode[]) {
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
                        edge.object
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
                        edge.object
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
     */
    private connectBlocks(parent: Block, child: Block, line: Line) {
        const place_below = new Set(["action", "AND_operator", "OR_operator", "condition"]);

        let parent_anchor = this.getAvailableAnchor(parent, "w");
        let child_anchor = child.anchors.get(AnchorPosition.D0);

        if (place_below.has(child.id)) {
            child_anchor = child.anchors.get(AnchorPosition.D90);
            if (parent.id === "condition") {
                // TODO: Encode true/false branch in stix json.
                parent_anchor = this.getAvailableAnchor(parent, "w");
            } else {
                parent_anchor = this.getAvailableAnchor(parent, "s");
            }
        }

        parent_anchor?.link(line.source);
        child_anchor?.link(line.target);

    }


}
