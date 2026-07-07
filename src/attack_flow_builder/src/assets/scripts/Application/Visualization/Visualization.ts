import { Device } from "@/assets/scripts/Browser";
import { toBlob, toSvg } from "html-to-image";
import type { Options } from "html-to-image/lib/types";
import type { Component } from "vue";
import type { ApplicationStore } from "@/stores/ApplicationStore";

export interface VisualizationRegistration {

    /**
     * The visualization's unique identifier.
     */
    id: string;

    /**
     * The visualization's display title.
     */
    title: string;

    /**
     * The visualization's Vue component.
     */
    component: Component;

    /**
     * A custom name for the exported file.
     */
    exportName?: string | ((app: ApplicationStore) => string);

    /**
     * A custom root for exports.
     */
    getExportRoot?: (root: HTMLElement) => HTMLElement | null;

    /**
     * A custom exporter for the visualization.
     */
    exporter?: VisualizationExporter;

}

export interface VisualizationModalController {

    /**
     * The available visualizations.
     */
    readonly visualizations: readonly VisualizationRegistration[];

    /**
     * Whether the modal is open.
     */
    active: boolean;

    /**
     * The active visualization.
     */
    readonly activeVisualization?: VisualizationRegistration;

    /**
     * Opens a visualization in the modal.
     * @param id
     *  The visualization's identifier.
     */
    open(id: string): void;

    /**
     * Closes the modal.
     */
    close(): void;

}

export interface VisualizationExportContext {

    /**
     * The application store.
     */
    app: ApplicationStore;

    /**
     * The visualization being exported.
     */
    visualization: VisualizationRegistration;

    /**
     * The visualization's rendered root element.
     */
    root: HTMLElement;

}

export type VisualizationExporter = (
    context: VisualizationExportContext
) => Promise<void>;

/**
 * Exports a visualization with either its custom exporter or the default SVG
 * exporter.
 * @param context
 *  The visualization export context.
 */
export async function exportVisualization(
    context: VisualizationExportContext
): Promise<void> {
    const { visualization } = context;
    if (visualization.exporter) {
        await visualization.exporter(context);
    } else {
        await exportVisualizationAsSvg(context);
    }
}

/**
 * Maximum width for clipboard images so pastes work reliably in Teams and
 * PowerPoint without exceeding typical clipboard size limits.
 */
const MAX_CLIPBOARD_IMAGE_WIDTH = 1200;

/**
 * Applied to visualization toolbars and controls that should be excluded from
 * clipboard captures. New visualizations should add this class to any UI
 * chrome that should not appear in copied images.
 */
const VISUALIZATION_EXPORT_IGNORE_CLASS = "visualization-export-ignore";

/**
 * Resolves the element to capture for clipboard copy.
 */
function getClipboardExportRoot(context: VisualizationExportContext): Element {
    const exportRoot = context.visualization.getExportRoot?.(context.root);
    return exportRoot instanceof Element ? exportRoot : context.root;
}

/**
 * Resolves a single SVG element from an export root when present.
 */
function resolveExportSvg(exportRoot: Element): SVGSVGElement | null {
    if (exportRoot instanceof SVGSVGElement) {
        return exportRoot;
    }

    const svg = exportRoot.querySelector("svg");
    return svg instanceof SVGSVGElement ? svg : null;
}

/**
 * Excludes visualization UI chrome marked with
 * {@link VISUALIZATION_EXPORT_IGNORE_CLASS} from clipboard captures.
 */
function shouldIncludeClipboardCaptureNode(node: Node): boolean {
    return !(node instanceof Element)
        || !node.closest(`.${VISUALIZATION_EXPORT_IGNORE_CLASS}`);
}

/**
 * Returns html-to-image options for clipboard capture.
 */
function buildClipboardCaptureOptions(
    dimensions: { width: number, height: number }
): Options {
    return {
        cacheBust: true,
        filter: shouldIncludeClipboardCaptureNode,
        width: dimensions.width,
        height: dimensions.height,
        backgroundColor: "rgba(0,0,0,0)",
        pixelRatio: 1,
        style: {
            overflow: "hidden",
            scrollbarWidth: "none",
            background: "transparent",
            backgroundColor: "transparent"
        }
    };
}

/**
 * Resolves the intrinsic size of an SVG element for clipboard rasterization.
 */
function getSvgExportDimensions(svg: SVGSVGElement): { width: number, height: number } {
    const width = svg.width.baseVal.value;
    const height = svg.height.baseVal.value;

    if (width > 0 && height > 0) {
        return { width, height };
    }

    try {
        const bbox = svg.getBBox();
        const bboxWidth = Math.ceil(bbox.width);
        const bboxHeight = Math.ceil(bbox.height);
        if (bboxWidth > 0 && bboxHeight > 0) {
            return { width: bboxWidth, height: bboxHeight };
        }
    } catch {
        // getBBox throws when the SVG is not rendered.
    }

    throw new Error("Unable to determine visualization size.");
}

/**
 * Resolves clipboard capture dimensions for an HTML export root.
 */
function getClipboardImageDimensions(element: HTMLElement): { width: number, height: number } {
    const width = element.scrollWidth || element.clientWidth;
    const height = element.scrollHeight || element.clientHeight;

    if (!width || !height) {
        throw new Error("Unable to determine visualization size.");
    }

    return scaleDimensionsForClipboard(width, height);
}

/**
 * Scales visualization dimensions down for clipboard pasting while preserving
 * aspect ratio.
 */
function scaleDimensionsForClipboard(
    sourceWidth: number,
    sourceHeight: number
): { width: number, height: number } {
    if (sourceWidth <= MAX_CLIPBOARD_IMAGE_WIDTH) {
        return { width: sourceWidth, height: sourceHeight };
    }

    const scale = MAX_CLIPBOARD_IMAGE_WIDTH / sourceWidth;
    return {
        width: Math.round(sourceWidth * scale),
        height: Math.round(sourceHeight * scale)
    };
}

/**
 * Clones an SVG for clipboard raster export without scroll-container layout
 * constraints.
 */
function prepareSvgForRasterExport(
    svg: SVGSVGElement,
    width: number,
    height: number
): SVGSVGElement {
    const clone = svg.cloneNode(true) as SVGSVGElement;
    const sourceViewBox = svg.getAttribute("viewBox");

    if (sourceViewBox) {
        clone.setAttribute("viewBox", sourceViewBox);
    } else {
        try {
            const bbox = svg.getBBox();
            clone.setAttribute(
                "viewBox",
                `${bbox.x} ${bbox.y} ${bbox.width} ${bbox.height}`
            );
        } catch {
            // getBBox throws when the SVG is not rendered.
        }
    }

    clone.setAttribute("width", String(width));
    clone.setAttribute("height", String(height));
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    clone.style.minWidth = "auto";
    clone.style.minHeight = "auto";
    clone.style.width = `${width}px`;
    clone.style.height = `${height}px`;
    clone.style.overflow = "visible";
    clone.style.maxWidth = "none";
    clone.style.maxHeight = "none";
    return clone;
}

/**
 * Rasterizes an SVG element to a transparent PNG blob at clipboard-friendly
 * dimensions. Uses native SVG serialization so the full graphic is captured
 * instead of the visible scroll viewport.
 */
async function rasterizeSvgElementToPngBlob(svg: SVGSVGElement): Promise<Blob> {
    const sourceDimensions = getSvgExportDimensions(svg);
    const outputDimensions = scaleDimensionsForClipboard(
        sourceDimensions.width,
        sourceDimensions.height
    );
    const exportSvg = prepareSvgForRasterExport(
        svg,
        sourceDimensions.width,
        sourceDimensions.height
    );
    const svgText = new XMLSerializer().serializeToString(exportSvg);
    const svgUrl = URL.createObjectURL(
        new Blob([svgText], { type: "image/svg+xml;charset=utf-8" })
    );

    try {
        const image = await loadImage(svgUrl);
        const canvas = document.createElement("canvas");
        canvas.width = outputDimensions.width;
        canvas.height = outputDimensions.height;
        const context = canvas.getContext("2d");
        if (!context) {
            throw new Error("Unable to render visualization image.");
        }
        context.clearRect(0, 0, canvas.width, canvas.height);
        context.drawImage(
            image,
            0,
            0,
            outputDimensions.width,
            outputDimensions.height
        );
        return await canvasToPngBlob(canvas);
    } finally {
        URL.revokeObjectURL(svgUrl);
    }
}

function loadImage(url: string): Promise<HTMLImageElement> {
    return new Promise((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error("Unable to render visualization image."));
        image.src = url;
    });
}

function canvasToPngBlob(canvas: HTMLCanvasElement): Promise<Blob> {
    return new Promise((resolve, reject) => {
        canvas.toBlob(
            blob => blob ? resolve(blob) : reject(new Error("Unable to render visualization image.")),
            "image/png"
        );
    });
}

/**
 * Rasterizes an HTML export root with html-to-image for clipboard copy.
 */
async function rasterizeHtmlElementToPngBlob(element: Element): Promise<Blob> {
    if (!(element instanceof HTMLElement)) {
        throw new Error("Unable to render visualization image.");
    }

    const dimensions = getClipboardImageDimensions(element);
    const pngBlob = await toBlob(element, buildClipboardCaptureOptions(dimensions));
    if (!pngBlob) {
        throw new Error("Unable to render visualization image.");
    }
    return pngBlob;
}

/**
 * Copies a visualization to the device's clipboard as a transparent PNG image.
 *
 * Download still uses SVG via {@link exportVisualizationAsSvg}. Clipboard copy
 * uses a scaled PNG because Teams, PowerPoint, and similar apps handle
 * `image/png` more reliably than large SVG markup.
 * @param context
 *  The visualization export context.
 */
export async function copyVisualizationToClipboard(
    context: VisualizationExportContext
): Promise<void> {
    const exportRoot = getClipboardExportRoot(context);
    const svg = resolveExportSvg(exportRoot);
    const pngBlob = svg
        ? await rasterizeSvgElementToPngBlob(svg)
        : await rasterizeHtmlElementToPngBlob(exportRoot);
    try {
        await navigator.clipboard.write([
            new ClipboardItem({ "image/png": pngBlob })
        ]);
    } catch {
        alert(
            "Clipboard access has been prohibited. " +
            "Please grant the required clipboard permissions."
        );
    }
}

/**
 * Exports a visualization as an SVG file using html-to-image.
 * @param context
 *  The visualization export context.
 */
export async function exportVisualizationAsSvg(
    context: VisualizationExportContext
): Promise<void> {
    const exportRoot = context.visualization.getExportRoot?.(context.root)
        ?? context.root;
    const svgDataUrl = await toSvg(exportRoot, { cacheBust: true });
    Device.downloadTextFile(
        getVisualizationExportName(context),
        svgDataUrlToText(svgDataUrl),
        "svg"
    );
}

/**
 * Finds an svg element and exports it to an svg image. If no svg element exists
 * in the root or if multiple exist, throws an error.
 * Uses browser-native capability instead of html-to-image.
 * @param context The visualization export context
 */
export async function liteSvgExporter(
    context: VisualizationExportContext
): Promise<void> {

    const exportRoot = context.visualization.getExportRoot?.(context.root)
        ?? context.root;
    const svgCandidates = exportRoot.querySelectorAll("svg");

    if (svgCandidates.length === 0) {
        throw new Error("No svg element found. Cannot export.");
    }

    if (svgCandidates.length > 1) {
        throw new Error("Multiple svg elements found. Cannot export.");
    }

    const svg = svgCandidates[0];

    const svgText = new XMLSerializer().serializeToString(svg);
    const blob = new Blob([svgText], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = getVisualizationExportName(context) + ".svg";
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * Resolves the exported file name for a visualization.
 * @param context
 *  The visualization export context.
 * @returns
 *  The export file name without an extension.
 */
function getVisualizationExportName(
    context: VisualizationExportContext
): string {
    const sourceName = context.app.activeEditor.file.canvas.properties.toString()
        || "attack-flow";
    const exportName = typeof context.visualization.exportName === "function"
        ? context.visualization.exportName(context.app)
        : context.visualization.exportName
            ?? context.visualization.title;
    return sanitizeFileName(`${sourceName} - ${exportName}`);
}

/**
 * Converts an SVG data URL into SVG file contents.
 * @param dataUrl
 *  The data URL to decode.
 * @returns
 *  The SVG file contents.
 */
function svgDataUrlToText(dataUrl: string): string {
    const parts = dataUrl.split(",", 2);
    if (parts.length !== 2) {
        throw new Error("Unable to decode SVG export.");
    }
    const [prefix, content] = parts;
    return prefix.includes(";base64")
        ? atob(content)
        : decodeURIComponent(content);
}

/**
 * Removes characters that are unsafe for downloaded file names.
 * @param value
 *  The file name to sanitize.
 * @returns
 *  A safe file name.
 */
function sanitizeFileName(value: string): string {
    return value
        .replace(/[\\/:*?"<>|]+/g, "-")
        .replace(/\s+/g, " ")
        .trim();
}
