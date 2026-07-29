import { fetchJson } from "./source_utils.mjs";

/**
 * @typedef {Object} SourceObject
 *  A Source Object.
 * @property {string} id
 *  The object's id.
 * @property {string} name
 *  The object's name.
 * @property {string} type
 *  The object's type.
 * @property {string} description
 *  The object's description.
 * @property {string} url
 *  The object's url.
 * @property {string} stixId
 *  The object's STIX id.
 * @property {boolean} deprecated
 *  True if the object has been deprecated, false otherwise.
 * @property {StixRelationship[]} stixRelationships
 *  The object's parsed outgoing STIX relationships.
 * @property {{name: string, channel: string}[]} [log_sources]
 *  Aggregated log sources from associated analytics.
 */

/**
 * @typedef {Object} StixRelationship
 *  A relationship between Source Objects.
 * @property {string} relationshipType
 *  The STIX relationship type.
 * @property {string} targetRef
 *  The STIX id of the target object.
 */

/**
 * A map that relates STIX types to source types.
 */
const STIX_TO_ATTACK = {
    "campaign": "campaign",
    "course-of-action": "mitigation",
    "intrusion-set": "group",
    "malware": "software",
    "tool": "software",
    "x-mitre-data-source": "data_source",
    "x-mitre-detection-strategy": "detection",
    "x-mitre-tactic": "tactic",
    "attack-pattern": "technique"
}

/**
 * MITRE's source identifiers.
 */
const MITRE_SOURCES = new Set([
    "mitre-attack",
    "mitre-ics-attack",
    "mitre-mobile-attack",
    "mitre-atlas",
    "mitre-f3"
])

/**
 * Extracts a detection strategy id from an analytic STIX object.
 * @remarks
 *  MITRE links analytics to detection strategies through the analytic's
 *  external reference URL (e.g. .../detectionstrategies/DET0516#AN1429), not
 *  through a STIX relationship object.
 * @param {Object} analytic
 *  The analytic STIX object.
 * @returns {string | undefined}
 *  The detection strategy id, if present.
 */
function getDetectionIdFromAnalytic(analytic) {
    for (const ref of analytic.external_references ?? []) {
        const match = ref.url?.match(/\/detectionstrategies\/(DET\d+)/);
        if (match) {
            return match[1];
        }
    }
}

/**
 * Parses log source references from an analytic STIX object.
 * @remarks
 *  Log sources use MITRE's PRE:POST naming (e.g. wineventlog:security) with a
 *  channel field for event IDs, operations, or match strings.
 * @param {Object} analytic
 *  The analytic STIX object.
 * @returns {{name: string, channel: string}[]}
 *  The parsed log sources.
 */
function parseAnalyticLogSources(analytic) {
    return (analytic.x_mitre_log_source_references ?? [])
        .map(reference => ({
            name: reference.name ?? "",
            channel: reference.channel ?? ""
        }))
        .filter(reference => reference.name.length > 0);
}

/**
 * Aggregates log sources from analytics onto detection strategy objects.
 * @remarks
 *  x-mitre-analytic objects are not added to STIX_TO_ATTACK because they are
 *  not standalone catalog entries. Instead, each analytic contributes zero or
 *  more entries to detection.log_sources (deduplicated union).
 * @param {Object} data
 *  The STIX manifest.
 * @param {Map<string, SourceObject>} objects
 *  The parsed source objects.
 */
function attachDetectionLogSources(data, objects) {
    const logSourcesByDetectionId = new Map();
    const seenLogSourcesByDetectionId = new Map();

    for (const obj of data.objects) {
        if (obj.type !== "x-mitre-analytic" || obj.x_mitre_deprecated || obj.revoked) {
            continue;
        }

        const detectionId = getDetectionIdFromAnalytic(obj);
        if (!detectionId) {
            continue;
        }

        if (!logSourcesByDetectionId.has(detectionId)) {
            logSourcesByDetectionId.set(detectionId, []);
            seenLogSourcesByDetectionId.set(detectionId, new Set());
        }

        // Deduplicate log sources that appear across multiple analytics.
        const seen = seenLogSourcesByDetectionId.get(detectionId);
        const logSources = logSourcesByDetectionId.get(detectionId);
        for (const logSource of parseAnalyticLogSources(obj)) {
            const key = `${logSource.name}\0${logSource.channel}`;
            if (seen.has(key)) {
                continue;
            }
            seen.add(key);
            logSources.push(logSource);
        }
    }

    for (const obj of objects.values()) {
        if (obj.type !== "detection") {
            continue;
        }
        obj.log_sources = logSourcesByDetectionId.get(obj.id) ?? [];
    }
}


/**
 * Parses a source object from a STIX object.
 * @param {Object} obj
 *  The STIX object.
 * @returns {SourceObject}
 *  The parsed source object.
 */
function parseStixToSourceObject(obj) {

    // Parse STIX id, name, and type directly
    let parse = {
        stixId: obj.id,
        name: obj.name,
        type: STIX_TO_ATTACK[obj.type],
        description: obj.description,
        external_references: obj.external_references,
        platforms: obj.x_mitre_platforms,
        domains: obj.x_mitre_domains,
        stixRelationships: []
    }

    // Parse MITRE reference information
    let mitreRef = obj.external_references.find(
        o => MITRE_SOURCES.has(o.source_name)
    );
    if (!mitreRef) {
        throw new Error("Missing MITRE reference information.")
    }
    parse.id = mitreRef.external_id;
    parse.url = mitreRef.url;

    // Parse MITRE shortname
    if (obj.x_mitre_shortname) {
        parse.shortname = obj.x_mitre_shortname;
    }

    // Parse kill-chain phases
    if (obj.kill_chain_phases) {
        parse.tactics = obj.kill_chain_phases.map(o => o.phase_name);
    }

    // Parse deprecation status
    parse.deprecated = (obj.x_mitre_deprecated || obj.revoked) ?? false;

    // Return
    return parse;
}

/**
 * Parses a set of source objects from a STIX manifest.
 * @param {Object} data
 *  The STIX manifest.
 * @returns {SourceObject[]}
 *  The parsed source objects.
 */
export function parseSourceObjectsFromManifest(data) {

    // Parse objects and STIX relationships
    const stixRelationships = [];
    let objects = new Map();
    for (let obj of data.objects) {
        if (obj.type === "relationship") {
            if (obj.x_mitre_deprecated || obj.revoked) {
                continue;
            }
            stixRelationships.push(obj);
            continue;
        }
        if (!(obj.type in STIX_TO_ATTACK)) {
            continue;
        }
        const parse = parseStixToSourceObject(obj);
        objects.set(parse.stixId, parse);
    }

    // Add outgoing STIX relationships to parsed objects
    for (const relation of stixRelationships) {
        const source = objects.get(relation.source_ref);
        const target = objects.get(relation.target_ref);
        if (!source || !target) {
            continue;
        }
        source.stixRelationships.push({
            relationshipType: relation.relationship_type,
            targetRef: relation.target_ref
        });
    }

    // Collect tactics
    const tacticsMap = new Map();
    for(const tactic of objects.values()) {
        if(tactic.type !== "tactic") {
            continue;
        }
        tacticsMap.set(tactic.shortname, tactic);
    }

    // Assign tactics and techniques to each other
    for (const technique of objects.values()) {
        if(technique.type !== "technique") {
            continue;
        }
        const tactics = [];
        for(const tacticShortName of technique.tactics ?? []) {
            // Add tactic to technique
            const tactic = tacticsMap.get(tacticShortName);
            tactics.push(tactic);
            // Add technique to tactic
            if(!tactic.techniques) {
                tactic.techniques = [];
            }
            tactic.techniques.push(technique);
        }
        technique.tactics = tactics;
    }

    // Link x-mitre-analytic log sources to x-mitre-detection-strategy objects.
    attachDetectionLogSources(data, objects);

    // Return catalog
    return [...objects.values()];

}

/**
 * Fetches source data from a set of STIX manifests.
 * @param  {...string} urls
 *  A list of STIX manifests specified by url.
 * @returns {Promise<Map<string, SourceObject>>}
 *  A Promise that resolves with the parsed source data.
 */
export async function fetchSourceData(...urls) {
    console.log("→ Downloading Source Data...");

    // Parse objects
    let catalog = new Map();
    for (let url of urls) {
        console.log(` → ${url.length > 70 ? '...' : ''}${url.substring(url.length - 70)}`);
        let objs = parseSourceObjectsFromManifest(await fetchJson(url));
        for (let obj of objs) {
            catalog.set(obj.stixId, obj);
        }
    }

    // Categorize catalog
    let types = new Map(
        Object.values(STIX_TO_ATTACK).map(v => [v, []])
    );
    for(let obj of catalog.values()) {
        types.get(obj.type).push(obj);
    }

    // Return
    return types;

}
