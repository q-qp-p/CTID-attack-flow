from attack_flow_api.services.stix_entities import extract_stix_entities


def test_extract_stix_entities_extracts_supported_types_with_core_fields():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "campaign",
                "id": "campaign--1",
                "name": "Spring Offensive",
                "description": "Campaign description",
                "labels": ["apt", "high-priority"],
                "created_by_ref": "identity--author",
            },
            {
                "type": "indicator",
                "id": "indicator--1",
                "name": "Suspicious Hash",
                "pattern": "[file:hashes.'SHA-256' = 'abc']",
                "confidence": 70,
            },
            {
                "type": "sighting",
                "id": "sighting--1",
                "source_ref": "identity--sensor",
                "target_ref": "indicator--1",
                "observed_data_refs": ["observed-data--1"],
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-01-02T00:00:00Z",
            },
            {
                "type": "observed-data",
                "id": "observed-data--1",
                "first_observed": "2026-01-01T00:00:00Z",
            },
            {
                "type": "marking-definition",
                "id": "marking-definition--skip",
                "definition_type": "tlp",
            },
        ],
    }

    entities = extract_stix_entities(bundle)

    assert [entity.object_type for entity in entities] == [
        "campaign",
        "indicator",
        "observed-data",
        "sighting",
    ]

    campaign = entities[0]
    assert campaign.object_id == "campaign--1"
    assert campaign.display_name == "Spring Offensive"
    assert campaign.description == "Campaign description"
    assert campaign.labels == ["apt", "high-priority"]
    assert campaign.created_by_ref == "identity--author"

    indicator = entities[1]
    assert indicator.pattern == "[file:hashes.'SHA-256' = 'abc']"
    assert indicator.confidence == 70

    sighting = entities[3]
    assert sighting.source_ref == "identity--sensor"
    assert sighting.target_ref == "indicator--1"
    assert sighting.observed_data_refs == ["observed-data--1"]


def test_extract_stix_entities_uses_fallback_name_fields_and_provenance():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "report",
                "id": "report--1",
                "title": "Executive Report",
                "description": "Report body",
            },
            {
                "type": "note",
                "id": "note--1",
                "abstract": "Analyst Note",
                "content": "Detailed note content",
            },
        ],
    }

    entities = extract_stix_entities(bundle)

    note = entities[0]
    report = entities[1]

    assert note.object_type == "note"
    assert note.display_name == "Analyst Note"
    assert note.description == "Detailed note content"
    assert note.provenance["display_name"] == "abstract"
    assert note.provenance["description"] == "content"

    assert report.object_type == "report"
    assert report.display_name == "Executive Report"
    assert report.provenance["display_name"] == "title"


def test_extract_stix_entities_is_deterministic_and_ignores_empty_values():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "tool", "id": "tool--b", "name": "  "},
            {"type": "tool", "id": "tool--a", "name": "Recon Toolkit", "labels": ["  ", "ops"]},
            {"type": "malware", "id": "malware--1", "description": "payload"},
        ],
    }

    entities = extract_stix_entities(bundle)

    assert [(entity.object_type, entity.object_id) for entity in entities] == [
        ("malware", "malware--1"),
        ("tool", "tool--a"),
        ("tool", "tool--b"),
    ]
    assert entities[1].labels == ["ops"]
    assert entities[2].display_name is None
