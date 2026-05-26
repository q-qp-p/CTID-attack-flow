from pathlib import Path

import json

from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import JobCreate, JobExtractionUpdate


def test_update_job_extraction_persists_afb_intermediate_fields(tmp_path: Path) -> None:
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_job(
        JobCreate(
            id="job-afb-1",
            status="queued",
            stage="queued",
        )
    )
    assert created is not None

    extraction_payload = {
        "schema_version": "afb-v2-intermediate",
        "attack_flow": {"id": "attack-flow--1", "name": "Example flow", "scope": "incident", "start_refs": []},
        "attack_actions": [],
    }

    updated = service.update_job_extraction(
        "job-afb-1",
        JobExtractionUpdate(
            extraction_mode="ai_enrichment",
            provider_invoked=True,
            provider_id="default-openai",
            model="gpt-4.1-mini",
            extraction_result_json=json.dumps(extraction_payload),
            extraction_validation_state="valid",
            extraction_repair_attempted=True,
            extraction_provenance_classification="stix_structured",
            extraction_authors_json='["analyst-a"]',
            extraction_external_references_json='["https://example.com/report"]',
        ),
    )

    assert updated is not None
    assert updated.extraction_mode == "ai_enrichment"
    assert updated.provider_invoked is True
    assert updated.provider_id == "default-openai"
    assert updated.model == "gpt-4.1-mini"
    assert updated.extraction_validation_state == "valid"
    assert updated.extraction_repair_attempted is True
    assert updated.extraction_provenance_classification == "stix_structured"
    assert updated.extraction_authors_json == '["analyst-a"]'
    assert updated.extraction_external_references_json == '["https://example.com/report"]'
    assert json.loads(updated.extraction_result_json or "{}")["schema_version"] == "afb-v2-intermediate"
