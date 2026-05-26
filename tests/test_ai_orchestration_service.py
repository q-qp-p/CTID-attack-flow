import json
from pathlib import Path

from attack_flow_api.config import ProviderConfig, ProvidersConfig
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.ai_orchestration_service import AIOrchestrationService
from attack_flow_api.services.ai_provider_invocation_service import AIProviderInvocationService
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import InputSourceCreate, JobCreate


def test_orchestration_service_runs_with_deterministic_only_path(tmp_path: Path) -> None:
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    persistence = PersistenceService(db_path)

    normalized_package = {
        "source_type": "stix_structured",
        "normalized_text": "",
        "metadata": {"title": "Case A", "authors": ["analyst-a"]},
        "structured_summary": {"bundle_metadata": {"id": "bundle--1"}},
        "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
        "entities": [{"object_id": "malware--1", "object_type": "malware"}],
        "relationships": [
            {
                "relationship_id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "malware--1",
            }
        ],
        "provenance": {"narrative_source_object_ids": ["report--1"]},
    }

    input_source = persistence.create_input_source(
        InputSourceCreate(
            id="input-1",
            type="file",
            file_class="stix_json",
            normalized_package_json=json.dumps(normalized_package),
            normalized_source_type="stix_structured",
        )
    )
    persistence.create_job(
        JobCreate(
            id="job-1",
            status="queued",
            stage="queued",
            input_source_id=input_source.id,
        )
    )

    registry = ProviderRegistry(
        ProvidersConfig(
            providers=[
                ProviderConfig(
                    provider_id="default-openai",
                    provider_type="openai",
                    enabled=True,
                    default_model="gpt-4.1-mini",
                    api_key_env="OPENAI_API_KEY",
                )
            ]
        )
    )
    invocation = AIProviderInvocationService(registry)
    service = AIOrchestrationService(
        persistence_service=persistence,
        provider_invocation_service=invocation,
    )

    result = service.run_for_job(job_id="job-1", requested_provider_id=None, requested_model=None)

    assert result.succeeded is True
    assert result.provider_invoked is False
    payload = json.loads(result.extraction_payload_json)
    assert payload["deterministic_attack_refs"][0]["technique_id"] == "T1059"
    assert payload["deterministic_attack_refs"][0]["confidence"] == 1.0
