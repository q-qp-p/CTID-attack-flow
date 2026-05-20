import sqlite3
from pathlib import Path


SCHEMA_VERSION = 8


def create_connection(sqlite_path: Path) -> sqlite3.Connection:
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(sqlite_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(sqlite_path: Path) -> None:
    with create_connection(sqlite_path) as connection:
        _create_schema_migrations_table(connection)
        current_version = _get_schema_version(connection)
        if current_version < SCHEMA_VERSION:
            _apply_schema(connection)
            _set_schema_version(connection, SCHEMA_VERSION)


def _create_schema_migrations_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        """
    )


def _get_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
    if row is None or row["version"] is None:
        return 0
    return int(row["version"])


def _set_schema_version(connection: sqlite3.Connection, version: int) -> None:
    connection.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version,))


def _apply_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS input_sources (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            original_name TEXT,
            source_url TEXT,
            fetch_final_url TEXT,
            fetch_status_code INTEGER,
            fetch_content_type TEXT,
            fetch_size_bytes INTEGER,
            fetch_error_code TEXT,
            fetch_error_message TEXT,
            content_text TEXT,
            raw_text TEXT,
            normalized_text TEXT,
            normalized_char_count INTEGER,
            was_truncated INTEGER,
            normalization_version TEXT,
            storage_path TEXT,
            metadata_json TEXT,
            options_json TEXT,
            mime_type TEXT,
            size_bytes INTEGER,
            sha256 TEXT,
            title TEXT,
            case_id TEXT,
            source_name TEXT,
            stored_filename TEXT,
            detected_mime_type TEXT,
            file_class TEXT,
            stix_json_kind TEXT,
            stix_json_valid INTEGER,
            ingestion_error_code TEXT,
            ingestion_error_message TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            provider_id TEXT,
            model TEXT,
            input_source_id TEXT,
            result_json TEXT,
            progress_percent INTEGER,
            started_at TEXT,
            last_heartbeat_at TEXT,
            worker_id TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            completed_at TEXT,
            error_code TEXT,
            error_message TEXT,
            request_id TEXT,
            FOREIGN KEY (input_source_id) REFERENCES input_sources(id)
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            type TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT,
            size_bytes INTEGER,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (job_id) REFERENCES jobs(id)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            job_id TEXT,
            request_id TEXT,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            metadata_json TEXT,
            FOREIGN KEY (job_id) REFERENCES jobs(id)
        );
        """
    )
