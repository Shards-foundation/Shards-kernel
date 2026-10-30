"""In-memory artifact store for deterministic runtime dataflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from shards_kernel.common.hashing import compute_hash_dict


@dataclass(frozen=True)
class StoredArtifact:
    """Persisted artifact entry."""

    artifact_id: str
    artifact_type: str
    schema_version: str
    value: Any
    value_hash: str
    provenance: tuple[str, ...]
    created_event_id: Optional[str] = None
    parent_artifacts: tuple[str, ...] = ()


class ArtifactStore:
    """Simple in-memory artifact store.

    This store is deterministic and keyed by explicit artifact IDs.
    """

    def __init__(self) -> None:
        self._artifacts: dict[str, StoredArtifact] = {}

    def put(
        self,
        *,
        artifact_id: Optional[str] = None,
        artifact_type: str,
        schema_version: str,
        value: Any,
        provenance: tuple[str, ...],
        created_event_id: Optional[str] = None,
        parent_artifacts: tuple[str, ...] = (),
    ) -> StoredArtifact:
        """Store an artifact and return the normalized record."""
        value_hash = compute_hash_dict(
            {
                "artifact_type": artifact_type,
                "schema_version": schema_version,
                "value": value,
                "provenance": provenance,
                "parent_artifacts": parent_artifacts,
            }
        )
        normalized_artifact_id = artifact_id or value_hash
        if artifact_id is not None and artifact_id != value_hash:
            raise ValueError("artifact_id must equal content hash for immutability")

        existing = self._artifacts.get(normalized_artifact_id)
        if existing is not None and existing.value_hash != value_hash:
            raise ValueError("artifact_id collision with different content hash")

        stored = StoredArtifact(
            artifact_id=normalized_artifact_id,
            artifact_type=artifact_type,
            schema_version=schema_version,
            value=value,
            value_hash=value_hash,
            provenance=provenance,
            created_event_id=created_event_id,
            parent_artifacts=parent_artifacts,
        )
        self._artifacts[normalized_artifact_id] = stored
        return stored

    def get(self, artifact_id: str) -> Optional[StoredArtifact]:
        """Get an artifact by ID."""
        return self._artifacts.get(artifact_id)

    def has(self, artifact_id: str) -> bool:
        """Check artifact presence."""
        return artifact_id in self._artifacts
