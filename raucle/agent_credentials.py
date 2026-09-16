"""Agent credential store for gateway API-key authentication.

Task A1.1 of the production-readiness plan. Each agent gets a
``rak_``-prefixed API key; only the SHA-256 hash of the key is written to
disk, never the key itself. Verification is a constant-time hash lookup.
Revocation removes the agent's record entirely (fail-closed).

Storage: JSONL with atomic-rename writes so a crash mid-write can never
corrupt the store. A corrupt file fails closed on load with a clear error
rather than being silently reset (a reset would resurrect revoked keys).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

_KEY_PREFIX = "rak_"
_KEY_BYTES = 32  # 256 bits of entropy


class AgentCredentialStore:
    """Issue and verify per-agent API keys, persisted to a JSONL file.

    Each agent maps to exactly one active key. Issuing a new key for an
    agent that already has one replaces it (the old key stops verifying
    immediately) - this is the rotation path.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._by_hash: dict[str, str] = {}
        self._by_agent: dict[str, str] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def issue(self, agent_id: str) -> str:
        """Mint a new key for *agent_id*, replacing any existing one.

        Returns the plaintext key. It is shown exactly once; only its
        SHA-256 digest is stored.
        """
        key = _KEY_PREFIX + secrets.token_hex(_KEY_BYTES)
        key_hash = hashlib.sha256(key.encode("ascii")).hexdigest()
        self._by_hash[key_hash] = agent_id
        self._by_agent[agent_id] = key_hash
        self._persist()
        return key

    def verify(self, key: str) -> str | None:
        """Return the agent_id for *key*, or None if unknown/revoked.

        Constant-time: the candidate is hashed and looked up; no
        early-exit comparison over stored keys.
        """
        if not key or not isinstance(key, str):
            return None
        candidate = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()
        agent_id = self._by_hash.get(candidate)
        if agent_id is None:
            return None
        # Confirm the agent still has this exact key active (guards against
        # a stale hash entry surviving a re-issue race).
        stored_hash = self._by_agent.get(agent_id)
        if stored_hash is not None and not hmac.compare_digest(stored_hash, candidate):
            return None
        return agent_id

    def revoke(self, agent_id: str) -> bool:
        """Remove *agent_id*'s credential entirely. Idempotent."""
        key_hash = self._by_agent.pop(agent_id, None)
        if key_hash is None:
            return False
        self._by_hash.pop(key_hash, None)
        self._persist()
        return True

    def list_agents(self) -> list[str]:
        """Active agent ids (sorted for determinism)."""
        return sorted(self._by_agent.keys())

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        records: list[dict[str, Any]] = []
        text = self._path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"agent credential store {self._path} is corrupt "
                    f"(line {lineno}: {exc}); refusing to reset - restore the "
                    f"file or delete it only after re-issuing every agent key"
                ) from exc
            if not isinstance(rec, dict) or "agent_id" not in rec or "key_hash" not in rec:
                raise ValueError(
                    f"agent credential store {self._path} is corrupt "
                    f"(line {lineno}: not a credential record); refusing to reset"
                )
            records.append(rec)
        for rec in records:
            self._by_hash[rec["key_hash"]] = rec["agent_id"]
            self._by_agent[rec["agent_id"]] = rec["key_hash"]

    def _persist(self) -> None:
        """Write the store atomically (temp file + rename)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        records = [
            {"agent_id": agent_id, "key_hash": key_hash}
            for agent_id, key_hash in sorted(self._by_agent.items())
        ]
        payload = "".join(json.dumps(r) + "\n" for r in records)
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), prefix=".creds-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
