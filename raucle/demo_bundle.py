"""Demo bundle: locate, digest, and document the shipped demo bundle.

The bundle at ``docs/demo-bundle/`` is a real, offline-verifiable audit pack
(shipped evidence anyone can verify with one command: ``raucle demo verify``).

Published-value mechanism
=========================

``bundle_digest`` is a sha256 over the sorted member digests of every file in
the bundle. It is **published OUTSIDE the bundle** (in this repo's CI
workflow, ``.github/workflows/ci.yml``, and downstream pinners) so it can
never be silently changed by the same PR that doctored the bundle: repinning
is always a separate, reviewable edit. ``raucle demo verify --pinned <hex>``
compares the computed digest against the published value; a mismatch or a
failed pack verification exits non-zero.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

DEMO_BUNDLE_DIRNAME = Path("docs") / "demo-bundle"

# Canonical bundle-digest algorithm version. Bumping it invalidates all pinned
# values, so treat any bump as a published-event worth its own PR.
DIGEST_ALGO = "raucle-demo-bundle-digest/v1"


def locate_demo_bundle(explicit: str | Path | None = None) -> Path:
    """Return the demo-bundle directory: explicit path, else cwd, else repo."""
    if explicit is not None:
        return Path(explicit)
    candidates = [
        Path.cwd() / DEMO_BUNDLE_DIRNAME,
        Path(__file__).resolve().parent.parent / DEMO_BUNDLE_DIRNAME,
    ]
    for candidate in candidates:
        if (candidate / "PACK.json").is_file():
            return candidate
    tried = ", ".join(str(c) for c in candidates)
    raise FileNotFoundError(
        f"demo bundle not found (looked for PACK.json in: {tried}); "
        "pass the bundle directory as the first argument, or run from the repo root"
    )


def bundle_digest(pack_dir: str | Path) -> str:
    """Canonical digest of the bundle: sha256 over the sorted pack-member digests.

    Enumerates the members declared (and signature-checked) in ``PACK.json`` —
    chain, manifest, report, pubkeys — plus ``PACK.json`` itself. Non-member
    files (e.g. documentation) intentionally do not move the digest, so a doc
    edit never triggers a repin, while a re-signed replacement of any evidence
    member does.
    """
    pack = Path(pack_dir)
    index_path = pack / "PACK.json"
    if not index_path.is_file():
        raise FileNotFoundError(f"no PACK.json in {pack}")
    index = json.loads(index_path.read_text())
    members: list[tuple[str, str]] = []
    for member in index.get("members", []):
        rel = member.get("path")
        if not isinstance(rel, str) or not rel:
            raise ValueError(f"PACK.json member without a path: {member!r}")
        members.append((rel, hashlib.sha256((pack / rel).read_bytes()).hexdigest()))
    members.append(("PACK.json", hashlib.sha256(index_path.read_bytes()).hexdigest()))
    payload = "\n".join(f"{digest}\t{rel}" for rel, digest in sorted(members)) + "\n"
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def pack_index_summary(pack_dir: str | Path) -> dict[str, object]:
    """Human-relevant fields from PACK.json (signer id, member count, version)."""
    index = json.loads((Path(pack_dir) / "PACK.json").read_text())
    return {
        "kind": index.get("kind"),
        "tool_version": index.get("tool_version"),
        "audit_key_id": index.get("audit_key_id"),
        "member_count": len(index.get("members", [])),
        "verify": index.get("verify"),
    }
