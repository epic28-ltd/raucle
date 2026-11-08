"""S3 (EPIC S3): threat-model-as-code.

Contract: every control in docs/threat-model/threat-model.json is either
MAPPED with at least one test that exists in the repository, or explicitly
OUT-OF-SCOPE with a reason; every T-section documented in v1.md has a
mapping entry; and the checker fails named when a control loses its test —
that is the CI guard this file pins.
"""

import json

from scripts.threat_model_check import check

MAPPING = "docs/threat-model/threat-model.json"
SOURCE = "docs/threat-model/v1.md"


def test_the_real_tree_is_clean():
    errors = check(SOURCE, MAPPING)
    assert errors == [], errors


def test_missing_pinned_test_fails_named(tmp_path):
    """The CI scenario: a test a control cites is deleted -> red."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "stale_test.py").write_text("# will be pinned then deleted\n")
    entry = {
        "version": 1,
        "threats": [
            {
                "id": "T1",
                "title": "demo",
                "controls": [
                    {
                        "id": "C-1",
                        "description": "demo control",
                        "module": "raucle/x.py",
                        "tests": ["stale_test.py"],
                        "status": "mapped",
                    }
                ],
            }
        ],
    }
    source = tmp_path / "v1.md"
    source.write_text("")
    mapping = tmp_path / "threat-model.json"
    mapping.write_text(json.dumps(entry))
    assert check(source, mapping, repo_root=repo) == []

    (repo / "stale_test.py").unlink()  # the control lost its test
    errors = check(source, mapping, repo_root=repo)
    assert any("stale_test.py" in e and "does not exist" in e for e in errors)


def test_mapped_control_without_tests_fails(tmp_path):
    entry = {
        "threats": [
            {
                "id": "T1",
                "title": "demo",
                "controls": [{"id": "C-1", "description": "x", "tests": [], "status": "mapped"}],
            }
        ]
    }
    errors = check(tmp_path / "s.md", _js(tmp_path, entry), repo_root=tmp_path)
    assert any("mapped but names no test" in e for e in errors)


def test_out_of_scope_without_reason_fails(tmp_path):
    entry = {
        "threats": [
            {
                "id": "T1",
                "title": "demo",
                "controls": [
                    {"id": "C-1", "description": "x", "tests": [], "status": "out_of_scope"}
                ],
            }
        ]
    }
    errors = check(tmp_path / "s.md", _js(tmp_path, entry), repo_root=tmp_path)
    assert any("no reason" in e for e in errors)


def test_documented_threat_missing_from_mapping_fails(tmp_path):
    source = tmp_path / "v1.md"
    source.write_text("## T9 — New boundary added to the doc\n\nnone\n")
    entry = {
        "threats": [
            {
                "id": "T1",
                "title": "demo",
                "controls": [],
            }
        ]
    }
    errors = check(source, _js(tmp_path, entry), repo_root=tmp_path)
    assert any("T9" in e and "absent from the mapping" in e for e in errors)


def test_source_unreadable_is_a_failure_not_a_pass(tmp_path):
    good = {
        "threats": [
            {
                "id": "T1",
                "title": "demo",
                "controls": [
                    {
                        "id": "C-1",
                        "description": "x",
                        "tests": ["existing_test.py"],
                        "status": "mapped",
                    }
                ],
            }
        ]
    }
    (tmp_path / "existing_test.py").write_text("")
    errors = check(tmp_path / "ghost.md", _js(tmp_path, good), repo_root=tmp_path)
    assert any("source unreadable" in e for e in errors)


def _js(tmp_path, entry):
    path = tmp_path / "threat-model.json"
    path.write_text(json.dumps(entry))
    return path
