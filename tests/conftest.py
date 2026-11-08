"""Shared test fixtures.

The URL guard (T-S4) blocks loopback/private targets by default, but this
suite exercises real HTTP behaviour against loopback doubles deliberately
(http.server on 127.0.0.1, no external calls). Opt in once here; negative
URL-guard tests remove the opt-in explicitly.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _allow_private_urls_in_tests():
    old = os.environ.get("RAUCLE_ALLOW_PRIVATE_URLS")
    os.environ["RAUCLE_ALLOW_PRIVATE_URLS"] = "1"
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("RAUCLE_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["RAUCLE_ALLOW_PRIVATE_URLS"] = old
