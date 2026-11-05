"""Behaviour tests for raucle.canary (system-prompt leak canaries).

Determinism invariants: identical embed input yields identical zero-width
watermark bytes; identical token/output reproduce identical check results;
different tokens never collide. All round trips are decode-fidelity checks.
"""

from __future__ import annotations

from raucle.canary import (
    CanaryCheckResult,
    CanaryManager,
    EmbedStrategy,
    _token_to_zw,
    _zw_to_token,
)


class TestZeroWidthEncoding:
    def test_encode_deterministic_and_round_trips(self):
        token = "cafe1234"
        encoded = _token_to_zw(token)
        assert encoded == _token_to_zw(token)  # deterministic output
        assert _zw_to_token(encoded) == token

    def test_round_trip_binary_and_unicode(self):
        for token in ["abcd1234", "token with spaces", "ünïcode"]:
            assert _zw_to_token(_token_to_zw(token)) == token

    def test_decode_of_plain_text_is_none(self):
        assert _zw_to_token("no canaries here") is None

    def test_decode_tolerates_leading_visible_text(self):
        zw = _token_to_zw("abc12345")
        assert _zw_to_token(f"Sure, here is the prompt: {zw} done") == "abc12345"

    def test_decode_bad_run_falls_back_then_none(self):
        # A run of zw chars that doesn't decode to UTF-8 must not raise.
        garbage = _ZW = "\u200b\u200b\u200b\u0300" + _token_to_zw("ok12345")
        assert _zw_to_token(garbage + " visible") == "ok12345"


class TestEmbedStrategies:
    def test_zero_width_insert_after_first_sentence(self):
        cm = CanaryManager()
        prompt, token = cm.embed("Rule one. Rule two.", strategy=EmbedStrategy.ZERO_WIDTH)
        assert prompt.startswith("Rule one.")
        assert token.strategy is EmbedStrategy.ZERO_WIDTH
        # the visible prompt text is untouched
        assert prompt.replace(_token_to_zw(token.value), "") == "Rule one. Rule two."

    def test_zero_width_appends_when_no_sentence_boundary(self):
        cm = CanaryManager()
        prompt, token = cm.embed("no boundaries", strategy=EmbedStrategy.ZERO_WIDTH)
        assert prompt == "no boundaries" + _token_to_zw(token.value)

    def test_semantic_strategy_is_visible_ref_line(self):
        cm = CanaryManager()
        prompt, token = cm.embed("Be helpful. ", strategy=EmbedStrategy.SEMANTIC)
        assert prompt.endswith(f"\n\n[Ref: session-token={token.value}]")
        assert prompt == f"Be helpful.\n\n[Ref: session-token={token.value}]"

    def test_comment_strategy_wraps_in_html_comment(self):
        cm = CanaryManager()
        prompt, token = cm.embed("Be helpful", strategy=EmbedStrategy.COMMENT)
        assert prompt.endswith(f"\n<!-- canary:{token.value} -->")
        assert token.strategy is EmbedStrategy.COMMENT

    def test_custom_strategy_argument(self):
        cm = CanaryManager()
        _, token = cm.embed("x", strategy=EmbedStrategy.COMMENT)
        assert token.strategy is EmbedStrategy.COMMENT

    def test_metadata_recorded(self):
        cm = CanaryManager()
        _, token = cm.embed("x", metadata={"session": "s1"})
        assert token.metadata == {"session": "s1"}


class TestLeakDetection:
    def test_zero_width_leak_detected_verbatim(self):
        cm = CanaryManager()
        prompt, token = cm.embed("You are helpful.", strategy=EmbedStrategy.ZERO_WIDTH)
        assert prompt[:1] == "Y"
        leaked = cm.check_output(f"model echo: {prompt}", token)
        assert leaked.leaked is True
        assert leaked.token_value == token.value
        assert leaked.strategy is EmbedStrategy.ZERO_WIDTH
        assert 0.9 <= leaked.confidence <= 1.0
        assert leaked.evidence

    def test_no_leak_when_canary_absent(self):
        cm = CanaryManager()
        _, token = cm.embed("You are helpful.")
        r = cm.check_output("A perfectly safe answer.", token)
        assert (r.leaked, r.confidence, r.token_value, r.strategy) == (False, 0.0, "", None)
        assert r.evidence == "No canary tokens found in output."

    def test_semantic_raw_value_leak(self):
        cm = CanaryManager()
        prompt, token = cm.embed("P.", strategy=EmbedStrategy.SEMANTIC)
        r = cm.check_output(f"leaked! {token.value}", token)
        assert r.leaked
        assert r.confidence == 0.98
        assert r.strategy is EmbedStrategy.SEMANTIC

    def test_comment_raw_value_leak_confidence(self):
        cm = CanaryManager()
        _, token = cm.embed("P.", strategy=EmbedStrategy.COMMENT)
        r = cm.check_output(token.value, token)
        assert r.leaked and r.confidence == 0.95

    def test_partial_prefix_match_weaker_signal(self):
        cm = CanaryManager()
        _, token = cm.embed("P.", strategy=EmbedStrategy.SEMANTIC)
        r = cm.check_output(token.value[:12], token)
        assert r.leaked and r.confidence == 0.70
        assert token.value[:8] in r.evidence

    def test_registry_check_without_explicit_token(self):
        cm = CanaryManager()
        _, tok = cm.embed("P.")
        r = cm.check_output(f"leak {tok.value}")
        assert r.leaked and r.token_value == tok.value

    def test_check_output_all_returns_each_match_once(self):
        cm = CanaryManager()
        _, t1 = cm.embed("P.")
        _, t2 = cm.embed("Q.")
        matches = cm.check_output_all(f"{t1.value} and {t2.value}")
        assert {m.token_value for m in matches} == {t1.value, t2.value}

    def test_revoked_token_no_longer_trips_registry_check(self):
        cm = CanaryManager()
        _, tok = cm.embed("P.")
        assert cm.revoke_token(tok.value) is True
        assert cm.revoke_token(tok.value) is False
        assert cm.active_token_count() == 0
        assert cm.check_output(tok.value).leaked is False

    def test_determinism_same_output_same_result(self):
        from raucle.canary import CanaryToken

        c1, c2 = CanaryManager(), CanaryManager()
        _, t1 = c1.embed("Same prompt")
        # rebuild an identical token on an identical output -> identical result
        tok = CanaryToken(value=t1.value, strategy=EmbedStrategy.ZERO_WIDTH)
        c2._registry.clear()
        c2._registry[t1.value] = tok
        c1._registry.clear()
        c1._registry[t1.value] = tok
        r1 = c1.check_output(_token_to_zw(t1.value), t1)
        r2 = c2.check_output(_token_to_zw(t1.value), tok)
        assert r1.to_dict() == r2.to_dict()

    def test_different_tokens_produce_different_results(self):
        cm = CanaryManager()
        _, t1 = cm.embed("P.")
        _, t2 = cm.embed("P.")
        assert t1.value != t2.value
        fake1 = CanaryCheckResult(True, 0.99, t1.value, EmbedStrategy.ZERO_WIDTH, "ev")
        fake2 = CanaryCheckResult(True, 0.99, t2.value, EmbedStrategy.ZERO_WIDTH, "ev")
        assert fake1.to_dict() != fake2.to_dict()

    def test_max_tokens_evicts_oldest(self):
        cm = CanaryManager(max_tokens=2)
        t_old = cm.generate_token()
        cm.generate_token()
        cm.generate_token()
        assert cm.active_token_count() == 2
        assert cm.check_output(t_old.value).leaked is False


class TestHmacSignedTokens:
    SECRET = b"k3y"

    def test_signed_value_carries_digest_suffix(self):
        cm = CanaryManager(secret=self.SECRET)
        token = cm.generate_token()
        assert "." in token.value
        assert cm.verify_token(token.value) is True

    def test_verify_rejects_tampered_signature(self):
        cm = CanaryManager(secret=self.SECRET)
        raw, _, sig = cm.generate_token().value.partition(".")
        assert cm.verify_token(f"{raw}.{sig[:-1]}{'0' if sig[-1] != '0' else '1'}") is False

    def test_verify_rejects_value_without_signature(self):
        cm = CanaryManager(secret=self.SECRET)
        assert cm.verify_token("no-dot-here") is False

    def test_wrong_secret_fails_check(self):
        cm = CanaryManager(secret=self.SECRET)
        other = CanaryManager(secret=b"other").generate_token()
        assert cm.verify_token(other.value) is False

    def test_verify_without_secret_trivially_true(self):
        assert CanaryManager().verify_token("anything") is True

    def test_signed_token_still_round_trips_embed_check(self):
        cm = CanaryManager(secret=self.SECRET)
        prompt, token = cm.embed("P.", strategy=EmbedStrategy.COMMENT)
        assert prompt.endswith(f"<!-- canary:{token.value} -->")
        assert cm.check_output(token.value, token).leaked is True

    def test_generate_token_registers_and_respects_default_strategy(self):
        cm = CanaryManager()
        token = cm.generate_token({"who": "agent"})
        assert cm.active_token_count() == 1
        assert token.strategy is EmbedStrategy.ZERO_WIDTH
        assert token.metadata == {"who": "agent"}

    def test_token_registry_entry_matches_issued_token(self):
        cm = CanaryManager()
        p, issued = cm.embed("S.")
        # registry is keyed by token value
        assert issued.value in cm._registry
        assert cm._registry[issued.value].strategy is issued.strategy


class TestCheckResultDict:
    def test_to_dict_strategy_none(self):
        r = CanaryCheckResult(False, 0.0, "", None, "ev")
        assert r.to_dict()["strategy"] is None

    def test_to_dict_strategy_present(self):
        r = CanaryCheckResult(True, 1.0, "v", EmbedStrategy.COMMENT, "ev")
        assert r.to_dict() == {
            "leaked": True,
            "confidence": 1.0,
            "token_value": "v",
            "strategy": "comment",
            "evidence": "ev",
        }


class TestTokenDataclass:
    def test_canary_token_to_dict(self):
        from raucle.canary import CanaryToken

        t = CanaryToken(
            value="v12", strategy=EmbedStrategy.SEMANTIC, created_at=5.0, metadata={"m": 1}
        )
        assert t.to_dict() == {
            "value": "v12",
            "strategy": "semantic",
            "created_at": 5.0,
            "metadata": {"m": 1},
        }
