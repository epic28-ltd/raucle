"""Framework-agnostic middleware for integrating raucle into LLM pipelines.

Provides pre/post processing hooks and event callbacks for scanning user
inputs, LLM outputs, and tool calls.

    from raucle.middleware import RaucleMiddleware

    mw = RaucleMiddleware(on_block=lambda r, phase: print(f"Blocked in {phase}"))
    prompt, result = mw.pre_process("Ignore all previous instructions", session_id="s1")
    output, result = mw.post_process("Here is the answer", session_id="s1")
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from raucle.redaction import RedactionResult, redact_text, wired_redaction_classes
from raucle.scanner import Scanner, ScanResult
from raucle.session import SessionScanner, SessionScanResult

logger = logging.getLogger(__name__)

_DEFAULT_SESSION_TTL = 3600  # seconds — idle sessions older than this are evicted

#: Harness label on every advisory finding this middleware emits.
ADVISORY_HARNESS = "middleware-advisory"


def _fail_open_result(_scanned_text: str) -> ScanResult:
    """A clean ALLOW fallback used when the advisory layer fails open.

    The digest of the passed-through content is deliberately NOT
    attached here: the content was not scanned, so claiming a clean
    verdict is the honest statement and nothing more is recorded.
    """
    return ScanResult(
        verdict="CLEAN",
        confidence=0.0,
        injection_detected=False,
        action="ALLOW",
        notes=["middleware failed open: content passed through unscanned"],
    )


class RaucleMiddleware:
    """Framework-agnostic middleware for integrating raucle into LLM pipelines.

    Provides pre/post processing hooks and event callbacks.

    The middleware is an ADVISORY layer by construction: it observes,
    redacts (when configured) and reports. It never blocks a call and
    never mints gate receipts; enforcement authority lives in the
    deterministic gate, not here. Failure inside the advisory layer is
    fail-open by design (logged, never raised into the agent loop) — in
    deliberate contrast to the gate, which is fail-closed.

    Parameters
    ----------
    mode : str
        Detection sensitivity mode.
    rules_dir : str, optional
        Path to custom YAML rules directory.
    on_alert : callable, optional
        Callback fired when a scan produces an ALERT verdict.
        Signature: ``(result, phase) -> None`` where *phase* is
        ``"pre_process"``, ``"post_process"``, or ``"pre_tool_call"``.
    on_block : callable, optional
        Callback fired when a scan produces a BLOCK verdict.
        Same signature as *on_alert*.
    session_enabled : bool
        Whether to track session state across calls.
    window_size : int
        Rolling window size for session tracking.
    session_ttl : int
        Seconds of inactivity after which a session is automatically evicted.
        Defaults to 3600 (1 hour).  Set to 0 to disable TTL eviction.
    redaction_classes : list[str], optional
        ADVISORY data-plane redaction classes (EPIC Q, Q-7c). When set,
        ``post_process`` replaces matched spans in assistant responses
        with ``[REDACTED:<class>]`` collars before handing the text back
        into the agent loop, and ``pre_tool_call`` redacts tool argument
        text recorded into the session window. Default: ``None`` —
        redaction is OFF and hooks stay byte-compatible. Classes are
        aligned with the x_dlp matched-class vocabulary (a subset:
        ``pii_card``, ``pii_email``, ``pii_national_id``, ``secret_bearer``);
        unknown classes are refused at configuration time.
    gateway : object, optional
        A gateway client reference exposing ``emit_finding(**kwargs)``.
        When wired, the middleware emits bounded-disclosure advisory
        findings (harness ``middleware-advisory``) through it, best
        effort: emission failures are logged and swallowed. Default
        ``None`` — no findings are emitted. A finding is emitted only
        when a receipt citation is bound for the call (see
        ``record_trace_receipt``): the offline verifier refuses findings
        that cite a receipt not in the chain, so uncited redactions are
        logged locally instead of minted as unverifiable evidence.
    """

    def __init__(
        self,
        mode: str = "standard",
        rules_dir: str | None = None,
        on_alert: Callable[[ScanResult | SessionScanResult, str], None] | None = None,
        on_block: Callable[[ScanResult | SessionScanResult, str], None] | None = None,
        session_enabled: bool = True,
        window_size: int = 20,
        session_ttl: int = _DEFAULT_SESSION_TTL,
        redaction_classes: list[str] | None = None,
        gateway: Any = None,
    ) -> None:
        if redaction_classes is not None:
            unknown = [c for c in redaction_classes if c not in wired_redaction_classes()]
            if unknown:
                raise ValueError(
                    f"unknown redaction class(es) {unknown!r}; wired classes are "
                    f"{wired_redaction_classes()}"
                )
        self.scanner = Scanner(mode=mode, rules_dir=rules_dir)
        self.on_alert = on_alert
        self.on_block = on_block
        self._sessions: dict[str, SessionScanner] = {}
        self._session_last_seen: dict[str, float] = {}
        self._session_enabled = session_enabled
        self._window_size = window_size
        self._mode = mode
        self._session_ttl = session_ttl
        self._redaction_classes = list(redaction_classes) if redaction_classes else None
        self._gateway = gateway
        self._trace_receipts: dict[str, tuple[str, str]] = {}

    def record_trace_receipt(self, trace_id: str, receipt_id: str, decision: str) -> None:
        """Bind a gate receipt to a trace so advisory findings can cite it.

        The integration that runs the gate (and this middleware) calls
        this after a gated tool call so a later ``post_process`` /
        ``pre_tool_call`` with the same ``trace_id`` can cite the
        RELATED gate receipt in its advisory finding. The recorded
        decision is reported as the finding's ``actual_decision``; the
        offline verifier re-checks it against the cited receipt, so a
        mistracked decision fails verification rather than lying.
        """
        self._trace_receipts[trace_id] = (receipt_id, decision)

    def clear_trace_receipt(self, trace_id: str | None = None) -> None:
        """Drop one trace binding, or all bindings when *trace_id* is None."""
        if trace_id is None:
            self._trace_receipts.clear()
        else:
            self._trace_receipts.pop(trace_id, None)

    def get_session(self, session_id: str) -> SessionScanner:
        """Get or create a session scanner for the given ID.

        Evicts stale sessions on each access when TTL is enabled.
        """
        self._evict_stale_sessions()
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionScanner(
                scanner=self.scanner,
                window_size=self._window_size,
                mode=self._mode,
            )
        self._session_last_seen[session_id] = time.monotonic()
        return self._sessions[session_id]

    def active_session_count(self) -> int:
        """Return the number of currently tracked sessions."""
        return len(self._sessions)

    def _evict_stale_sessions(self) -> None:
        """Remove sessions that have been idle longer than *session_ttl* seconds."""
        if not self._session_ttl:
            return
        now = time.monotonic()
        stale = [
            sid for sid, last in self._session_last_seen.items() if now - last > self._session_ttl
        ]
        for sid in stale:
            self._sessions.pop(sid, None)
            self._session_last_seen.pop(sid, None)

    def pre_process(
        self,
        prompt: str,
        session_id: str | None = None,
    ) -> tuple[str, ScanResult | SessionScanResult]:
        """Scan user input before it reaches the LLM.

        Returns the (unchanged) prompt and the scan result.
        Fires on_alert/on_block callbacks as appropriate.
        """
        if self._session_enabled and session_id is not None:
            session = self.get_session(session_id)
            result: ScanResult | SessionScanResult = session.scan_message(prompt, role="user")
            action = result.session_action
        else:
            scan_result = self.scanner.scan(prompt)
            result = scan_result
            action = scan_result.action

        self._fire_callbacks(result, action, "pre_process")
        return prompt, result

    def post_process(
        self,
        output: str,
        original_prompt: str | None = None,
        session_id: str | None = None,
        trace_id: str | None = None,
    ) -> tuple[str, ScanResult | SessionScanResult]:
        """Scan LLM output before it's returned to the user.

        With ``redaction_classes`` configured, matched spans are replaced
        with ``[REDACTED:<class>]`` collars and the REDACTED text is what
        is handed back to the adapter consumer. Without configuration the
        output is returned byte-identical. The whole hook is fail-open:
        a scan or advisory failure yields the original output with a
        clean result and never raises into the agent loop.

        Returns the (possibly redacted) output and the scan result.
        """
        try:
            if self._session_enabled and session_id is not None:
                session = self.get_session(session_id)
                result: ScanResult | SessionScanResult = session.scan_message(
                    output, role="assistant"
                )
                action = result.session_action
            else:
                scan_result = self.scanner.scan_output(output, original_prompt=original_prompt)
                result = scan_result
                action = scan_result.action

            self._fire_callbacks(result, action, "post_process")
            return self._post_process_redaction(output, trace_id), result
        except Exception:
            logger.warning(
                "advisory middleware post_process failed open: content passed "
                "through unscanned (this layer has no enforcement authority)",
                exc_info=True,
            )
            return output, _fail_open_result(output)

    def _post_process_redaction(self, output: str, trace_id: str | None) -> str:
        """Advisory data-plane redaction plus finding emission, best effort."""
        if not self._redaction_classes or not output:
            return output
        rr = redact_text(output, self._redaction_classes)
        if not rr.span_counts:
            return output
        citation = self._resolve_citation(trace_id)
        if citation is not None:
            self._emit_advisory_findings(
                rr, phase="post_process", tool="assistant_response", citation=citation
            )
        else:
            logger.info(
                "middleware-advisory redaction without a trace citation: "
                "counts=%s content_sha256=%s (no receipted finding, the "
                "verifier refuses uncited findings)",
                rr.span_counts,
                rr.content_sha256,
            )
        return rr.redacted_text

    def pre_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str | None = None,
        trace_id: str | None = None,
    ) -> tuple[bool, ScanResult]:
        """Scan tool call before execution.

        Returns ``(allowed, result)`` where *allowed* is ``False`` when the
        scan produces a BLOCK action.

        The advisory layer never changes *allowed*: redaction
        configuration may redact the argument text recorded into the
        session window (so matched content does not accumulate in
        session state) and emit advisory findings, but the caller's
        argument dict is untouched and the decision stays the scanner's.
        Emission is best effort; a failure never breaks the hook.
        """
        result = self.scanner.scan_tool_call(tool_name, arguments)

        # If session tracking, also record in session
        if self._session_enabled and session_id is not None:
            session = self.get_session(session_id)
            # Serialize args for session tracking
            arg_text = " ".join(f"{k}={v}" for k, v in arguments.items())
            record_text = self._tool_arg_redaction(arg_text, tool_name, trace_id)
            session.scan_message(
                record_text,
                role="user",
                tool_name=tool_name,
                tool_args=arguments,
            )

        self._fire_callbacks(result, result.action, "pre_tool_call")
        allowed = result.action != "BLOCK"
        return allowed, result

    def _tool_arg_redaction(self, arg_text: str, tool_name: str, trace_id: str | None) -> str:
        """Advisory redaction of serialized tool arguments (best effort).

        Without redaction classes configured this is the identity
        function, so taint-tagging behaviour is byte-unchanged. With
        classes configured the matched spans are collared in the text
        recorded into the session window and an advisory finding is
        emitted when a citation is bound. The caller's argument dict is
        never modified.
        """
        if not self._redaction_classes or not arg_text:
            return arg_text
        try:
            rr = redact_text(arg_text, self._redaction_classes)
            if not rr.span_counts:
                return arg_text
            citation = self._resolve_citation(trace_id)
            if citation is not None:
                self._emit_advisory_findings(
                    rr, phase="pre_tool_call", tool=tool_name, citation=citation
                )
            return rr.redacted_text
        except Exception:
            logger.warning(
                "advisory middleware pre_tool_call redaction failed open: "
                "argument text recorded unredacted",
                exc_info=True,
            )
            return arg_text

    def _resolve_citation(self, trace_id: str | None) -> tuple[str, str] | None:
        """Return (receipt_id, decision) bound to *trace_id*, else None.

        No bound receipt means no finding: the offline verifier refuses
        findings that cite a receipt not in the chain, so an uncited
        finding would be unverifiable rather than advisory evidence.
        """
        if not trace_id or self._gateway is None:
            return None
        return self._trace_receipts.get(trace_id)

    def _emit_advisory_findings(
        self,
        rr: RedactionResult,
        *,
        phase: str,
        tool: str,
        citation: tuple[str, str],
    ) -> None:
        """Emit one bounded-disclosure finding per matched class.

        Best effort by contract: any gateway failure is logged and
        swallowed, never raised into the agent loop. Findings carry
        class names, span counts and sha256 digests only — never
        content — mirroring the x_dlp bounded-disclosure rule.
        """
        if self._gateway is None:
            return
        receipt_id, decision = citation
        for cls, count in sorted(rr.span_counts.items()):
            try:
                self._gateway.emit_finding(
                    harness=ADVISORY_HARNESS,
                    test_id=cls,
                    verdict="confirmed",
                    cited_receipt=receipt_id,
                    expected_decision="allow",
                    actual_decision=decision,
                    tool=tool,
                    args_digest=rr.content_sha256,
                    note=(
                        f"advisory {phase} redaction: {count} span(s) of {cls} "
                        f"collared; content_sha256={rr.content_sha256}; "
                        f"redacted_content_sha256={rr.redacted_content_sha256}; "
                        "bounded disclosure: digests and counts only, "
                        "never content"
                    ),
                )
            except Exception:
                logger.warning(
                    "advisory finding emission failed (fail-open): class=%s", cls, exc_info=True
                )

    def drop_session(self, session_id: str) -> None:
        """Remove a session from tracking."""
        self._sessions.pop(session_id, None)
        self._session_last_seen.pop(session_id, None)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fire_callbacks(
        self,
        result: ScanResult | SessionScanResult,
        action: str,
        phase: str,
    ) -> None:
        """Fire on_alert or on_block callbacks based on the action."""
        if action == "BLOCK" and self.on_block is not None:
            self.on_block(result, phase)
        elif action == "ALERT" and self.on_alert is not None:
            self.on_alert(result, phase)
