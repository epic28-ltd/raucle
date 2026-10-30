# Verifiable enforcement: the pattern everyone else left out

Draft for Craig's review (agent-authored, 30 October 2026, humanizer pass
applied). Not published anywhere yet; Craig approves and posts.

Every agent-security product on the market enforces inside its own box. The
gate is theirs, the logs are theirs, and when an incident lands the answer to
"what did the agent actually do?" is whatever their product says it did. The
buyer notices this at exactly the wrong moment: during the incident, or
during the audit, when the vendor's own log is the only witness.

We shipped the opposite pattern in raucle, and this note shows it working.

## The pattern

Three properties, each independently checkable:

1. **Every decision is a receipt.** Allow and deny both. A denial carries
   the acting identity, the rule that produced it (by stable id, since
   v0.23.3-era audit work), the reason, and when the call came in under
   delegated authority, the full chain of grants from root to the caller.
2. **The receipts are chained and signed.** Each one hashes the record
   before it, and the whole chain is signed with an Ed25519 key the
   operator holds. Editing history breaks the hash chain; forging a
   record breaks the signature.
3. **Anyone can verify the chain offline.** The verifier is public code
   with no network requirement. A regulator, an auditor, or the other
   party in a dispute needs the chain file and the public key. They do
   not need a raucle account, a raucle server, or raucle's word for
   anything.

Property 3 is the one the market is missing. The YC cohort we surveyed in
October 2026 (OneCLI, Alter, Agentic Fabriq, Clawvisor, and roughly twenty
newer names) vaults credentials, gate actions and monitor traffic, and every
one of them reports through its own log. A newer crop (Asqav, Obsigna,
Signet) has started shipping receipt-like artefacts, which we take as
validation of the category. None of them binds a per-call decision to a
delegation chain an outsider can replay. The FSB told financial institutions
in October 2026 to be able to show "whether it acted within its permissions
throughout this chain of steps"; a vendor-held log cannot show that, because
the verifier and the verified are the same party.

## The demo, real output

Two tool calls cross the gate: one allowed (account ACC-001 is in policy),
one denied (ACC-999 is not). Both land in the chain. One command verifies:

```console
$ raucle provenance verify receipts.jsonl --pubkeys gate-pubkey.pem
Provenance chain: VALID
  Receipts:                  2
  Signature failures:        0
  Parent-link failures:      0
  Taint monotonicity fails:  0
```

Now an attacker edits history: they open the first receipt, change the
recorded reason to something friendlier, and leave the signature exactly as
it was. The verifier runs again, same command, same key:

```console
$ raucle provenance verify tampered.jsonl --pubkeys gate-pubkey.pem
Provenance chain: INVALID
  Receipts:                  2
  Signature failures:        1
  Parent-link failures:      0
  Taint monotonicity fails:  0
  Tampered receipts:         1

Errors:
  - line 1: receipt_hash mismatch — record tampered
  - line 1: signature verification failed for agent_key_id=aa322dd84753ff23
```

The chain names the break, the line, and the key whose signature failed.
That is the whole pattern: the record defends itself, and the defence is
checkable by someone with no reason to trust us.

## What rides on it

Because the decision record is verifiable, everything downstream of it is
too:

- **Delegation.** A call made under attenuated authority binds the chain of
  grants that authorised it, and the verifier re-checks that every hop
  narrowed rather than widened (the narrowing invariant is enforced at mint
  time and re-verified offline).
- **Revocation.** A revocation is itself a signed receipt; a call made after
  its authority was revoked fails verification with the revoking line
  named.
- **Intent.** A receipt can bind the approved task intent and the verifier
  re-checks the action against it (v1.2 extension).
- **Harness findings.** A red-team harness reporting through raucle cites
  the receipt covering the tested request; a finding that misreports what
  the gate did fails verification.

## Try it

The verifier ships in the open-source core (Apache-2.0, PyPI `raucle`, and
the receipt format with test vectors under docs/spec/provenance/). If you
run agents through LangChain, CrewAI, AutoGen, the Microsoft Agent
Framework, AGT or QM, the adapters are public too.