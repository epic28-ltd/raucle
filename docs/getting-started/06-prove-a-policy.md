# 5. Prove a policy

**Time: 10 min · Pre-req: `pip install 'raucle[proof]'` (pulls Z3)**

Every other product in this space says "we have policies." Raucle's policies can be **proven**: an SMT solver decides whether *every string the tool's JSON Schema admits* satisfies the policy, or produces a concrete counterexample call as the refutation.

By the end of this tutorial you will have:

- written a tool's JSON Schema,
- written a policy over that schema (forbidden values, max amount, required fields),
- proven the policy holds with `JSONSchemaProver`,
- extracted a counterexample when it doesn't,
- minted a capability token citing the proof's content-address,
- produced a receipt that an auditor can verify *and* re-prove offline.

---

## Why this matters

A configured policy says "we set max_value to 10000."
A proven policy says "no input satisfying the JSON Schema can exceed 10000, regardless of the LLM's intent or the attacker's prompt — here is the SMT proof, content-addressed, citeable, re-checkable offline."

The difference is what an auditor needs.

---

## Step 1 — install with the proof extra

```bash
pip install 'raucle[proof,compliance]'
```

`[proof]` pulls in `z3-solver` (Microsoft Research's SMT solver) for the prover. `[compliance]` pulls in `cryptography`, which Step 6 needs to mint a capability token citing the proof. Both compose with `[agent-framework]` and the other extras.

---

## Step 2 — define the tool's JSON Schema

A `lookup_customer` tool that takes a customer ID, a service tier, and an optional amount:

```python
schema = {
    "type": "object",
    "properties": {
        "customer_id": {
            "type": "string",
            "pattern": "^C-[0-9]+$",  # must start C- followed by digits
        },
        "tier": {
            "type": "string",
            "enum": ["bronze", "silver"],
        },
        "amount": {
            "type": "integer",
            "minimum": 0,
            "maximum": 10000,
        },
    },
    "required": ["customer_id"],
}
```

The prover reads this. It understands top-level `type: object` with `properties`, plus per-property `string` (with `enum`), `integer` / `number` (with `minimum` / `maximum`), `boolean`, and `required`. Properties of unsupported types (e.g. `array`) raise `UnsupportedGrammar` — the prover refuses to silently over-approximate.

---

## Step 3 — write the policy

We never want the `platinum` tier reachable, and `amount` must never exceed 10000:

```python
policy = {
    # The "platinum" tier must never appear.
    "forbidden_values": {
        "tier": ["platinum"],
    },
    # amount can never exceed 10000.
    "max_value": {
        "amount": 10000,
    },
}
```

`forbidden_values` and `max_value` are two of the supported policy forms. Others:

- `min_value`: numeric lower bounds.
- `required_present`: fields that must be present.
- `forbidden_field_combinations`: field tuples that must not co-occur.

---

## Step 4 — prove it

```python
from raucle.prove import JSONSchemaProver

prover = JSONSchemaProver(timeout_ms=5000)
result = prover.prove(schema=schema, policy=policy)

print(f"status            : {result.status}")  # PROVEN | REFUTED | UNDECIDED
print(f"prover            : {result.prover} {result.prover_version}")
print(f"grammar hash      : {result.grammar_hash}")
print(f"policy hash       : {result.policy_hash}")
print(f"content-address   : {result.hash}")
```

Expected output (hashes will match exactly for this schema + policy):

```
status            : PROVEN
prover            : JSONSchemaProver jsonschema-prover/v1
grammar hash      : sha256:9b67b33866ee5ce44bbf7e44db83a21038f81b6d0aaf9792e321b77b227742a0
policy hash       : sha256:3861bf6b6deccdd364d9ff25b14ec08c385abbc14003fcf768b432ab071503f2
content-address   : sha256:cf33127dfc032a7dba26ae7736a0e40152580baa38f3f3f4647360030012cca1
```

That `content-address` is what your tokens cite. It's a hash over the (status, prover, grammar_hash, policy_hash, counterexample, notes) tuple — content-addressed, deterministic, citeable in receipts.

---

## Step 5 — break it on purpose

Drop the `enum` constraint on `tier` so the schema admits arbitrary strings, but keep the policy forbidding `"platinum"`:

```python
schema["properties"]["tier"].pop("enum")

result = prover.prove(schema=schema, policy=policy)
print(f"status            : {result.status}")
if result.status == "REFUTED":
    print("counterexample    :")
    print("  ", result.counterexample)
```

Output:

```
status            : REFUTED
counterexample    :
   {'customer_id': '', 'tier': 'platinum', 'amount': 0}
```

The prover **constructed a concrete call** that satisfies the schema but violates the policy. This is the counterexample you'd hand to whoever wrote the schema — it's actionable, not abstract.

(With the `enum` constraint back in place, `tier` can only be `"bronze"` or `"silver"`, so no schema-valid call admits `"platinum"` and the policy is provably watertight.)

---

## Step 6 — cite the proof in a capability token

A token cites the proof by its content-address:

```python
from raucle.capability import CapabilityIssuer

issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")

# Re-prove with the enum in place
schema["properties"]["tier"]["enum"] = ["bronze", "silver"]
result = prover.prove(schema=schema, policy=policy)

token = issuer.mint(
    agent_id="agent:kyc-prod",
    tool="lookup_customer",
    constraints={
        "forbidden_values": {"tier": ["platinum"]},
    },
    ttl_seconds=300,
    policy_proof_hash=result.hash,  # <— cites the proof
)
```

Every receipt emitted under this token carries `policy_proof_hash` pointing at `result.hash`. Downstream, an auditor:

1. Fetches the receipt.
2. Fetches the published proof artefact at that hash from the issuer's policy registry.
3. Verifies the receipt's signature.
4. Re-runs the proof on their own Z3 to confirm soundness.
5. Inspects the cited Lean theorem (`VCD.TokenCitingProofConforms`) which says: *if a token cites a proof of a policy P over schema S, every call the gate accepts under that token satisfies P.*

That's the full chain. The receipt is provable, not merely declared.

---

## Step 7 — publish the proof

For an auditor to do step 2 above, the proof has to be reachable. Dump the full `ProofResult` to a file (the auditor re-proves from the same `schema` + `policy` and confirms the hash matches):

```python
import json

artefact = result.to_dict()  # status, prover, hashes, counterexample, content-address
with open(f"{result.hash.replace(':', '_')}.json", "w") as f:
    json.dump(artefact, f, indent=2)

print("published proof artefact:", result.hash)
```

You can also drive the whole prove step from the command line, which is the form most CI pipelines use. Put the schema and policy in files and run:

```bash
raucle prove json --schema schema.json --policy policy.json
```

```
PROVEN  prover=JSONSchemaProver  hash=sha256:cf33127dfc032a7dba26ae7736a0e40152580baa38f3f3f4647360030012cca1
```

Exit code is `0` for PROVEN, `2` for REFUTED (the counterexample prints to stderr), `1` for UNDECIDED — so a CI gate can simply check the exit status.

Now any receipt citing that hash points at a reachable artefact. (We're skipping the issuer-signature on the proof file for tutorial brevity.)

If you're using [Raucle Cloud](https://cloud.raucle.com), the registry is hosted for you and the URL is auto-populated into every receipt's `verification_pointers.policy_registry`.

---

## What you've built

A policy that is **structurally enforced**, not configured. The auditor can re-prove it without trusting raucle. The cite-chain — token → proof artefact → Lean theorem — is what makes the difference between "we set max_value=10000" and "we hold a proof that max_value=10000 is satisfied for every well-formed call."

---

## Where next

- **`URLPolicyProver`** — same idea, for URL allowlists (`raucle prove url`): require_https, host_allowlist with wildcards, max_path_depth.
- **`SQLClauseProver`** — a **finite SQL-template checker over a modelled subset** (`raucle prove sql`): forbidden_tokens, allowed_tables. Not a general SQL prover — a template using a construct outside the modelled subset (quoted identifiers, `LATERAL`/`UNNEST`/`VALUES`, recursive CTEs, table functions) returns **UNDECIDED** rather than PROVEN.
- **[Paper draft](../../paper/DRAFT.md)** — the soundness theorems backing the prover (`VCD.GateAllowImpliesPolicy`, `VCD.TokenCitingProofConforms`).

If you'd rather author policies in a UI with a live "Prove" button and a counterexample browser, that's [Raucle Cloud's](https://cloud.raucle.com) Policies workspace (phase 5b — shipping shortly).
