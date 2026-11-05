# 1. Hello, receipt

**Time: 5 min · Pre-req: Python 3.10+**

By the end of this tutorial you will have:

- generated an Ed25519 keypair,
- minted a capability token,
- run the gate against a tool call,
- produced a signed receipt,
- and verified that receipt's signature from the command line.

No agent framework. No LLM. No network. Just the gate and the primitives.

---

## Step 1 — install

```bash
pip install 'raucle[compliance]'
```

The `[compliance]` extra pulls in `cryptography`, which the capability tokens, signed audit chain, and receipts all depend on.

(If `pip` complains about Python version, ensure you're on 3.10 or newer.)

---

## Step 2 — generate an issuer keypair

Issuers mint capability tokens. In production, you'd run one issuer per platform team (KYC platform, payments platform, etc.). For this tutorial we generate one inline.

Create `hello_receipt.py`:

```python
from raucle.capability import CapabilityIssuer, CapabilityGate

# An issuer + its keypair. In production, persist this PEM somewhere
# safe (HashiCorp Vault, AWS KMS-wrapped, etc.). For this tutorial,
# we keep it in memory.
issuer = CapabilityIssuer.generate(issuer="acme.bank.kyc")
print(f"issuer    : {issuer.issuer}")
print(f"key id    : {issuer.key_id}")
print(f"public pem: {issuer.public_key_pem[:64]}...")
```

Run it:

```bash
python3 hello_receipt.py
```

You should see your issuer identity and the first 64 chars of the Ed25519 public key.

---

## Step 3 — mint a capability token

A capability token authorises *one agent* to call *one tool*, subject to constraints.

Add to your script:

```python
token = issuer.mint(
    agent_id="agent:kyc-prod",
    tool="lookup_customer",
    constraints={
        # "Only look up customer IDs that start with C-"
        "starts_with": {"customer_id": "C-"},
    },
    ttl_seconds=60,  # token expires in 60 seconds
)
print(f"\ntoken: {token}")
```

Re-run. You'll see a JSON-encoded token with `issuer`, `agent_id`, `tool`, `constraints`, `nbf`, `exp`, `signature`, and a few other fields.

The token is **signed by the issuer's private key**. Tampering with any field invalidates the signature; the gate will reject it.

---

## Step 4 — build a gate

The gate enforces tokens. It needs to know which issuers' public keys it trusts.

```python
gate = CapabilityGate(
    trusted_issuers={issuer.key_id: issuer.public_key_pem},
)
```

A gate in production is configured with the public keys of *every* trusted issuer in your organisation. An unknown issuer's tokens are rejected automatically.

---

## Step 5 — check a tool call

The agent suggests it wants to call `lookup_customer` with a specific argument. The gate decides whether to allow it:

```python
decision = gate.check(
    token,
    tool="lookup_customer",
    agent_id="agent:kyc-prod",
    args={"customer_id": "C-1042"},
)
print(f"\nallowed : {decision.allowed}")
print(f"reason  : {decision.reason}")
```

This should print `allowed : True`.

Now try a call that violates the constraint:

```python
bad_decision = gate.check(
    token,
    tool="lookup_customer",
    agent_id="agent:kyc-prod",
    args={"customer_id": "X-9999"},  # doesn't start with "C-"
)
print(f"\nallowed : {bad_decision.allowed}")
print(f"reason  : {bad_decision.reason}")
```

`allowed : False` with a reason explaining which constraint failed.

---

## Step 6 — emit a signed receipt

Receipts are the audit artefact. Each decision is appended to a hash-chained, append-only log: every record links to the previous record's hash, and the chain is anchored by periodic Ed25519-signed checkpoints (written every `checkpoint_every` records and on close). Tampering with any past record breaks the chain.

```python
import hashlib, json
from raucle.audit import HashChainSink, Ed25519Signer

signer = Ed25519Signer.generate()
sink = HashChainSink("./receipts.log", signer=signer)

# Hash the call args locally so the receipt records *what* was inspected
# without leaking the argument values themselves.
args = {"customer_id": "C-1042"}
args_hash = (
    "sha256:"
    + hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
)

# Append a receipt for the ALLOW above:
record = sink.append(
    {
        "agent_id": "agent:kyc-prod",
        "tool": "lookup_customer",
        "decision": "ALLOW" if decision.allowed else "DENY",
        "reason": decision.reason,
        "args_hash": args_hash,
        "policy_proof_hash": token.policy_proof_hash,
        "issuer": issuer.issuer,
        "key_id": issuer.key_id,
    }
)

print(f"\nrecord index: {record['index']}")
print(f"record hash : {record['hash']}")
print(f"prev hash   : {record['prev_hash']}")

# Flush a signed checkpoint and close the file.
sink.close()
```

A new file `receipts.log` exists in your directory. Each line is one hash-chained record (with `index`, `timestamp`, `prev_hash`, `event`, and `hash`). The file is **append-only and hash-chained**: each row's hash includes the previous row's hash, so tampering anywhere shows up immediately. The Ed25519 signature lives in the periodic *checkpoint* records — signing is per-checkpoint, not per-record.

---

## Step 7 — verify offline

This is the bit that matters: anyone with the chain + the signer's public key can verify it, without contacting raucle or your platform.

First, write the signer's public key to a PEM file (add this to your script, before `sink.close()`):

```python
with open("audit_pub.pem", "wb") as f:
    f.write(signer.public_key_pem())
```

Then verify the chain from the command line:

```bash
raucle audit verify receipts.log --pubkey audit_pub.pem
```

(In a real flow, you'd publish the signer's public key alongside the chain and the verifier loads it once. The verifier never needs the private key or any network access.)

A valid chain returns exit code 0 and prints a report:

```
Audit chain: VALID
  Events:               1
  Checkpoints:          1
  Valid signatures:     1
  Invalid signatures:   0
```

---

## What you've built

A working **gated tool-call pipeline** with cryptographic accountability:

- **Capability token** — signed authorisation, agent-scoped, time-bounded, constraint-bound.
- **Gate** — enforces tokens. Sub-100 µs per check.
- **Receipt** — signed record of the decision. Hash-chained log. Verifiable offline.

The receipt is your audit artefact. Whatever you build on top — Microsoft Agent Framework, LangChain, AutoGen, custom — emits one of these per tool call.

---

## Where next

- **[2. Agent Framework integration](02-agent-framework.md)** — wire the gate into Microsoft Agent Framework's middleware chain.
- **[3. Prove a policy](06-prove-a-policy.md)** — turn `constraints={...}` into a *proof* that no string in the tool's schema can violate the policy.
- **[Spec index](../spec/README.md)** — the receipt and provenance formats, in detail.

If you want a system-of-record for the receipts you just produced — search, share with auditors, audit-pack export — [Raucle Cloud](https://cloud.raucle.com) hosts that.
