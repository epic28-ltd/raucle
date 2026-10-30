# VCD-A2A discussion post (paste-ready draft for Craig)

Status: DRAFT for Craig's review. Nothing has been posted. Per the standing
rule, the agent drafts and Craig submits, after the LASR window (5-6 Nov)
per the 29 October sequencing note in vcd-a2a.md.

Suggested venue: the a2a-protocol.org working-group discussion area, or the
protocol's GitHub discussions. Humanizer pass applied; no em dashes.

---

Subject: Proposal discussion: capability discipline for A2A (verifiable,
per-call authorisation receipts)

Hi all,

We have been watching the authorisation question in A2A since the GA, and
the published security analysis names the problem well: authorisation creep.
OAuth 2.0 authenticates who is talking. Nothing in the protocol says what a
given skill call is allowed to do, or lets the other side check afterwards
that the call stayed inside those bounds.

We think the slot is open for a small, optional extension, and we have a
working reference implementation to show rather than a slide deck. The short
version:

1. Each A2A skill call can carry a capability receipt: a signed, content-
   addressed record of the attenuated grant that authorised the call, with
   the constraints that applied and the decision made.
2. Grants attenuate: a child capability can only narrow its parent (shorter
   lifetime, smaller scope, never wider). The narrowing invariant is
   enforced at mint time and re-verified offline on replay.
3. The receipts chain, and anyone can verify the chain offline with the
   public key and an open-source verifier. No vendor account, no vendor
   server, no need to trust the party that made the decision.

The receipts format (v1.2) is public with test vectors, and the verifier
runs on a chain file and a PEM. Things it re-checks offline, with no network:
signature validity, parent links, that every delegation hop narrowed, that
revocations propagate, and since last month that a call stayed inside its
approved task intent (an approval to check today's calendar cannot cover a
five-year export, and the verifier names the break).

Why we are posting here rather than just shipping it: there are four design
questions where working-group judgement matters more than our preference,
and they are in the proposal's open-questions section. The two we care most
about:

- Should the receipt ride as a top-level JSON-RPC envelope field or scoped
  under params._meta? Conservative says _meta; discoverability says
  top-level.
- Is there appetite for a mandatory receipt profile for skills tagged
  regulated: true? Banking and healthcare A2A deployments keep asking for
  exactly this, and a profile that requires a receipt for those skills
  would give them a standards answer instead of a vendor promise.

Full proposal with the wire format, the threat-model deltas and the
reference implementation milestones:

https://github.com/epic28-ltd/raucle/blob/main/docs/proposals/vcd-a2a.md

Receipt format specs and test vectors:

https://github.com/epic28-ltd/raucle/tree/main/docs/spec/provenance

Happy to demo the two-agent cross-boundary case with live verification at a
working-group call, or to take feedback here first.

Craig Allan-McWilliams
Epic28 Ltd
raucle.com