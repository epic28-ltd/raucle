# Raucle glossary

One line per term, in plain words. Link here from the first use of a term.

- **Capability token**: a signed record naming one agent, one tool, the argument limits, and an expiry. The agent presents it to the gate.
- **Attenuation**: minting a child token from a parent token with equal or narrower permissions. The child can shorten the lifetime or shrink the scope, and can never widen either.
- **Content-addressed**: identified by the cryptographic hash of the content. The same content always gives the same address, so a change in content changes the address.
- **SMT (satisfiability modulo theories)**: automated reasoning over formulas with domains such as numbers, strings and sets. A solver decides whether a formula can be made true, and produces an example when it can.
- **Z3**: Microsoft's open-source SMT solver. raucle's prover uses Z3 to prove a tool's policy holds for every input a tool's schema allows, or returns a breaking input.
- **Lean 4**: a proof assistant (a programming language for writing machine-checked proofs). The gate's soundness theorems are mechanised in Lean 4 under `paper/lean/`.
- **Ed25519**: a well-known, fast digital signature scheme. raucle signs receipts, tokens and checkpoints with it by default.
- **ML-DSA-65**: NIST's post-quantum lattice signature scheme (FIPS 204). raucle can pair it with Ed25519 so a receipt verifies only when both signatures verify.
- **Merkle (root/tree)**: a construction where the hash of many records is folded into one root hash. One signed root commits to the whole set, so tampering with any record changes the root.
- **Fail-closed**: the behaviour where a missing, malformed or unverifiable input leads to refusal. raucle's gate denies when it cannot verify; it never defaults to allow.
- **Sidecar**: a separate process deployed beside the agent runtime, mediating traffic between the agent and the outside world. The gate can run as a sidecar so the agent process holds no authority.
- **MCP (Model Context Protocol)**: an open protocol for connecting models to tools and data sources. raucle gates MCP tool calls at its gateway or through framework adapters.
