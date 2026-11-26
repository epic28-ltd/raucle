# Consumer policy regression example

This fixture demonstrates a consumer-owned policy and scenario contract. The scenarios are evaluated against the exact bytes of `policies.yaml` through the Raucle gateway decision path.

## Scenario format

The JSON document has `version: 1` and a non-empty `scenarios` array. Each case supplies a unique ID, tool, agent ID, JSON object of arguments and expected decision (`allow`, `deny` or `escalate`). Optional source and destination fields narrow the rule match. Unknown fields and malformed values are refused.

The report binds the exact raw policy and scenario files and the versioned suite manifest by SHA-256, and records the immutable engine commit supplied to the action. It contains stable suite/scenario IDs, tool names and decisions, but never argument values or free-text reasons. Unsupported suites are listed explicitly.

## Consumer workflow

Grant only `contents: read` to the job. Pin the action itself and the engine independently to full immutable commit SHAs:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@<PINNED_CHECKOUT_COMMIT>
  - uses: epic28-ltd/raucle/.github/actions/policy-regression@<PINNED_ACTION_COMMIT>
    with:
      policy-file: examples/policy-regression-consumer/policies.yaml
      scenarios-file: examples/policy-regression-consumer/scenarios.json
      engine-ref: <PINNED_ENGINE_COMMIT>
      report-file: raucle-policy-regression-report.json
```

The action installs the engine from `engine-ref`, runs the offline regression runner and uploads the machine-readable report. Replace each placeholder with a reviewed immutable commit SHA before use.

## GitLab CI

GitLab can invoke the same versioned CLI after installing the engine from an immutable commit. Use `python -m raucle.policy_regression --policy ... --scenarios ... --engine-commit "$RAUCLE_ENGINE_COMMIT" --output raucle-policy-regression-report.json`, then publish the JSON report as a job artefact. There is no separate GitLab runner implementation or second policy-evaluation code path.

## Assurance boundary

This checks only the supplied deterministic scenarios against the supplied policy bytes. It does not exercise downstream tool side effects, a deployed identity provider, production infrastructure, every possible prompt injection or every agent runtime. It is not formal verification, a penetration test or a claim of complete agent security.
