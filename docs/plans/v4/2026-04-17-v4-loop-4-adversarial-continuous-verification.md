# V4 Loop 4 Adversarial Continuous Verification

Goal: continuously run replay, injection, transcript-leak, and boundary-violation scenarios so claims degrade only when the evidence says they should.

Scope:
- continuous adversarial regression suites
- seeded canary secret strategy
- scheduled and PR-safe verification lanes
- evidence handling for adversarial failures

Out of scope:
- uncontrolled chaos against production
- unsupported host paths without stable fixtures

Implementation order:

1. Adversarial suite design
- define replay, prompt-injection, transcript-echo, malformed-ingress, and cross-target misuse scenarios
- seed deterministic canary secrets and boundary markers into the test harness
- classify which adversarial checks run on PRs and which run on schedules

2. Continuous execution
- wire adversarial suites into CI and scheduled verification
- capture redact-safe artifacts and summaries for failures
- add policy for how adversarial failures downgrade claims or block releases

3. Operations feedback loop
- feed adversarial findings into docs, support matrices, and ship gates
- track recurring regressions and required remediations

Verification:
- PR-safe adversarial regression lane
- scheduled extended adversarial lane
- evidence review on any failure

Acceptance:
- replay, injection, transcript-leak, and boundary-violation scenarios run continuously
- failures produce safe evidence and block or downgrade claims as defined
- claim strength is tied to ongoing verification, not one-time test success

