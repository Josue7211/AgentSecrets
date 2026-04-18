# V4 Loop 0 Policy Engine Maturity

Goal: evolve the broker from simple allow/deny checks into a richer policy engine over action, target, actor, environment, and risk.

Scope:
- richer policy model
- actor and environment inputs
- risk scoring and policy explanation
- stronger test coverage for policy decisions

Out of scope:
- hardware-backed identity
- full governance workflow tooling

Implementation order:

1. Policy model expansion
- extend policy inputs beyond action and target into actor, environment, and risk signals
- define a policy evaluation model that produces allow, deny, require-approval, or step-up outcomes
- add explainable masked policy output for operator review

2. Storage and enforcement
- add structured policy configuration and evaluation wiring in the broker
- keep unsafe or unknown policy states fail closed
- add migration guidance for existing simple policy deployments

3. Verification and docs
- add unit and integration coverage for policy evaluation branches
- add docs for policy semantics, precedence, and safe defaults

Verification:
- policy unit tests
- broker integration tests for action, target, actor, environment, and risk combinations
- docs review for policy truth and default behavior

Acceptance:
- policy decisions can account for action, target, actor, environment, and risk
- policy behavior remains explainable and fail-closed
- existing deployments have a documented migration path

