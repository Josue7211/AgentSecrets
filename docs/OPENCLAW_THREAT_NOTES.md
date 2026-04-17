# OpenClaw Threat Notes

These notes cover the documented OpenClaw host path only. It remains `preview` until Task 2 adds OpenClaw-specific identity evidence. Anything outside the documented broker HTTP contract remains untrusted and out of scope.

## Sink classification

- Transcript sink: OpenClaw stdout, stderr, console logs, and crash dumps.
- Log sink: structured logs, access logs, request logs, retry logs, and error telemetry.
- Tool-call sink: request bodies, approval payloads, execution payloads, and any adapter-facing payloads.
- Failure sink: exception text, network retry traces, timeout handling, and circuit-breaker output.

All of those sinks are untrusted. They must only contain masked data, opaque refs, request ids, and other broker-issued non-plaintext values.

## Trusted-input path

- OpenClaw may start a trusted-input session, but only the broker can mint the `tir://session/<id>` opaque ref.
- The trusted host-input surface is the only place where plaintext secret entry is allowed.
- Completion retries must not change `request_type`, `action`, or `target`.
- If the completion token is reused, expect `trusted_input_consumed`.
- If the request context changes, expect `trusted_input_context_mismatch`.

## Approval payloads

- Approval payloads shown in OpenClaw must stay masked.
- The payload may include request type, action, target, masked secret ref, and reason.
- Approval payloads must never show plaintext provider refs or secret values.
- Replaying an approval payload should not expose additional secret material.

## Execution payloads

- OpenClaw must send the approved `id`, `capability_token`, `action`, and `target`.
- Capability tokens are one-time and must not appear in cleartext logs or crash traces.
- Adapter results must be masked and must not echo plaintext secret values.
- If action or target drifts after approval, execution must fail closed.

## Retries and failures

- Retry the broker request, not the plaintext secret entry.
- If a request fails before completion, start a new trusted-input session instead of reusing the failed host-side payload.
- If approval is denied, discard any pending capability state.
- If execution fails, keep the failure payload redacted and preserve the broker audit trail.
- Do not widen the host trust boundary to make retry handling easier.

## Certification note

OpenClaw is preview only for the documented host path and only while the OpenClaw E2E lane stays green. If the lane regresses, keep OpenClaw at `preview` until the evidence is restored and host-specific identity evidence exists.
