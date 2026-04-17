# Redaction Policy

This document defines the current redaction contract for the supported-host helper surfaces that this repo owns and tests today.

## Scope

In scope:

- the local supported-host helper used by the node-to-node harness
- helper transcript lines emitted to stdout and stderr
- helper-created untrusted log and artifact surfaces derived from those transcript lines

Out of scope:

- arbitrary external host runtimes
- retroactive cleanup of third-party transcript systems
- blanket redaction claims across every future integration

## Sink classification

Untrusted sinks:

- helper transcript lines written to stdout
- helper errors written to stderr
- artifact logs captured from helper stdout and stderr
- summary artifacts copied from those untrusted surfaces

Trusted control sinks:

- the local `RESULT_JSON=` control line consumed by the harness to continue the flow
- in-process Rust test state that never becomes a host transcript or untrusted artifact

The trusted control sink exists so the harness can keep driving the flow without teaching the untrusted transcript path about raw completion tokens or other bounded credentials.

## Current redaction rules

When the supported-host helper runs with `SECRET_BROKER_E2E_REDACTION_MODE=supported`, it must sanitize untrusted transcript output before emission.

Current redaction classes:

- seeded canary secret from `SECRET_BROKER_E2E_CANARY_SECRET`
- provider refs with the `bw://` prefix
- broker opaque refs with the `tir://session/` prefix
- capability tokens with the `sbt_` prefix
- trusted-input completion tokens with the `tit_` prefix

Current replacement semantics:

- canary secret: `[redacted:canary]`
- provider ref: `[redacted:provider-ref]`
- broker opaque ref: `[redacted:opaque-ref]`
- capability token: `[redacted:capability]`
- completion token: `[redacted:completion-token]`

## Failure semantics

Supported-host redaction is fail-closed.

If supported-host redaction is required and the helper cannot initialize the redaction hook, the helper must:

- exit non-zero
- report a redaction failure on stderr
- avoid emitting untrusted transcript lines first

The test harness uses `SECRET_BROKER_E2E_REDACTION_FORCE_FAILURE=1` to exercise that path.

## Current claim boundary

The repo can currently claim tested transcript and log redaction coverage only for the local supported-host helper path exercised by the harness.

It cannot yet claim:

- universal host transcript safety
- universal external log redaction
- protection for unsupported hosts or runtimes
