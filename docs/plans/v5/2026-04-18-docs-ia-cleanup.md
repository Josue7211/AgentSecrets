# Docs IA Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the repo docs into a durable information architecture with `ROADMAP.md` as roadmap truth, `docs/INDEX.md` as the human entrypoint, version-owned plan/backlog folders, and clear separation between product, architecture, operations, specs, and execution artifacts.

**Architecture:** This is a docs-only migration. Establish the new directory skeleton and entrypoints first, then move canonical docs into owned folders, then move planning artifacts into version buckets, then repair links and verify there is only one active source of truth per topic. Preserve filenames where possible and avoid renames unless a name is actively confusing.

**Tech Stack:** Markdown, shell file moves, ripgrep, git, existing docs tree

---

## File Structure Map

**Create directories:**
- `docs/product/`
- `docs/architecture/`
- `docs/operations/`
- `docs/specs/`
- `docs/plans/v2/`
- `docs/plans/v3/`
- `docs/plans/v4/`
- `docs/plans/v5/`
- `docs/plans/v6/`
- `docs/plans/v7/`
- `docs/plans/v8/`
- `docs/plans/v9/`
- `docs/plans/v10/`
- `docs/backlog/`
- `docs/backlog/v5/`
- `docs/backlog/v6/`
- `docs/backlog/v7/`
- `docs/backlog/v8/`
- `docs/backlog/v9/`
- `docs/backlog/v10/`
- `docs/archive/completed/`
- `docs/archive/superseded/`

**Create files:**
- `docs/INDEX.md`
- `docs/backlog/INDEX.md`

**Current canonical product docs:**
- `docs/product/ADAPTERS.md`
- `docs/product/IDENTITY_MODEL.md`
- `docs/product/INTEGRATION.md`
- `docs/product/PLATFORM_SUPPORT.md`
- `docs/product/PROVIDER_MEDIATION.md`
- `docs/product/QUICKSTART.md`
- `docs/product/REDACTION_POLICY.md`
- `docs/product/RELEASE.md`
- `docs/product/SECURITY_GUARANTEES.md`
- `docs/product/SUPPORTED_HOSTS.md`

**Current canonical architecture docs:**
- `docs/architecture/ARCHITECTURE.md`
- `docs/architecture/OPENCLAW.md`
- `docs/architecture/OPENCLAW_THREAT_NOTES.md`
- `docs/architecture/THREAT_MODEL.md`

**Current canonical operations docs:**
- `docs/operations/OPERATIONS.md`
- `docs/operations/TROUBLESHOOTING.md`

**Current plan artifacts:**
- `docs/plans/v2/2026-04-16-v2-loop-0-truth-reset.md`
- `docs/plans/v2/2026-04-17-v2-loop-1-secret-ingress-lockdown.md`
- `docs/plans/v2/2026-04-17-v2-loop-2-provider-isolation-contract.md`
- `docs/plans/v2/2026-04-17-v2-loop-3-execution-adapter-containment.md`
- `docs/plans/v2/2026-04-17-v2-loop-4-capability-and-approval-hardening.md`
- `docs/plans/v2/2026-04-17-v2-loop-5-memd-style-node-to-node-e2e-harness.md`
- `docs/plans/v2/2026-04-17-v2-loop-6-v2-ship-gate.md`
- `docs/plans/v3/2026-04-17-v3-loop-0-trusted-input-surface.md`
- `docs/plans/v3/2026-04-17-v3-loop-1-transcript-and-log-redaction-pipeline.md`
- `docs/plans/v3/2026-04-17-v3-loop-2-real-trusted-execution-adapters.md`
- `docs/plans/v3/2026-04-17-v3-loop-3-multi-host-support-matrix.md`
- `docs/plans/v3/2026-04-17-v3-loop-4-v3-ship-gate.md`
- `docs/plans/v4/2026-04-17-v4-loop-0-policy-engine-maturity.md`
- `docs/plans/v4/2026-04-17-v4-loop-1-attestation-and-runtime-identity.md`
- `docs/plans/v4/2026-04-17-v4-loop-2-tamper-evident-operations-and-forensics.md`
- `docs/plans/v4/2026-04-17-v4-loop-3-rotation-and-recovery-drills.md`
- `docs/plans/v4/2026-04-17-v4-loop-4-adversarial-continuous-verification.md`
- `docs/plans/v4/2026-04-17-v4-loop-5-platform-ship-gate.md`
- `docs/plans/v5/2026-04-17-post-v4-vision-completion.md`

**Current spec artifacts:**
- `docs/specs/2026-04-16-zero-trust-v2-v4-hardening-roadmap-design.md`
- `docs/specs/2026-04-17-zero-trust-v2-v4-remaining-loop-spec-pack.md`
- `docs/specs/2026-04-18-docs-information-architecture-design.md`

### Task 1: Create Entrypoints And Folder Skeleton

**Files:**
- Create: `docs/INDEX.md`
- Create: `docs/backlog/INDEX.md`
- Create: `docs/product/`
- Create: `docs/architecture/`
- Create: `docs/operations/`
- Create: `docs/specs/`
- Create: `docs/plans/v2/` through `docs/plans/v10/`
- Create: `docs/backlog/v5/` through `docs/backlog/v10/`
- Create: `docs/archive/completed/`
- Create: `docs/archive/superseded/`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Snapshot the current docs tree before moving anything**

```bash
find docs -maxdepth 3 -type d | sort
find docs -maxdepth 3 -type f | sort
```

Expected: current flat docs plus `docs/superpowers/plans` and `docs/superpowers/specs`.

- [ ] **Step 2: Create the target directory skeleton**

```bash
mkdir -p \
  docs/product \
  docs/architecture \
  docs/operations \
  docs/specs \
  docs/plans/v2 docs/plans/v3 docs/plans/v4 docs/plans/v5 docs/plans/v6 docs/plans/v7 docs/plans/v8 docs/plans/v9 docs/plans/v10 \
  docs/backlog/v5 docs/backlog/v6 docs/backlog/v7 docs/backlog/v8 docs/backlog/v9 docs/backlog/v10 \
  docs/archive/completed docs/archive/superseded
```

Expected: zero output, directories created.

- [ ] **Step 3: Write `docs/INDEX.md` as the human docs entrypoint**

```markdown
# Docs Index

This is the human entrypoint for the Secret Broker docs tree.

## Canonical Entrypoints

- Roadmap truth: [../ROADMAP.md](../ROADMAP.md)
- Release and claim authority: [product/RELEASE.md](product/RELEASE.md)
- Host support matrix: [product/SUPPORTED_HOSTS.md](product/SUPPORTED_HOSTS.md)
- Platform support matrix: [product/PLATFORM_SUPPORT.md](product/PLATFORM_SUPPORT.md)

## Folders

### Product

Shipping truth, release truth, support matrices, guarantees, and operator/user contracts.

### Architecture

System boundaries, threat model, host-specific architecture notes.

### Operations

Runbooks, operational guidance, and troubleshooting.

### Specs

Strategic design documents and design companions.

### Plans

Execution plans grouped by owning version.

### Backlog

Future work grouped by owning version.

### Archive

Historical or superseded artifacts only. No active source of truth belongs here.

## Ownership Rules

- `ROADMAP.md` is the only roadmap truth.
- `docs/INDEX.md` is the navigation layer, not a second roadmap.
- `docs/product/` owns release and support truth.
- `docs/architecture/` owns system model truth.
- `docs/operations/` owns runbooks.
- `docs/plans/` owns execution plans.
- `docs/backlog/` owns active backlog.
- `docs/archive/` owns inactive historical artifacts only.
```

- [ ] **Step 4: Write `docs/backlog/INDEX.md` to define version-owned backlog**

```markdown
# Backlog Index

Active backlog is version-owned.

## Version Buckets

- [v5](v5/)
- [v6](v6/)
- [v7](v7/)
- [v8](v8/)
- [v9](v9/)
- [v10](v10/)

## Rules

- Every active backlog item belongs to one version bucket.
- No active backlog items should live in plan folders.
- If an item becomes obsolete, move it to `docs/archive/superseded/` instead of leaving it active.
```

- [ ] **Step 5: Update `ROADMAP.md` process links to the new target locations**

```markdown
## Process

- Release and claim authority: [[docs/product/RELEASE.md]]
- Current host matrix: [[docs/product/SUPPORTED_HOSTS.md]]
- Current platform support matrix: [[docs/product/PLATFORM_SUPPORT.md]]
- Current post-V4 expansion plan: [[docs/plans/v5/2026-04-17-post-v4-vision-completion.md]]
- Prior roadmap design reference: [[docs/specs/2026-04-16-zero-trust-v2-v4-hardening-roadmap-design.md]]
```

- [ ] **Step 6: Verify the entrypoint layer exists**

Run: `find docs -maxdepth 2 -type d | sort`
Expected: includes `docs/product`, `docs/architecture`, `docs/operations`, `docs/specs`, `docs/plans`, `docs/backlog`, and `docs/archive`.

- [ ] **Step 7: Commit the entrypoint and skeleton changes**

```bash
git add ROADMAP.md docs/INDEX.md docs/backlog/INDEX.md docs
git commit -m "docs: add IA entrypoints and folder skeleton"
```

### Task 2: Move Canonical Product, Architecture, And Operations Docs

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Current canonical product docs:
  - `docs/product/ADAPTERS.md`
  - `docs/product/IDENTITY_MODEL.md`
  - `docs/product/INTEGRATION.md`
  - `docs/product/PLATFORM_SUPPORT.md`
  - `docs/product/PROVIDER_MEDIATION.md`
  - `docs/product/QUICKSTART.md`
  - `docs/product/REDACTION_POLICY.md`
  - `docs/product/RELEASE.md`
  - `docs/product/SECURITY_GUARANTEES.md`
  - `docs/product/SUPPORTED_HOSTS.md`
- Current canonical architecture docs:
  - `docs/architecture/ARCHITECTURE.md`
  - `docs/architecture/OPENCLAW.md`
  - `docs/architecture/OPENCLAW_THREAT_NOTES.md`
  - `docs/architecture/THREAT_MODEL.md`
- Current canonical operations docs:
  - `docs/operations/OPERATIONS.md`
  - `docs/operations/TROUBLESHOOTING.md`

- [ ] **Step 1: Move product docs into `docs/product/`**

```bash
mv docs/ADAPTERS.md docs/product/ADAPTERS.md
mv docs/IDENTITY_MODEL.md docs/product/IDENTITY_MODEL.md
mv docs/INTEGRATION.md docs/product/INTEGRATION.md
mv docs/PLATFORM_SUPPORT.md docs/product/PLATFORM_SUPPORT.md
mv docs/PROVIDER_MEDIATION.md docs/product/PROVIDER_MEDIATION.md
mv docs/QUICKSTART.md docs/product/QUICKSTART.md
mv docs/REDACTION_POLICY.md docs/product/REDACTION_POLICY.md
mv docs/RELEASE.md docs/product/RELEASE.md
mv docs/SECURITY_GUARANTEES.md docs/product/SECURITY_GUARANTEES.md
mv docs/SUPPORTED_HOSTS.md docs/product/SUPPORTED_HOSTS.md
```

- [ ] **Step 2: Move architecture docs into `docs/architecture/`**

```bash
mv docs/ARCHITECTURE.md docs/architecture/ARCHITECTURE.md
mv docs/OPENCLAW.md docs/architecture/OPENCLAW.md
mv docs/OPENCLAW_THREAT_NOTES.md docs/architecture/OPENCLAW_THREAT_NOTES.md
mv docs/THREAT_MODEL.md docs/architecture/THREAT_MODEL.md
```

- [ ] **Step 3: Move operations docs into `docs/operations/`**

```bash
mv docs/OPERATIONS.md docs/operations/OPERATIONS.md
mv docs/TROUBLESHOOTING.md docs/operations/TROUBLESHOOTING.md
```

- [ ] **Step 4: Update README links to the new canonical locations**

```markdown
Read [docs/product/SECURITY_GUARANTEES.md](docs/product/SECURITY_GUARANTEES.md) before relying on any security property.
Read [docs/product/REDACTION_POLICY.md](docs/product/REDACTION_POLICY.md) for the current supported-host transcript and log redaction boundary.
Read [docs/product/SUPPORTED_HOSTS.md](docs/product/SUPPORTED_HOSTS.md) for the current V3 host-certification boundary.
Read [docs/product/PLATFORM_SUPPORT.md](docs/product/PLATFORM_SUPPORT.md) for the current V4 control and support boundary.
```

- [ ] **Step 5: Verify the moved files exist and old flat copies are gone**

Run: `find docs -maxdepth 2 -type f | sort`
Expected: canonical docs appear under `docs/product/`, `docs/architecture/`, and `docs/operations/`; the old flat copies no longer exist.

- [ ] **Step 6: Commit the canonical docs move**

```bash
git add README.md ROADMAP.md docs
git commit -m "docs: separate canonical docs by ownership"
```

### Task 3: Move Plans And Specs Into Version-Owned Folders

**Files:**
- Move: legacy plan artifacts
- Move: legacy spec artifacts
- Modify: `ROADMAP.md`
- Modify: `docs/specs/2026-04-18-docs-information-architecture-design.md`

- [ ] **Step 1: Move V2-V4 plan files into version buckets**

```bash
mv docs/superpowers/plans/2026-04-16-v2-loop-0-truth-reset.md docs/plans/v2/
mv docs/superpowers/plans/2026-04-17-v2-loop-1-secret-ingress-lockdown.md docs/plans/v2/
mv docs/superpowers/plans/2026-04-17-v2-loop-2-provider-isolation-contract.md docs/plans/v2/
mv docs/superpowers/plans/2026-04-17-v2-loop-3-execution-adapter-containment.md docs/plans/v2/
mv docs/superpowers/plans/2026-04-17-v2-loop-4-capability-and-approval-hardening.md docs/plans/v2/
mv docs/superpowers/plans/2026-04-17-v2-loop-5-memd-style-node-to-node-e2e-harness.md docs/plans/v2/
mv docs/superpowers/plans/2026-04-17-v2-loop-6-v2-ship-gate.md docs/plans/v2/
mv docs/superpowers/plans/2026-04-17-v3-loop-0-trusted-input-surface.md docs/plans/v3/
mv docs/superpowers/plans/2026-04-17-v3-loop-1-transcript-and-log-redaction-pipeline.md docs/plans/v3/
mv docs/superpowers/plans/2026-04-17-v3-loop-2-real-trusted-execution-adapters.md docs/plans/v3/
mv docs/superpowers/plans/2026-04-17-v3-loop-3-multi-host-support-matrix.md docs/plans/v3/
mv docs/superpowers/plans/2026-04-17-v3-loop-4-v3-ship-gate.md docs/plans/v3/
mv docs/superpowers/plans/2026-04-17-v4-loop-0-policy-engine-maturity.md docs/plans/v4/
mv docs/superpowers/plans/2026-04-17-v4-loop-1-attestation-and-runtime-identity.md docs/plans/v4/
mv docs/superpowers/plans/2026-04-17-v4-loop-2-tamper-evident-operations-and-forensics.md docs/plans/v4/
mv docs/superpowers/plans/2026-04-17-v4-loop-3-rotation-and-recovery-drills.md docs/plans/v4/
mv docs/superpowers/plans/2026-04-17-v4-loop-4-adversarial-continuous-verification.md docs/plans/v4/
mv docs/superpowers/plans/2026-04-17-v4-loop-5-platform-ship-gate.md docs/plans/v4/
mv docs/superpowers/plans/2026-04-17-post-v4-vision-completion.md docs/plans/v5/
```

- [ ] **Step 2: Move spec files into `docs/specs/`**

```bash
mv docs/superpowers/specs/2026-04-16-zero-trust-v2-v4-hardening-roadmap-design.md docs/specs/
mv docs/superpowers/specs/2026-04-17-zero-trust-v2-v4-remaining-loop-spec-pack.md docs/specs/
```

- [ ] **Step 3: Update roadmap and IA-spec references to the new locations**

```markdown
- Current post-V4 expansion plan: [[docs/plans/v5/2026-04-17-post-v4-vision-completion.md]]
- Prior roadmap design reference: [[docs/specs/2026-04-16-zero-trust-v2-v4-hardening-roadmap-design.md]]
```

- [ ] **Step 4: Verify there are no remaining active files in `docs/superpowers/plans` or `docs/superpowers/specs`**

Run: `find docs -maxdepth 3 -type f | sort`
Expected: no active plan/spec files remain in legacy planning directories.

- [ ] **Step 5: Commit the plan and spec migration**

```bash
git add ROADMAP.md docs/specs docs/plans docs/superpowers
git commit -m "docs: version execution plans and specs"
```

### Task 4: Seed Version-Owned Backlog And Prune Empty Legacy Folders

**Files:**
- Modify: `docs/backlog/INDEX.md`
- Modify: `docs/INDEX.md`
- Delete: `docs/superpowers/` if empty

- [ ] **Step 1: Add placeholder README files to version-owned backlog folders**

```markdown
# V5 Backlog

This folder owns backlog items assigned to V5.
```

Repeat the same pattern for `v6` through `v10`.

- [ ] **Step 2: Update `docs/INDEX.md` to point readers to the backlog index**

```markdown
### Backlog

Future work grouped by owning version. Start at [backlog/INDEX.md](backlog/INDEX.md).
```

- [ ] **Step 3: Remove now-empty legacy planning directories**

```bash
rmdir docs/superpowers/plans docs/superpowers/specs docs/superpowers || true
```

- [ ] **Step 4: Verify the docs tree top-level is now clean**

Run: `find docs -maxdepth 2 -type d | sort`
Expected: only the new owned folders remain at top level, plus populated children.

- [ ] **Step 5: Commit the backlog seeding and legacy cleanup**

```bash
git add docs
git commit -m "docs: seed version backlog and remove legacy planning dirs"
```

### Task 5: Repair Link Targets Across The Repo

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `docs/INDEX.md`
- Modify: `docs/product/*.md`
- Modify: `docs/architecture/*.md`
- Modify: `docs/operations/*.md`
- Modify: `docs/plans/v2/*.md`
- Modify: `docs/plans/v3/*.md`
- Modify: `docs/plans/v4/*.md`
- Modify: `docs/plans/v5/*.md`
- Modify: `docs/specs/*.md`
- Modify: `.continue-here.md`

- [ ] **Step 1: Find all stale old-path references after the move**

Run: `rg -n "docs/(ADAPTERS|ARCHITECTURE|IDENTITY_MODEL|INTEGRATION|OPENCLAW|OPENCLAW_THREAT_NOTES|OPERATIONS|PLATFORM_SUPPORT|PROVIDER_MEDIATION|QUICKSTART|REDACTION_POLICY|RELEASE|SECURITY_GUARANTEES|SUPPORTED_HOSTS|THREAT_MODEL|TROUBLESHOOTING)\\.md|docs/superpowers/(plans|specs)/" -g '*.md' -g 'ROADMAP.md' .`
Expected: a finite list of stale references to patch.

- [ ] **Step 2: Patch canonical references to the new folders**

```markdown
docs/product/RELEASE.md               is canonical
docs/product/SUPPORTED_HOSTS.md       is canonical
docs/product/PLATFORM_SUPPORT.md      is canonical
docs/product/SECURITY_GUARANTEES.md   is canonical
docs/product/INTEGRATION.md           is canonical
docs/product/IDENTITY_MODEL.md        is canonical
docs/product/PROVIDER_MEDIATION.md    is canonical
docs/product/REDACTION_POLICY.md      is canonical
docs/architecture/OPENCLAW.md         is canonical
docs/architecture/OPENCLAW_THREAT_NOTES.md is canonical
docs/architecture/ARCHITECTURE.md     is canonical
docs/architecture/THREAT_MODEL.md     is canonical
docs/operations/OPERATIONS.md         is canonical
docs/operations/TROUBLESHOOTING.md    is canonical
docs/plans/vX/...                     are version-owned
docs/specs/...                        are canonical specs
```

- [ ] **Step 3: Re-run the stale-reference search**

Run: `rg -n "docs/superpowers/(plans|specs)/|docs/(ADAPTERS|ARCHITECTURE|IDENTITY_MODEL|INTEGRATION|OPENCLAW|OPENCLAW_THREAT_NOTES|OPERATIONS|PLATFORM_SUPPORT|PROVIDER_MEDIATION|QUICKSTART|REDACTION_POLICY|RELEASE|SECURITY_GUARANTEES|SUPPORTED_HOSTS|THREAT_MODEL|TROUBLESHOOTING)\\.md" -g '*.md' -g 'ROADMAP.md' .`
Expected: zero results.

- [ ] **Step 4: Commit the link repair pass**

```bash
git add README.md ROADMAP.md docs .continue-here.md
git commit -m "docs: repair links after IA migration"
```

### Task 6: Run The Final Verification Sweep

**Files:**
- Modify: none

- [ ] **Step 1: Verify the final docs tree**

Run: `find docs -maxdepth 3 -type f | sort`
Expected: canonical docs under owned folders, version-owned plans, version-owned backlog, no active files under `docs/superpowers/`.

- [ ] **Step 2: Verify roadmap and docs entrypoints resolve to the new ownership model**

Run: `sed -n '1,220p' ROADMAP.md && printf '\n---\n' && sed -n '1,220p' docs/INDEX.md && printf '\n---\n' && sed -n '1,220p' docs/backlog/INDEX.md`
Expected: roadmap truth in `ROADMAP.md`, docs map in `docs/INDEX.md`, backlog ownership in `docs/backlog/INDEX.md`.

- [ ] **Step 3: Verify no legacy planning files remain in active locations**

Run: `find docs/superpowers -maxdepth 3 -type f 2>/dev/null || true`
Expected: no output.

- [ ] **Step 4: Review the final diff against the IA spec**

Run: `git diff --stat HEAD~6..HEAD`
Expected: only docs moves, new indexes, and link repairs; no product-truth rewrites beyond path changes.

- [ ] **Step 5: Commit any final tiny cleanup if needed**

```bash
git add .
git commit -m "docs: finalize IA cleanup verification"
```

## Self-Review

- Spec coverage: this plan covers entrypoints, folder ownership, canonical doc moves, plan/spec moves, version backlog seeding, link repair, and final verification.
- Placeholder scan: no `TODO`, `TBD`, or “handle appropriately” placeholders remain.
- Type consistency: target folder names and moved file paths are consistent across tasks.
