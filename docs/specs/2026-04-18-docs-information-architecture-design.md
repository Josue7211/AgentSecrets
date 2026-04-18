# Secret Broker Docs Information Architecture Design

## Status

- Date: `2026-04-18`
- Scope: docs information architecture cleanup
- Type: design spec
- Goal: make docs easier to navigate, own, and maintain without creating needless churn

## Why This Exists

The repo now has a clean canonical roadmap in `ROADMAP.md`, but the docs tree is still mixed:

- canonical product truth lives in flat `docs/*.md` files
- architecture and operations docs sit beside product docs
- plan and spec artifacts live under `docs/superpowers/...`
- there is no human docs entrypoint
- future backlog structure is not defined

The repo works, but the docs system does not scale cleanly into `V5` through `V10`.

## Design Goals

- preserve one canonical roadmap source of truth in `ROADMAP.md`
- create one obvious human entrypoint in `docs/INDEX.md`
- separate product truth from planning artifacts
- make version ownership obvious for plans and backlog
- preserve filenames where possible
- minimize churn while still making the structure durable

## Non-Goals

- rewriting product truth during the IA pass
- renaming files just for style
- changing release claims or support claims as part of the move
- archiving active canonical docs

## Current State

Current root docs are flat:

- `docs/ADAPTERS.md`
- `docs/ARCHITECTURE.md`
- `docs/IDENTITY_MODEL.md`
- `docs/INTEGRATION.md`
- `docs/OPENCLAW.md`
- `docs/OPENCLAW_THREAT_NOTES.md`
- `docs/OPERATIONS.md`
- `docs/PLATFORM_SUPPORT.md`
- `docs/PROVIDER_MEDIATION.md`
- `docs/QUICKSTART.md`
- `docs/REDACTION_POLICY.md`
- `docs/RELEASE.md`
- `docs/SECURITY_GUARANTEES.md`
- `docs/SUPPORTED_HOSTS.md`
- `docs/THREAT_MODEL.md`
- `docs/TROUBLESHOOTING.md`

Current planning artifacts live under:

- `docs/superpowers/plans/`
- `docs/superpowers/specs/`

## Target Information Architecture

```text
ROADMAP.md
docs/
  INDEX.md

  product/
    ADAPTERS.md
    IDENTITY_MODEL.md
    INTEGRATION.md
    PLATFORM_SUPPORT.md
    PROVIDER_MEDIATION.md
    QUICKSTART.md
    REDACTION_POLICY.md
    RELEASE.md
    SECURITY_GUARANTEES.md
    SUPPORTED_HOSTS.md

  architecture/
    ARCHITECTURE.md
    OPENCLAW.md
    OPENCLAW_THREAT_NOTES.md
    THREAT_MODEL.md

  operations/
    OPERATIONS.md
    TROUBLESHOOTING.md

  specs/
    ...

  plans/
    v2/
    v3/
    v4/
    v5/
    v6/
    v7/
    v8/
    v9/
    v10/

  backlog/
    INDEX.md
    v5/
    v6/
    v7/
    v8/
    v9/
    v10/

  archive/
    completed/
    superseded/
```

## Canonical Ownership Rules

### ROADMAP.md

`ROADMAP.md` is the only roadmap truth.

It owns:

- version ladder
- current version and phase
- blockers
- next step
- completed foundation summary

It does not own:

- release details
- host matrix details
- plan task breakdowns

### docs/INDEX.md

`docs/INDEX.md` is the human navigation layer.

It owns:

- the doc map
- which folder to read for which question
- canonical ownership summary

It does not duplicate product truth.

### docs/product/

This folder owns shipping truth and user/operator contract truth.

It includes:

- release and claim authority
- support matrices
- guarantees
- integration contracts
- provider and adapter boundary docs
- quickstart

### docs/architecture/

This folder owns system model and trust-boundary explanation.

It includes:

- architecture
- threat model
- host-specific architecture notes

### docs/operations/

This folder owns runbooks and operational guidance.

It includes:

- operations
- troubleshooting
- future drill and recovery docs if they become doc artifacts

### docs/specs/

This folder owns strategic design docs and design companions.

It includes:

- roadmap design companions
- IA design docs
- major strategic design specs

### docs/plans/

This folder owns execution plans.

Rules:

- plans are version-owned
- old V2-V4 plans move into `docs/plans/v2/`, `docs/plans/v3/`, and `docs/plans/v4/`
- future V5-V10 plans must live in their version folder

### docs/backlog/

This folder owns future work that is not yet in execution.

Rules:

- backlog is version-owned
- every active backlog item belongs to one version bucket
- no active backlog items should live in random planning folders

### docs/archive/

This folder owns dead or superseded artifacts only.

Rules:

- use `completed/` for historical artifacts that are no longer active working docs
- use `superseded/` for docs replaced by newer canonical truth
- do not keep duplicate active truth in archive and active folders

## Naming Rules

- preserve existing filenames where possible
- move first, rename only when the current name is actually unclear
- use folder ownership to carry most of the structure
- keep version folder names lowercase: `v2`, `v3`, ... `v10`

## Migration Plan

### Phase 1: Establish Entrypoints

- keep `ROADMAP.md` as the roadmap truth
- add `docs/INDEX.md`
- document the ownership rules in `docs/INDEX.md`

### Phase 2: Create Folders

- create `docs/product/`
- create `docs/architecture/`
- create `docs/operations/`
- create `docs/specs/`
- create `docs/plans/v2/` through `docs/plans/v10/`
- create `docs/backlog/v5/` through `docs/backlog/v10/`
- create `docs/archive/completed/`
- create `docs/archive/superseded/`

### Phase 3: Move Canonical Docs

Move current root docs into their owned folders without renaming unless needed.

### Phase 4: Move Planning Artifacts

- move `docs/superpowers/plans/*` into version-owned `docs/plans/`
- move `docs/superpowers/specs/*` into `docs/specs/`
- decide case by case whether completed bridge artifacts stay in plans or move to archive

### Phase 5: Seed Backlog Structure

- add `docs/backlog/INDEX.md`
- create version-owned backlog folders
- require all future backlog items to live there

### Phase 6: Repair Links

- update all internal markdown links
- update links from `ROADMAP.md`
- update links from release and support docs

### Phase 7: Archive Cleanup

- move superseded duplicates into `docs/archive/superseded/`
- move historical inactive artifacts into `docs/archive/completed/`
- leave no duplicate active truth

## Success Criteria

- `ROADMAP.md` remains the single roadmap source of truth
- `docs/INDEX.md` becomes the obvious human entrypoint
- canonical product docs are separated from plans and specs
- plans are version-owned
- backlog is version-owned
- there are no duplicate active truth docs in two places
- internal links still work after the move
- filenames are preserved where possible

## Risks

- broken links after moves
- accidental duplication of truth during migration
- over-renaming, which would create churn without value

## Risk Controls

- move first, rename later only when needed
- do link repair as an explicit migration phase
- keep `ROADMAP.md` stable during the docs IA pass
- treat canonical ownership rules as part of the entrypoint docs, not tribal knowledge

## Recommendation

Use the hybrid cleanup path:

- canonical entrypoints
- clear folder ownership
- version-owned plans
- version-owned backlog
- preserved filenames where possible

This gives the repo a durable docs system without turning the reorg into churn theater.
