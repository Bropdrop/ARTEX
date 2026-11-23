# Awootex — Codex handoff

> Historical handoff for PR #2. The fork now uses the **Wolftrax** name.
> New development is documented in the [Investigation Lab guide](wolftrax-investigation-lab-v1.md).

**Awootex** was the name of this Bropdrop development fork at the Authority Graph handoff.
The verified GitHub repository address is currently
[Bropdrop/ARTEX](https://github.com/Bropdrop/ARTEX).

Use the **Bropdrop** GitHub account for this project. The user transferred the
repository out of GovernableIntelligence; future branches, pull requests and
project work belong under Bropdrop. Do not create a replacement fork or redirect
this work into the HERCULES account.

## Current review target

| Item | Location |
| --- | --- |
| Repository | `Bropdrop/ARTEX` |
| Working branch | `feat/wolftrap-authority-graph-v1` |
| Authority Graph draft | [PR #2](https://github.com/Bropdrop/ARTEX/pull/2) |
| Base branch | `feat/wolftrap-evidence-referee-v1` |
| Evidence referee draft | [PR #1](https://github.com/Bropdrop/ARTEX/pull/1) |
| Authority implementation and acceptance conditions | [Authority Graph v1](wolftrap-authority-graph-v1.md) |
| Prior qualification | [Authority qualification record](wolftrap-authority-qualification-v1.json) |

For a fresh development checkout:

```sh
git clone --branch feat/wolftrap-authority-graph-v1 https://github.com/Bropdrop/ARTEX.git awootex
cd awootex
```

The graph, API and focused checks are implemented. The outstanding review gate is
rendered desktop/mobile behavior, especially record selection, pagination, refresh
failures, task changes and opening the original execution. The prior environment
could build the frontend but could not complete browser access to its local preview.

## Task to give Codex

> Work in Bropdrop/ARTEX, project name Awootex. Check out
> feat/wolftrap-authority-graph-v1 and inspect PR #2 against
> feat/wolftrap-evidence-referee-v1. Read docs/wolftrap-authority-graph-v1.md and its
> qualification record. Independently review task scope, deleted/archived task
> visibility, metadata redaction, legacy and unknown states, refresh races and
> original-call navigation. Run the documented focused checks with a disposable
> PostgreSQL database and build the static frontend. Where the environment permits,
> review desktop and mobile layouts against synthetic fixtures and exercise the
> outstanding interactions. Respect environment access controls and report any
> blocked check explicitly. Fix concrete defects in a small follow-up branch based
> on this work and return a reviewable diff or draft PR with actual test results.
> Keep recorded approval, tool-reported outcome and independent effect evidence
> separate. Missing owner grants and effect receipts must remain not recorded.
> Do not launch assessments against live targets, make model-provider calls, merge,
> deploy, or change permissions. Use Bropdrop for any repository writes.

Use the Go version pinned in `go.mod` and the locked frontend dependencies. The
existing tests require `ARTEX_PG_DSN` for PostgreSQL-backed checks; missing database
access produces skipped tests and must not be reported as a pass. The full commands
and evidence distinctions are in the Authority document linked above.

## Transfer and qualification history

The repository retained its branches, commit history and both draft pull requests
after the ownership transfer. The earlier qualification files are historical
records of their tested revisions. Their original repository address, timestamps
and source digests remain unchanged; they do not identify the current destination
for new work. In particular, the README digest predates this ownership/name update.
The offline-reader snapshot is commit `07f8770878e5f77d949f3c93fdc8f2d3ee58ab06`;
the Authority snapshot is commit `72c198a0254ecde4c7a92220be467e20ce107a74`.

This handoff and README correction change documentation only. They do not rerun or
extend the earlier qualification, change application behavior, or claim that a
separate Codex Cloud task has been launched. The upstream ARTEX attribution and
AGPL-3.0 licence are preserved.
