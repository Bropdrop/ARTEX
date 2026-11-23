# WolfTrap Evidence Referee — first development increment

The referee checks an ARTEX findings `md-zip` export without launching ARTEX,
contacting a target, using a model, or extracting the archive. It answers a narrow
question: **are the evidence files present, structurally supported, and consistent
with their recorded hashes and an optional archive digest supplied by the reviewer?**

It does not decide whether a vulnerability exists. An authentic response can be
misinterpreted, an internally consistent archive can be fabricated, and a correct
hash can accompany an unsupported conclusion. These are different questions and the
result keeps them separate.

## Source and scope

This fork starts at BaaRai/ARTEX commit
`d235be850e9b34247ddb566686c47e6d4e4f0daf`, Git tree
`f57922d97e56c2614e04e0406df13838e131a92e`.

BaaRai describes its repository as the English continuation of Autumn-27's ARTEX.
The original author's public profile says public updates stopped and the original
project became closed source on October 8, 2026. This fork retains the available
continuation's AGPL-3.0 licence and attribution; it does not claim affiliation with
either maintainer. See [upstream](https://github.com/BaaRai/ARTEX), the
[original author's statement](https://github.com/Autumn-27), and [LICENSE](../LICENSE).

Existing ARTEX work supplies the foundation:

| Existing component | Behavior used by this increment |
| --- | --- |
| `server/finding_traffic_export.go` | Writes the finding Markdown and five files per evidence binding into an `md-zip` export. |
| `db/finding_traffic.go` | Defines binding/snapshot fields and `TrafficSnapshotID` metadata hashing. |
| `evidence/store.go` | Checks body sizes and SHA-256 values when reading evidence. |
| `server/finding_verification.go` | Checks bound proof/verification responses, declared proof level and evidence quotations. |

The offline referee rechecks the exported artifact from outside the running server.
It does not replace ARTEX's verification status, modify its database, or add a UI
badge. Its supported export profile is pinned to the source above. Unsupported
future structures are rejected rather than silently interpreted.

## Use

Requires Python 3.10 or newer, with the standard library only.

Export the selected findings as `md-zip` through ARTEX, then inspect the archive:

```sh
python3 scripts/wolftrap_evidence.py verify /path/to/findings.zip
```

For a pinned check, supply a SHA-256 digest that you obtained through a separately
trusted channel:

```sh
python3 scripts/wolftrap_evidence.py verify /path/to/findings.zip \
  --expected-sha256 <64-character-SHA-256>
```

Do not treat a digest read from the same untrusted download as independent evidence
of origin. Computing the digest immediately before verification is useful for
repeatability, but it does not authenticate the publisher or the capture.

The command prints a JSON result. It does not include raw traffic bodies,
credentials, HTTP headers or target URLs in that result.

### Result dimensions

| Field | Meaning |
| --- | --- |
| `evidence_integrity` | Whether the supported evidence structure, body hashes, lengths, snapshot metadata and HTTP renderings agree. |
| `anchor_status` | Whether the archive matches an externally supplied SHA-256 digest, lacks one, or mismatches it. |
| `origin_status` | `UNAUTHENTICATED`: this increment has no trusted capture signer or independent witness. A matching digest does not change that. |
| `claim_status` | `CLAIM_NOT_ASSESSED`: this increment neither executes a reproduction nor establishes that the response supports the claimed security failure. |
| `status` | Overall artifact-check outcome: `VERIFIED`, `INVALID` or `INCONCLUSIVE`. `VERIFIED` is limited to the pinned artifact checks. |

A structurally valid, internally consistent export without an external digest is
`INCONCLUSIVE`, while still reporting its successful evidence-integrity check.
An empty report with no evidence cannot earn an evidence-integrity pass.
A pass covers the included bindings. It does not establish completeness against
the server's database or evidence support for every report in a mixed export.

| Exit code | Meaning |
| --- | --- |
| `0` | Supported evidence checks passed and the supplied archive digest matched. Claims and origin remain unassessed/unauthenticated. |
| `1` | Invalid archive, inconsistent evidence, unsupported structure, or failed digest check. |
| `2` | Inconclusive, including an internally consistent archive without an external digest. |

## What the checks establish

The reader consumes one bounded archive snapshot. It checks ZIP member names and
types before reading evidence, refuses duplicate members and ambiguous JSON, bounds
compressed and expanded sizes, and reads members through CRC verification. It never
extracts paths or evaluates archive content as instructions.

For each evidence binding it checks:

- The binding and finding identifiers match their archive path.
- The manifest follows the pinned ARTEX export structure and supported field types.
- Request and response bodies match their recorded SHA-256 and lengths.
- The snapshot identifier matches ARTEX's `TrafficSnapshotID` algorithm.
- Each `.http` rendering agrees with the stored header text and the corresponding
  raw `.bin` body.

ARTEX's snapshot digest intentionally excludes `created_at`, `rewritten` and
`rewrite_rule_ids`, and it does not cover the enclosing binding's role, note or
position. The archive-level digest covers their exported bytes when that digest is
independently pinned. Neither digest proves that the metadata is truthful.

Resource limits are deliberate. A legitimate export exceeding the reader's limits
does not receive a partial pass; split it into smaller exports. A rejected archive
is not evidence that the target was attacked or that the publisher acted maliciously.

| Limit | Supported maximum |
| --- | --- |
| Compressed archive | 64 MiB |
| One expanded member | 16 MiB |
| All expanded members | 128 MiB |
| ZIP members | 2,048 |
| One manifest | 256 KiB |
| Expanded/compressed member ratio | 100:1 |

The bounded profile supports ordinary single-disk ZIPs with stored or deflated
members. ZIP64, archive comments, self-extracting prefixes, directory/link entries
and trailing data are unsupported. This intentionally narrower profile must not be
presented as a general-purpose ZIP verifier.

## Local verification

The [qualification record](wolftrap-qualification-v1.json) records the tested
source digests, 42 passing test methods, review corrections and qualification scope.

```sh
python3 -m unittest discover -s scripts -p 'test_wolftrap_evidence.py' -v
```

The tests use temporary, synthetic archives shaped from the actual ARTEX exporter.
They cover valid binary and empty-body evidence, external anchors, corrupted files,
metadata inconsistencies, missing evidence, ambiguous archive/JSON inputs and
resource limits. They make no model calls and send no target traffic.

These tests qualify the additive Python reader. They do not qualify the entire Go
backend, PostgreSQL integration, frontend, container image, runtime containment or
production deployment. Compatibility with a live server-generated export should
be demonstrated before this reader is promoted as an operational release.

## Where the bigger WolfTrap features fit

These are proposed follow-on increments. They are not delivered by the referee.

| Feature | User-visible result | Engineering acceptance condition |
| --- | --- | --- |
| **Authority graph** | Click a finding and see the owner grant, agent identity, permitted operation, decision and resulting evidence. | Every dispatched action binds to a grant and policy version; missing or ambiguous links remain visible and cannot imply authorization. |
| **Controlled reproduction** | Separate an intact evidence pack from a finding reproduced by an independent check. | A versioned oracle compares controlled baseline, authorized and unauthorized cases; missing controls or ambiguous results stay inconclusive. Model agreement alone cannot promote a claim. |
| **Worker containment** | Agents operate through a limited broker with visible boundaries. | Per-task isolation denies direct filesystem, credential and network access; hostile tests demonstrate the broker is the sole path to protected effects. Prior WolfAlibi results must be reproduced in this integration. |
| **Revocation and emergency stop** | Revoke a grant and see which queued actions were stopped and which effects had already happened. | Expired, consumed, revoked or generation-mismatched grants cannot dispatch. Test queue races, concurrency, restart and lost replies. Completed effects are not claimed to be undone. |
| **Replay laboratory** | Reproduce a failed run against local fixtures without spending model credits or touching a live target. | Recorded model decisions remain untrusted inputs; fixtures and deterministic oracles measure actual effects. Record seeds, versions and limits. |
| **Contradiction tracking** | Conflicting observations, stale conclusions and unsupported findings stand out in the exploration graph. | Bind observations to target version, identity, time and evidence; disagreement creates an unresolved state rather than an invented consensus. |
| **Portable signed evidence** | A reviewer verifies an evidence pack without trusting the planner that produced the claim. | A separately trusted capture/witness key signs the full manifest; verification pins identity and context, handles revocation/freshness, and distinguishes provenance from truth. |
| **Accountable budgets** | See the remaining model, time and target-request budget before a worker starts. | Reservations and reconciliation cover every configured role, concurrency and restart; estimates are distinguished from provider-confirmed cost. |

The visual goal is to extend ARTEX's asset and exploration graphs with an authority
view. The hard part is making each displayed authorization and proof claim correspond
to an enforced action and an independently checkable record. The offline referee is
the first small component of that work.
