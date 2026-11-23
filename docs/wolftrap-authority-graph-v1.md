# WolfTrap Authority Graph v1

The task-detail **Authority** tab makes ARTEX's recorded interception decisions
inspectable. Select a record to see the tool proposal, decision, recorded tool
outcome and the missing owner-grant and independent-effect evidence. This is a
read-only projection of existing records; it does not introduce an execution
broker or change how ARTEX permits tools to run.

## What the graph establishes

The graph deliberately keeps different questions separate:

| Question | Available evidence in this increment |
| --- | --- |
| What operation was reviewed? | Recorded tool and agent display names, with a captured call/run ID when present. The agent label is not an authenticated identity. |
| Where did the review originate? | Stored decision source, independently displayed from the deciding actor. A model ask subsequently allowed by a human retains both facts. |
| What decision was recorded? | Pending, allowed, denied or timed out. Unknown future values remain unrecognized. |
| What did the tool report? | The saved execution state, such as tool-reported success, tool-reported failure or an unknown outcome. Denial is distinct from execution failure. |
| Is the original call available? | A separate execution-source lookup must resolve the call in the same task before navigation. Recorded exact correlation alone does not establish current availability. |
| Did the target owner authorize this operation? | No signed owner-grant record exists in this projection. The graph says **Not recorded**. An operator approval or target pin is not promoted to an owner grant. |
| Was an external effect independently established? | No independent effect receipt exists in this projection. The graph says **Not recorded**, even when the tool reported success. |

Solid edges relate fields in the recorded approval/audit. Dashed edges expose
unresolved call links and missing evidence. They are visual explanations of the
record, not signatures, enforced capabilities or proof that an action occurred.

### Coverage is intentionally explicit

This view covers **recorded interception decisions**, not every tool dispatch.
Some guard paths do not create a durable interception record. Target-gate approvals
can also be shared by concurrent calls to the same target. Therefore, record counts
are not action counts, and an empty list does not mean that no actions occurred.

The wider authority-graph acceptance condition in
[the roadmap](wolftrap-evidence-referee.md#where-the-bigger-wolftrap-features-fit)—
every dispatch bound to a grant and policy version—remains future enforcement work.

## API and source boundaries

`GET /api/tasks/{id}/authority?page=1&size=20` is served through ARTEX's existing
authenticated API mux. Task IDs must be explicit canonical positive integers;
blank IDs, aliases such as `active`, leading zeros and invalid pagination are
rejected. The defaults are page 1 and 20 records; page size is bounded to 100.

The reader uses a read-only, repeatable-read PostgreSQL transaction. Both count
and selection constrain records to the exact task, exclude conversation records,
and require that the task is neither deleted nor archived in the database
snapshot. A stale in-memory task entry does not bypass this check. Results are
ordered by creation time and ID, descending. A refresh can change page membership
as new records arrive; this API is not an immutable export.

The summary contains only selected metadata. It does not fetch or return raw tool
arguments, prompts, model input, context, output, freeform decision reasons, target
addresses or approver addresses. Captured rule names come from the historical
audit, not the current mutable rule definition. Stored digests are labelled as
recorded digests; this endpoint does not recompute them or authenticate their origin.

The response contains:

```json
{
  "task_id": "42",
  "items": [],
  "total": 0,
  "page": 1,
  "size": 20,
  "coverage": "recorded_interception_decisions",
  "owner_grant": "not_recorded",
  "independent_effect": "not_recorded"
}
```

An unavailable task returns 404. Invalid scope or pagination returns 400. An
unauthenticated request returns 401 through the existing auth layer. Internal
database/audit failures return a generic error instead of leaking audit content.
Successful responses use `Cache-Control: no-store`.

The current authentication boundary is ARTEX's operator session. This increment
does not add separate owner, project or tenant authorization.

## Interface behavior

The native tab provides a paginated record list, a selected-record graph and text
details for keyboard and narrow-screen use. It refreshes while visible, marks
failed refreshes as stale, and displays the last successful refresh time. Changing
tasks or pages discards the previous scope's pending responses and records.

The **original call** action uses ARTEX's existing interception-execution endpoint.
That endpoint rejects ambiguous or duplicate IDs instead of matching command text
or nearest timestamps. The client checks the returned task scope before navigation.
The graph does not fetch full audit details as part of polling.

## Development and verification

Use the Go version pinned in `go.mod`, a disposable PostgreSQL database, and the
locked frontend dependencies. These checks exercise synthetic records and local
HTTP handlers without starting ARTEX's scheduler or contacting assessment targets.

```sh
go test ./db ./server -run Authority -count=1
```

Set `ARTEX_PG_DSN` to a disposable local PostgreSQL database before running the Go
checks. The existing test harness creates package-specific databases. Without
PostgreSQL, integration tests skip; a skipped integration test is not a pass.

From `web/`:

```sh
npm ci --ignore-scripts
npm run test:authority
npm run test:polling
npm run test:i18n
npx tsc --noEmit
npm run build:static
```

The [qualification record](wolftrap-authority-qualification-v1.json) records the
actual checks, tool versions and source-file digests of this increment:

| Check | Result |
| --- | --- |
| New backend Authority suite with PostgreSQL | 6 top-level tests and 12 subtests passed; no failures or skips. |
| Frontend Authority semantics and response validation | 25 tests passed; no failures or skips. |
| Existing exact-source navigation, HTTP detail and trace-correlation regressions | 9 tests/subtests passed with PostgreSQL; no failures or skips. |
| Existing visibility-aware polling | 3 tests passed. |
| Existing i18n behavior and dictionary coverage | 5 tests and dictionary coverage passed. |
| Evidence referee regression | 42 test methods passed. |
| Frontend TypeScript, focused Biome checks and production static build | Passed. |
| Rendered browser interaction and layout review | Not completed: the execution environment blocks browser access to the local preview. |

The change remains a draft pending rendered desktop/mobile review, including the
original-execution navigation and stale-refresh behavior in a browser. Source
review and helper tests cover their logic but do not replace that interaction
check. The complete upstream test suite and an operational ARTEX deployment have
not been qualified by this increment.

## Codex review task

The implementation is deliberately bounded so another coding run can independently
review it. Give Codex the fork and the `feat/wolftrap-authority-graph-v1` branch,
then use this task:

> Review Authority Graph v1 against this document and the diff from
> `feat/wolftrap-evidence-referee-v1`. Verify task scope, deleted/archived visibility,
> response redaction, unknown and legacy states, polling races, and original-call
> navigation. Run the focused tests with disposable PostgreSQL and build the static
> frontend. Investigate failures and propose a small follow-up diff with evidence.
> Keep approval, tool-reported outcome and independently verified effects separate.
> Do not launch ARTEX assessments, make model calls, invent missing grants or
> receipts, merge the branch, or deploy. Report executed checks and skipped checks
> separately.

Useful source entry points are `db/authority.go`, `server/authority.go`,
`web/src/lib/authority.ts`, the task `authority-tab.tsx`, and
`web/src/components/authority-graph.tsx`. The existing conservative source resolver
is `db/intercept_execution.go`.
