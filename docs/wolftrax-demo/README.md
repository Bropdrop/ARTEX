# Wolftrax synthetic reading-room demonstration

The four JSON files in this directory are complete responses from the authenticated casefile route over a disposable PostgreSQL fixture. The fixture creates a task and inserts reading-room records with invented tool and agent labels. It never starts an assessment. Each file has the producer's `synthetic: true` marker. Check the saved bytes with `sha256sum -c SHA256SUMS` from this directory.

## A review in five steps

1. Open **Authority** for a task you can read. In **Live**, freeze the task to take a snapshot of its recorded interception decisions. Save the JSON and its SHA-256 separately. The source task can keep receiving writes. Live search covers the current page.
2. For the portable demonstration, select **Frozen** and import `before.json`. Five decisions appear. Select **Catalog**. Its decision source is model and its deciding actor is human. The saved tool outcome is success. Target-owner authorization and an independent effect receipt are both unrecorded. **Reader** is a display label.
3. Use the timeline to inspect recorded timestamps. Select **Index** to examine the denied decision with a saved success and the ambiguous call linkage. Its companion pending row has script-like label text and no decision time. **Legacy card** has no audit. **Shelf count** carries an unfamiliar saved outcome. The diagnostics identify their supporting records. Playing these entries does not send their requests.
4. Compare `before.json` with `after.json`. Expect **Reading log** added, **Legacy card** absent, and **Shelf count** changed from `demo_future_outcome` to `failed` in `execution_status`. Absence alone does not tell a reviewer what happened to the earlier record. Try `restored.json` as the later file. Equal task and record numbers span different declared dataset incarnations, so automatic alignment is unavailable.
5. Export a reviewer HTML report and open the local file. Read the capture scope, field changes and evidence gaps. The label containing angle brackets should appear as text. `empty.json` shows a visible task with zero recorded interception decisions. An exported-byte digest checks byte consistency. Source origin remains unauthenticated and the security claim remains unassessed.

## Re-create the pack

From the repository root, set `ARTEX_PG_DSN` to a **disposable** PostgreSQL URL with a database name and a role that can create the package-specific test database. Use the Go toolchain pinned in `go.mod`.

```sh
export WOLFTRAX_DEMO_DIR="$(mktemp -d)"
go test ./server -run '^TestInvestigationDemo$' -count=1 -v
(cd "$WOLFTRAX_DEMO_DIR" && sha256sum -c SHA256SUMS)
```

The fixture procedure and declared event times are fixed. Each run declares a fresh dataset incarnation. PostgreSQL assigns task/record IDs and capture times, so regenerated file bytes differ. The output directory also contains `large.json` with 2,000 synthetic rows for browser measurements. Only the four small casefiles are checked in.

To exercise import errors, run this from the repository root with a fresh destination path.

```sh
python3 docs/wolftrax-demo/import_examples.py /tmp/wolftrax-import-examples
node --experimental-transform-types docs/wolftrax-demo/check.mjs docs/wolftrax-demo /tmp/wolftrax-import-examples
```

The derived files include incompatible or unknown identity metadata, an unknown decision, a future schema, duplicate IDs and keys, excess depth, truncated JSON and an oversized input. An unknown decision remains inspectable. Invalid or unsupported structures should produce import errors before any records appear. These derived examples are edits to the demonstration file, distinct from the exact handler responses.
