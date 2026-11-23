# Wolftrax Investigation Lab v1

Open a task, select **Authority**, and choose **Freeze task**. Wolftrax reads the visible task’s interception records in one PostgreSQL snapshot and opens the result in **Frozen**. Save **Download casefile** and **Download SHA-256** together. Keep the two files with the same names and run `sha256sum -c <filename>.sha256` to check the original JSON bytes later.

In **Live**, the total covers the visible task and the search, filters and diagnostics cover the current page. In **Frozen**, those controls cover the whole file. Select a record to see its decision, outcome, graph, and cited advisories. The UTC date filter uses the record’s creation date. The timeline shows creation, decision and tool-result fields where available. Undated entries follow dated entries, with record ID and field as tie breakers. **Play** moves the selection over those entries locally. Details always show the row as captured, including fields recorded later than the selected event. Their order describes the producer’s timestamps and cannot establish causation.

Return to **Live** and freeze again, or import an earlier and later file in **Compare**. Select either side to inspect its records. The summary counts added, absent and changed records. Select a changed record for earlier and later values. An absent record only establishes a difference in membership. The **Investigation Lab** sidebar entry accepts files without requiring their task to still exist. **Export reviewer report** writes a standalone HTML file with the complete capture and, when two files are loaded for comparison, both captures and their comparison. Search and list pagination affect the screen only.

[Step-by-step synthetic walkthrough and example files](wolftrax-demo/README.md)

## Installation and dataset identity

Set these two non-secret values in the server environment, or the source build’s Compose `.env`, to enable historical alignment and source lookup.

| Setting | Operator responsibility |
| --- | --- |
| `WOLFTRAX_SOURCE_NAMESPACE` | Assign a stable identifier for the installation. |
| `WOLFTRAX_DATASET_INCARNATION` | Assign an identifier for this database lineage. Set a fresh value on clone, restore or replacement before exporting from it. |

Each configured identifier starts with an ASCII letter or digit and has at most 128 characters from letters, digits, period, underscore and hyphen. Unset identifiers appear as JSON `null`. Inspection and reporting still work. Assign and persist these values explicitly across normal server restarts. No host addresses or database credentials are used as identifiers. Use `WOLFTRAX_SYNTHETIC=1` only on a dedicated fixture server to declare its data synthetic.

Automatic alignment requires matching known namespace, incarnation, task, profile, selection, coverage and synthetic designation. A record’s ID is meaningful within that context. Identity metadata is producer-asserted. A clone or restore can copy all of it undetected. Equality cannot authenticate origin or establish continuity.

## What a freeze captures

The authenticated `GET /api/tasks/{id}/authority/casefile` route takes a canonical positive decimal task ID. It accepts no query parameters. Inside one read-only repeatable-read transaction, the first query checks that the task is visible and captures the producer’s statement time. The export includes task-only interception rows, ordered by creation time and ID descending. The successful result is complete for that selection. The assessment and other database writers continue during export. A task already deleted or archived at the transaction snapshot is unavailable. An archival committed later can coexist with a successful earlier capture. Previously distributed copies remain historical artifacts.

The v1 profile permits 2,000 records, 4 MiB of UTF-8 JSON and 4,096 UTF-8 bytes per string. Exceeding an export limit returns HTTP 413 before any casefile is sent. A visible empty task gets an empty array. Identifiers travel as canonical signed-int64-range positive decimal strings. Dates are UTC and nullable record times are explicit. The producer identifies the format as `wolftrax.authority.v1` and its implementation as `Wolftrax/1`. The format is distinct from ARTEX task archives, HAR and findings md-zip.

The SQL projection selects record identifiers, tool and agent display labels, decision state/source/actor, timestamps, correlation and run/call identifiers, recorded digests, captured rule/actions and outcome. Raw arguments, prompts, freeform reasons, context, output, target/approver addresses and traffic are excluded. Permitted display fields remain operator- or tool-supplied text and can contain sensitive information of their own.

The server applies the existing ARTEX operator-session boundary. It returns `Cache-Control: no-store` and `X-Casefile-SHA256` on the export. SHA-256 covers the complete response body before HTTP transfer encoding. The frontend checks that digest and downloads the original bytes. The hash stays outside the JSON. A digest supplied alongside an untrusted file provides a consistency check only. Independently compare the sidecar digest when you have a trusted copy. Browser hashing uses Web Crypto on HTTPS or localhost.

Import checks size before reading a file, enforces UTF-8, limits nesting to six, rejects duplicate JSON keys and record IDs, and checks field types, scopes, evidence assertions and the schema. A structurally valid unfamiliar decision or outcome remains available for inspection. Imported record values render as text. An authenticated task page can resolve an eligible historical row using an explicit source lookup. The server rechecks installation identity, visible task, recorded tool/run/call identifiers and unique activity linkage at lookup time. The file viewer never follows imported addresses.

## Reading the evidence

| Observation | Evidence available to the reviewer |
| --- | --- |
| Recorded approval | The operator/rule/model decision and the recorded deciding actor. Target-owner grants remain unrecorded. |
| Agent display label | A stored label. The projection supplies no authenticated agent identity. |
| Saved tool completion | The tool’s reported outcome. Independent effect receipts remain unrecorded. |
| Stored digest or matching file checksum | A recorded value or consistent file bytes. Origin remains `UNAUTHENTICATED`. |
| Database snapshot | A historical view of recorded interception decisions. Some dispatches lack any durable interception row. The database provides no immutable external witness. |
| Finding or claim | `CLAIM_NOT_ASSESSED`. The separate findings referee’s `VERIFIED` result concerns supported artifact checks with a matching external digest. |

The advisory rules cite record IDs. They flag missing audit/source, unavailable or ambiguous linkage, repeated call IDs, unknown decisions/outcomes, contradictory decisions and completions, missing or out-of-order times, and tool success without an independent receipt. Missing evidence leaves the underlying question unresolved.

Independent signatures and receipts, controlled reproduction, broker enforcement, revocation and durable budget accounting remain separate roadmap work. The prior Authority and referee qualifications describe their respective historical revisions.

[Investigation Lab qualification](wolftrax-investigation-qualification-v1.json) · [Historical Authority qualification](wolftrap-authority-qualification-v1.json) · [Historical referee qualification](wolftrap-qualification-v1.json)
