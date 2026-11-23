package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestInvestigationDemo creates only synthetic records in the server test
// database. WOLFTRAX_DEMO_DIR optionally keeps the exact handler responses for
// browser tests or human review. Synthetic labels come from the fixture server.
func TestInvestigationDemo(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("an explicit disposable ARTEX_PG_DSN is required")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// A fresh fixture run is a separate dataset even if PostgreSQL reuses IDs.
	incarnation := "fixture-" + rand.Text()
	t.Setenv("WOLFTRAX_SOURCE_NAMESPACE", "synthetic-wolftrax-demo")
	t.Setenv("WOLFTRAX_DATASET_INCARNATION", incarnation)
	t.Setenv("WOLFTRAX_SYNTHETIC", "1")
	task, err := d.CreateTask("Synthetic reading room", "Investigation Lab review fixture v1", nil, 0, 600)
	if err != nil {
		t.Fatal(err)
	}
	scope := strconv.FormatInt(task.ID, 10)
	t.Cleanup(func() {
		_, _ = d.Exec("DELETE FROM intercept_pending WHERE task_id=$1", scope)
		_, _ = d.Exec("DELETE FROM tasks WHERE id=$1", task.ID)
		_, _ = d.Exec("DELETE FROM explorations WHERE id=$1", task.ExplorationID)
	})

	out := os.Getenv("WOLFTRAX_DEMO_DIR")
	var checksums bytes.Buffer
	freeze := func(name string, count int) {
		t.Helper()
		s := &Server{m: &Manager{pg: d}, jwtKey: []byte("synthetic-investigation-fixture")}
		token, err := signJWT(s.jwtKey)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/tasks/"+scope+"/authority/casefile", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: freeze status %d", name, rec.Code)
		}
		body := rec.Body.Bytes()
		digest := fmt.Sprintf("%x", sha256.Sum256(body))
		if digest != rec.Header().Get("X-Casefile-SHA256") || bytes.Contains(body, []byte("EXCLUDED_DEMO_")) {
			t.Fatalf("%s: body hash/redaction failed", name)
		}
		var meta struct {
			Synthetic          bool
			Count              int
			Records            []json.RawMessage
			Coverage           string
			DatasetIncarnation string `json:"dataset_incarnation"`
			TaskID             string `json:"task_id"`
		}
		if err := json.Unmarshal(body, &meta); err != nil {
			t.Fatal(err)
		}
		if !meta.Synthetic || meta.TaskID != scope || meta.Coverage != db.AuthorityCoverage ||
			meta.DatasetIncarnation != os.Getenv("WOLFTRAX_DATASET_INCARNATION") ||
			meta.Count != count || meta.Records == nil || len(meta.Records) != count {
			t.Fatalf("%s: invalid fixture scope/lineage/count", name)
		}
		if out != "" {
			filename := name + ".json"
			if err := os.WriteFile(filepath.Join(out, filename), body, 0600); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&checksums, "%s  %s\n", digest, filename)
		}
	}
	freeze("empty", 0)

	// Fixed recorded times make timestamp ordering observable across runs.
	// PostgreSQL assigns the IDs and the producer assigns each capture time.
	start := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	var rowOrdinal int
	insert := func(tool, agent, status, source, actor string, audit *db.InterceptAudit) int64 {
		t.Helper()
		rowOrdinal++
		var auditJSON any
		if audit != nil {
			audit.UserMessage = "EXCLUDED_DEMO_USER_MESSAGE"
			audit.Output = "EXCLUDED_DEMO_TOOL_OUTPUT"
			audit.ApproverAddr = "EXCLUDED_DEMO_APPROVER"
			raw, err := json.Marshal(audit)
			if err != nil {
				t.Fatal(err)
			}
			auditJSON = string(raw)
		}
		created := start.Add(time.Duration(rowOrdinal) * time.Minute)
		var decided any
		if status != "pending" {
			decided = created.Add(5 * time.Second)
		}
		var id int64
		err := d.QueryRow(`INSERT INTO intercept_pending
			(task_id,tool_name,agent_name,status,decision_source,decided_by,audit,created_at,decided_at,tool_input,reason)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,'{"text":"EXCLUDED_DEMO_ARGUMENT"}','EXCLUDED_DEMO_REASON')
			RETURNING id`, scope, tool, agent, status, source, actor, auditJSON, created, decided).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	finished := start.Add(time.Minute + 10*time.Second)
	insert("Catalog", "Reader", "allowed", "model", "human", &db.InterceptAudit{
		Correlation: "exact", RunID: "demo-reading", ToolUseID: "catalog-card",
		InitialAction: "ask", EffectiveAction: "allow", ExecutionStatus: "succeeded", ExecutionEndedAt: &finished,
	})
	insert("Index", "Binder", "denied", "rule", "rule", &db.InterceptAudit{
		Correlation: "ambiguous", RunID: "demo-reading", ToolUseID: "index-card",
		InitialAction: "deny", EffectiveAction: "deny", ExecutionStatus: "succeeded",
	})
	insert("Index", "<script>fixtureLabel()</script>", "pending", "model", "", &db.InterceptAudit{
		Correlation: "ambiguous", RunID: "demo-reading", ToolUseID: "index-card", InitialAction: "ask", ExecutionStatus: "not_started",
	})
	legacy := insert("Legacy card", "Archivist", "allowed", "", "", nil)
	updated := insert("Shelf count", "Reader", "allowed", "rule", "rule", &db.InterceptAudit{
		Correlation: "unavailable", ExecutionStatus: "demo_future_outcome",
	})
	freeze("before", 5)

	// This mutation models two ordinary snapshots differing in membership and
	// saved values. A consumer of the snapshots cannot observe its cause.
	if _, err := d.Exec("DELETE FROM intercept_pending WHERE id=$1 AND task_id=$2", legacy, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE intercept_pending SET audit=jsonb_set(audit,'{execution_status}','"failed"') WHERE id=$1 AND task_id=$2`, updated, scope); err != nil {
		t.Fatal(err)
	}
	insert("Reading log", "Clerk", "timeout", "model", "system", &db.InterceptAudit{
		Correlation: "unavailable", ExecutionStatus: "not_executed",
	})
	freeze("after", 5)
	t.Setenv("WOLFTRAX_DATASET_INCARNATION", "restored-"+rand.Text())
	freeze("restored", 5)

	if out != "" {
		// Record-count boundary fixture for the rendered workbench. Generated in
		// one statement and left out of the checked-in example pack.
		t.Setenv("WOLFTRAX_DATASET_INCARNATION", incarnation)
		_, err := d.Exec(`INSERT INTO intercept_pending(task_id,agent_name,tool_name,status,created_at)
			SELECT $1,'Synthetic reader ' || (n%10), 'Read card ' || n,'pending',
				'2026-01-05T13:00:00Z'::timestamptz + n * interval '1 second'
			FROM generate_series(1,1995) AS series(n)`, scope)
		if err != nil {
			t.Fatal(err)
		}
		freeze("large", 2000)
		if err := os.WriteFile(filepath.Join(out, "SHA256SUMS"), checksums.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
