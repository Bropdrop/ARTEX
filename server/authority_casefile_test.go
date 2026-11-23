package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

type casefileFixture struct {
	d                  *db.DB
	task               *db.Task
	scope, path, token string
	handler            http.Handler
}

func newCasefileFixture(t *testing.T) *casefileFixture {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("synthetic casefile test", "fixture", nil, 0, 600)
	if err != nil {
		t.Fatal(err)
	}
	scope := strconv.FormatInt(task.ID, 10)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, scope)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
	})
	s := &Server{m: &Manager{pg: d, tasks: map[string]*Task{}}, jwtKey: []byte("casefile-test-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	return &casefileFixture{d, task, scope, "/api/tasks/" + scope + "/authority", token, s.Handler()}
}

func (f *casefileFixture) request(method, path, body string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

func TestCasefileHTTP(t *testing.T) {
	f := newCasefileFixture(t)
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() {
		log.SetOutput(previous)
		if strings.Contains(logs.String(), "PRIVATE_") {
			t.Error("excluded value written to the application log")
		}
	})
	for _, key := range []string{"WOLFTRAX_SOURCE_NAMESPACE", "WOLFTRAX_DATASET_INCARNATION", "WOLFTRAX_SYNTHETIC"} {
		t.Setenv(key, "")
	}
	path := f.path + "/casefile"
	get := func() *httptest.ResponseRecorder { return f.request("GET", path, "", true) }
	if w := f.request("GET", path, "", false); w.Code != 401 {
		t.Fatalf("unauthenticated export: %d", w.Code)
	}
	for _, p := range []string{path + "?page=1", "/api/tasks/0" + f.scope + "/authority/casefile"} {
		if w := f.request("GET", p, "", true); w.Code != 400 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("invalid scope: %d", w.Code)
		}
	}
	var file db.AuthorityCasefile
	w := get()
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &file) != nil || file.Count != 0 || file.Records == nil || !file.Complete || file.TaskID != f.scope || file.SourceNamespace != nil || file.DatasetIncarnation != nil || file.Synthetic || file.CapturedAt.IsZero() {
		t.Fatalf("empty selection: %s", w.Body)
	}
	id, err := f.d.CreateDecidedIntercept(0, 0, f.scope, "<script>fixture()</script>", "Fixture", []byte(`{"prompt":"PRIVATE_BODY"}`), "allowed", "PRIVATE_REASON", &db.InterceptAudit{
		Correlation: "exact", ToolUseID: "fixture-call", RunID: "fixture-run",
		InputDigest: "recorded-input", EffectiveAction: "allow", ExecutionStatus: "succeeded",
		ApproverAddr: "PRIVATE_ADDR", UserMessage: "PRIVATE_USER", ModelInput: json.RawMessage(`{"prompt":"PRIVATE_MODEL"}`),
		Context: []db.InterceptContextEntry{{Text: "PRIVATE_CONTEXT"}}, Output: "PRIVATE_OUTPUT",
		Targets: []db.InterceptTarget{{Host: "PRIVATE_TARGET"}}, DecisionReason: "PRIVATE_DECISION",
	})
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := f.d.CreateConversation("test", "mixed scope", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.d.Exec(`DELETE FROM conversations WHERE id=$1`, mixed.ID) })
	if _, err := f.d.CreateDecidedIntercept(0, mixed.ID, f.scope, "PRIVATE_MIXED", "Fixture", []byte("{}"), "denied", ""); err != nil {
		t.Fatal(err)
	}
	// This value is outside the range of exact JavaScript numbers.
	const wideID = int64(9007199254740993)
	if _, err = f.d.Exec(`UPDATE intercept_pending SET id=$1 WHERE id=$2`, wideID, id); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WOLFTRAX_SOURCE_NAMESPACE", "synthetic-lab")
	t.Setenv("WOLFTRAX_DATASET_INCARNATION", "v1")
	t.Setenv("WOLFTRAX_SYNTHETIC", "1")
	w = get()
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "PRIVATE_") || json.Unmarshal(w.Body.Bytes(), &file) != nil || file.Count != 1 || len(file.Records) != 1 ||
		file.OwnerGrant != "not_recorded" || file.IndependentEffect != "not_recorded" || file.Origin != "UNAUTHENTICATED" || file.Claim != "CLAIM_NOT_ASSESSED" ||
		file.Schema != "wolftrax.authority.v1" || file.Coverage != db.AuthorityCoverage || file.Selection != "all_task_only" || file.Producer != "Wolftrax/1" || !file.Synthetic || file.SourceNamespace == nil || *file.SourceNamespace != "synthetic-lab" || file.DatasetIncarnation == nil || *file.DatasetIncarnation != "v1" {
		t.Fatalf("wrong capture metadata, redaction or scope: status %d", w.Code)
	}
	var r map[string]any
	if err = json.Unmarshal(file.Records[0], &r); err != nil || r["id"] != "9007199254740993" || r["tool_use_id"] != "fixture-call" || r["input_digest"] != "recorded-input" || r["agent_name"] != "<script>fixture()</script>" {
		t.Fatal("lossy capture")
	}
	if got := w.Header().Get("X-Casefile-SHA256"); got != fmt.Sprintf("%x", sha256.Sum256(w.Body.Bytes())) || got == fmt.Sprintf("%x", sha256.Sum256(append(w.Body.Bytes(), ' '))) {
		t.Fatal("digest not bound to exact bytes")
	}
	if _, err = f.d.Exec(`UPDATE intercept_pending SET audit=jsonb_set(audit,'{execution_ended_at}','"PRIVATE_INVALID_TIME"') WHERE id=$1`, wideID); err != nil {
		t.Fatal(err)
	}
	if w = get(); w.Code != 500 || strings.Contains(w.Body.String(), "PRIVATE") || w.Header().Get("X-Casefile-SHA256") != "" {
		t.Fatal("malformed record leaked or exported")
	}
}

func TestCasefileHTTPLimits(t *testing.T) {
	f := newCasefileFixture(t)
	check := func(want int) {
		t.Helper()
		w := f.request("GET", f.path+"/casefile", "", true)
		if w.Code != want || (want != 200 && (w.Header().Get("X-Casefile-SHA256") != "" || strings.Contains(w.Body.String(), `"records"`))) {
			t.Fatalf("wanted %d, got %d", want, w.Code)
		}
	}
	update := func(query string, args ...any) {
		t.Helper()
		if _, err := f.d.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	update(`INSERT INTO intercept_pending(task_id,tool_name) SELECT $1,'Fixture' FROM generate_series(1,$2)`, f.scope, db.CasefileMaxRecords)
	check(200)
	update(`INSERT INTO intercept_pending(task_id,tool_name) VALUES ($1,'extra')`, f.scope)
	check(413)
	update(`DELETE FROM intercept_pending WHERE task_id=$1 AND tool_name='extra'`, f.scope)
	// Under each individual field ceiling, above the complete byte ceiling.
	update(`UPDATE intercept_pending SET agent_name=repeat('A',2200) WHERE task_id=$1`, f.scope)
	check(413)
	update(`DELETE FROM intercept_pending WHERE task_id=$1 AND id<>(SELECT min(id) FROM intercept_pending WHERE task_id=$1)`, f.scope)
	update(`UPDATE intercept_pending SET audit=jsonb_build_object('rule_name',repeat('é',2048)) WHERE task_id=$1`, f.scope)
	check(200)
	update(`UPDATE intercept_pending SET audit=jsonb_build_object('rule_name',repeat('é',2049)) WHERE task_id=$1`, f.scope)
	check(413)
}

func TestCasefileHTTPSource(t *testing.T) {
	f := newCasefileFixture(t)
	t.Setenv("WOLFTRAX_SOURCE_NAMESPACE", "test")
	t.Setenv("WOLFTRAX_DATASET_INCARNATION", "first")
	id, err := f.d.CreateDecidedIntercept(0, 0, f.scope, "display", "Fixture", []byte("{}"), "allowed", "", &db.InterceptAudit{Correlation: "exact", ToolUseID: "call", RunID: "run"})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("%s/records/%d/source", f.path, id)
	ref := `{"source_namespace":"test","dataset_incarnation":"first","tool_use_id":"call","run_id":"run","tool_name":"Fixture"}`
	expect := func(p, body string, auth bool, code int) *httptest.ResponseRecorder {
		t.Helper()
		w := f.request("POST", p, body, auth)
		if w.Code != code {
			t.Fatalf("wanted %d got %d: %s", code, w.Code, w.Body)
		}
		return w
	}
	expect(path, ref, false, 401)
	expect(path, ref, true, 409)
	activity := db.Activity{Worker: "mainagent", Kind: "tool_use", Tool: "Fixture", ToolUseID: "call", Summary: "PRIVATE_BODY"}
	seq, err := f.d.Exploration(f.task.ExplorationID).AppendActivity(activity)
	if err != nil {
		t.Fatal(err)
	}
	w := expect(path, ref, true, 200)
	var found db.InterceptExecution
	if json.Unmarshal(w.Body.Bytes(), &found) != nil || found.Seq != seq || found.Session != "main:0" || found.TaskID == nil || *found.TaskID != f.scope || strings.Contains(w.Body.String(), "PRIVATE_") || strings.Contains(w.Body.String(), `"items"`) {
		t.Fatal("unsafe navigation result")
	}
	for _, old := range []string{`"test"`, `"first"`, `"call"`, `"run"`, `"Fixture"`} {
		expect(path, strings.Replace(ref, old, `"other"`, 1), true, 409)
	}
	expect(strings.Replace(path, "/tasks/"+f.scope+"/", "/tasks/9223372036854775807/", 1), ref, true, 409)
	t.Setenv("WOLFTRAX_SOURCE_NAMESPACE", "")
	expect(path, ref, true, 409)
	t.Setenv("WOLFTRAX_SOURCE_NAMESPACE", "test")
	if _, err = f.d.Exec(`UPDATE tasks SET archived_at=now() WHERE id=$1`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	expect(path, ref, true, 409)
	if _, err = f.d.Exec(`UPDATE tasks SET archived_at=NULL WHERE id=$1`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.Exploration(f.task.ExplorationID).AppendActivity(activity); err != nil {
		t.Fatal(err)
	}
	expect(path, ref, true, 409)
}
