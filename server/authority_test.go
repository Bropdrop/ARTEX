package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestAuthorityParams(t *testing.T) {
	for _, raw := range []string{"1", "123", "9223372036854775807"} {
		if id, err := authorityTaskID(raw); err != nil || strconv.FormatInt(id, 10) != raw {
			t.Fatalf("valid task rejected %q: %d %v", raw, id, err)
		}
	}
	for _, raw := range []string{"", "0", "-1", "+1", "01", "1.0", " 1", "1 ", "active", "9223372036854775808"} {
		if _, err := authorityTaskID(raw); err == nil {
			t.Fatalf("noncanonical task accepted: %q", raw)
		}
	}
	for _, tc := range []struct {
		query      string
		page, size int
	}{
		{"", 1, 20}, {"page=2&size=1", 2, 1}, {"page=1000000&size=100", 1000000, 100},
	} {
		q, err := url.ParseQuery(tc.query)
		if err != nil {
			t.Fatal(err)
		}
		page, size, err := authorityPageParams(q)
		if err != nil || page != tc.page || size != tc.size {
			t.Fatalf("pagination %q: %d %d %v", tc.query, page, size, err)
		}
	}
	for _, query := range []string{"page=", "size=", "page=0", "page=-1", "page=01", "page=%2B1", "page=1.1", "page=x", "size=0", "size=-1", "size=101", "page=1000001", "page=9223372036854775808", "size=9223372036854775808", "page=1&page=2", "size=1&size=1"} {
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := authorityPageParams(q); err == nil {
			t.Fatalf("unbounded/ambiguous pagination accepted: %q", query)
		}
	}
}

func TestAuthorityHTTPValidation(t *testing.T) {
	// This exercises the real authenticated mux with no database or runtime.
	s := &Server{m: &Manager{}, jwtKey: []byte("authority-validation-test-key")}
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := do(http.MethodGet, "/api/tasks/1/authority", false); got.Code != http.StatusUnauthorized {
		t.Fatalf("unprotected authority route: %d %s", got.Code, got.Body.String())
	}
	for _, path := range []string{
		"/api/tasks/0/authority", "/api/tasks/01/authority", "/api/tasks/+1/authority", "/api/tasks/active/authority", "/api/tasks/9223372036854775808/authority",
		"/api/tasks/1/authority?page=0", "/api/tasks/1/authority?size=101", "/api/tasks/1/authority?page=1000001", "/api/tasks/1/authority?page=1&page=2",
		"/api/tasks/1/authority?page=1;size=2", "/api/tasks/1/authority?size=%zz",
	} {
		if got := do(http.MethodGet, path, true); got.Code != http.StatusBadRequest {
			t.Fatalf("invalid scope/page %q: %d %s", path, got.Code, got.Body.String())
		}
	}
	if got := do(http.MethodPost, "/api/tasks/1/authority", true); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("authority route accepts mutations: %d %s", got.Code, got.Body.String())
	}
}

func TestAuthorityHTTPProjection(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	newTask := func(name string) *db.Task {
		t.Helper()
		task, err := d.CreateTask(name, "authority HTTP fixture", nil, 0, 600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, strconv.FormatInt(task.ID, 10))
			_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
			_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
		})
		return task
	}
	task, other := newTask("authority HTTP"), newTask("authority other HTTP")
	scope := strconv.FormatInt(task.ID, 10)
	// No manager entry is needed for a live database task. Later a deliberately
	// stale entry proves that the database still excludes an archived task.
	m := &Manager{pg: d, tasks: map[string]*Task{}}
	s := &Server{m: m, jwtKey: []byte("authority-projection-test-key")}
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	path := fmt.Sprintf("/api/tasks/%d/authority", task.ID)
	empty := do(path)
	var emptyPage db.AuthorityPage
	if empty.Code != http.StatusOK || json.Unmarshal(empty.Body.Bytes(), &emptyPage) != nil || emptyPage.Total != 0 || emptyPage.Items == nil || emptyPage.TaskID != scope || emptyPage.Page != 1 || emptyPage.Size != 20 {
		t.Fatalf("live empty task unavailable without manager entry: %d %s", empty.Code, empty.Body.String())
	}
	legacy, err := d.CreateDecidedIntercept(0, 0, scope, "worker display", "Bash", []byte(`{"secret":"HTTP_PRIVATE_INPUT"}`), "denied", "HTTP_PRIVATE_REASON")
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.CreateDecidedIntercept(0, 0, scope, "worker display", "Bash", []byte(`{"secret":"HTTP_PRIVATE_INPUT"}`), "allowed", "[model] HTTP_PRIVATE_REASON", &db.InterceptAudit{
		RunID: "http-run", ToolUseID: "http-call", Correlation: "exact", RuleName: "captured HTTP rule", InitialAction: "ask", EffectiveAction: "allow", ExecutionStatus: "succeeded",
		InputDigest: "http-input-hash", ConfigDigest: "http-config-hash", UserMessage: "HTTP_PRIVATE_USER", Output: "HTTP_PRIVATE_OUTPUT", ApproverAddr: "HTTP_PRIVATE_ADDRESS",
		Context: []db.InterceptContextEntry{{Text: "HTTP_PRIVATE_CONTEXT"}}, ModelInput: json.RawMessage(`{"secret":"HTTP_PRIVATE_MODEL"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE intercept_pending SET decided_by='human' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateDecidedIntercept(0, 0, strconv.FormatInt(other.ID, 10), "HTTP_OTHER_SCOPE", "Bash", []byte(`{}`), "allowed", "other"); err != nil {
		t.Fatal(err)
	}
	rec := do(path + "?page=1&size=1")
	var got db.AuthorityPage
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("authority response: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || got.TaskID != scope || got.Total != 2 || got.Page != 1 || got.Size != 1 || len(got.Items) != 1 || got.Items[0].ID != id {
		t.Fatalf("wrong projection page/cache policy: %s", rec.Body.String())
	}
	if got.Coverage != db.AuthorityCoverage || got.OwnerGrant != db.AuthorityNotRecorded || got.IndependentEffect != db.AuthorityNotRecorded || got.Items[0].DecisionSource != "model" || got.Items[0].DecidedBy != "human" || got.Items[0].ExecutionStatus != "succeeded" || got.Items[0].Correlation != "exact" {
		t.Fatalf("decision/result promoted or actor conflated: %s", rec.Body.String())
	}
	for _, marker := range []string{"HTTP_PRIVATE_", "HTTP_OTHER_SCOPE", `"tool_input"`, `"context"`, `"output"`, `"reason"`, `"model_input"`, `"approver_addr"`, `"source_available"`} {
		if strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("unrequested sensitive/availability field %q: %s", marker, rec.Body.String())
		}
	}
	second := do(path + "?page=2&size=1")
	var secondPage db.AuthorityPage
	if second.Code != http.StatusOK || json.Unmarshal(second.Body.Bytes(), &secondPage) != nil || secondPage.Total != 2 || len(secondPage.Items) != 1 || secondPage.Items[0].ID != legacy || secondPage.Items[0].AuditPresent || secondPage.Items[0].ExecutionStatus != db.AuthorityNotRecorded {
		t.Fatalf("legacy page: %d %s", second.Code, second.Body.String())
	}
	// Captured exact correlation is not a fresh availability check. No activity
	// was inserted, so the existing navigation API must independently refuse it.
	if source := do(fmt.Sprintf("/api/intercept/history/%d/execution", id)); source.Code != http.StatusGone {
		t.Fatalf("missing original execution was invented: %d %s", source.Code, source.Body.String())
	}
	m.tasks[scope] = &Task{ID: scope}
	for _, field := range []string{"archived_at", "deleted_at"} {
		if _, err := d.Exec(`UPDATE tasks SET `+field+`=NOW() WHERE id=$1`, task.ID); err != nil {
			t.Fatal(err)
		}
		if hidden := do(path); hidden.Code != http.StatusNotFound || strings.Contains(hidden.Body.String(), "http-run") {
			t.Fatalf("stale manager exposed %s task: %d %s", field, hidden.Code, hidden.Body.String())
		}
		if _, err := d.Exec(`UPDATE tasks SET `+field+`=NULL WHERE id=$1`, task.ID); err != nil {
			t.Fatal(err)
		}
	}
	if missing := do("/api/tasks/9223372036854775807/authority"); missing.Code != http.StatusNotFound {
		t.Fatalf("missing task: %d %s", missing.Code, missing.Body.String())
	}
	// A malformed typed field fails without leaking its value in an HTTP error.
	if _, err := d.Exec(`UPDATE intercept_pending SET audit=jsonb_set(audit,'{execution_ended_at}','"HTTP_PRIVATE_BAD_TIMESTAMP"') WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if bad := do(path); bad.Code != http.StatusInternalServerError || strings.Contains(bad.Body.String(), "HTTP_PRIVATE_") {
		t.Fatalf("malformed metadata exposed: %d %s", bad.Code, bad.Body.String())
	}
}
