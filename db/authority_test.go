package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuthorityAuditMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, raw, correlation, outcome string
		present                         bool
	}{
		{"legacy", "", AuthorityNotRecorded, AuthorityNotRecorded, false},
		{"json null", "null", AuthorityNotRecorded, AuthorityNotRecorded, false},
		{"partial", `{}`, AuthorityNotRecorded, AuthorityNotRecorded, true},
		{"reported success", `{"correlation":"exact","execution_status":"succeeded"}`, "exact", "succeeded", true},
		{"reported failure", `{"correlation":"exact","execution_status":"failed"}`, "exact", "failed", true},
		{"denied", `{"correlation":"exact","execution_status":"not_executed"}`, "exact", "not_executed", true},
		{"waiting", `{"correlation":"exact","execution_status":"awaiting_result"}`, "exact", "awaiting_result", true},
		{"pending", `{"correlation":"exact","execution_status":"not_started"}`, "exact", "not_started", true},
		{"ambiguous", `{"correlation":"ambiguous","execution_status":"unknown"}`, "ambiguous", "unknown", true},
		{"unavailable", `{"correlation":"unavailable","execution_status":"unknown"}`, "unavailable", "unknown", true},
		{"unrecognized remains unrecognized", `{"correlation":"future-state","execution_status":"future-outcome"}`, "future-state", "future-outcome", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got AuthorityRecord
			if err := got.applyAuditMetadata([]byte(tc.raw)); err != nil {
				t.Fatal(err)
			}
			if got.AuditPresent != tc.present || got.Correlation != tc.correlation || got.ExecutionStatus != tc.outcome {
				t.Fatalf("unexpected audit projection: %+v", got)
			}
		})
	}
	t.Run("allowlist and captured fields", func(t *testing.T) {
		var got AuthorityRecord
		err := got.applyAuditMetadata([]byte(`{
 "run_id":"run-a","tool_use_id":"call-a","correlation":"exact",
 "input_digest":"input-hash","config_digest":"config-hash","model_input_digest":"model-hash",
 "rule_name":"captured rule","initial_action":"ask","effective_action":"allow",
 "execution_status":"succeeded","execution_ended_at":"2026-01-02T03:04:05Z",
 "user_message":"PRIVATE_USER","context":[{"text":"PRIVATE_CONTEXT"}],
 "model_input":{"prompt":"PRIVATE_MODEL"},"output":"PRIVATE_OUTPUT",
 "initial_reason":"PRIVATE_REASON","decision_reason":"PRIVATE_DECISION",
 "approver_addr":"PRIVATE_ADDRESS","targets":[{"host":"PRIVATE_TARGET"}],
 "owner_grant":"verified","independent_effect":"verified"
}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.RunID != "run-a" || got.ToolUseID != "call-a" || got.InputDigest != "input-hash" || got.ConfigDigest != "config-hash" || got.ModelInputDigest != "model-hash" || got.RuleName != "captured rule" || got.InitialAction != "ask" || got.EffectiveAction != "allow" || got.ExecutionEndedAt == nil {
			t.Fatalf("captured metadata lost: %+v", got)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"PRIVATE_", `"owner_grant"`, `"independent_effect"`, `"output"`, `"context"`, `"model_input"`, `"approver_addr"`} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("unexpected projection content %q: %s", forbidden, raw)
			}
		}
	})
	for _, malformed := range []string{`{"correlation":3}`, `{"execution_ended_at":"not-a-time"}`, `[1]`} {
		var got AuthorityRecord
		if err := got.applyAuditMetadata([]byte(malformed)); err == nil {
			t.Fatalf("malformed typed metadata accepted: %s", malformed)
		}
	}
}

func TestAuthorityPaginationBounds(t *testing.T) {
	for _, tc := range [][2]int{{1, 1}, {1, AuthorityDefaultPageSize}, {AuthorityMaxPage, AuthorityMaxPageSize}} {
		if err := ValidateAuthorityPagination(tc[0], tc[1]); err != nil {
			t.Fatalf("valid pagination %v: %v", tc, err)
		}
	}
	// These must fail before trying to use the nil database handle.
	d := &DB{}
	for _, tc := range [][2]int{{0, 20}, {-1, 20}, {AuthorityMaxPage + 1, 20}, {1, 0}, {1, -1}, {1, AuthorityMaxPageSize + 1}} {
		if _, err := d.ListTaskAuthority(context.Background(), 1, tc[0], tc[1]); !errors.Is(err, ErrAuthorityPagination) {
			t.Fatalf("unbounded pagination %v accepted: %v", tc, err)
		}
	}
	if _, err := d.ListTaskAuthority(context.Background(), 0, 1, 20); !errors.Is(err, ErrAuthorityTaskNotFound) {
		t.Fatalf("invalid task accepted: %v", err)
	}
}

func TestTaskAuthorityProjection(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()
	newTask := func(name string) *Task {
		t.Helper()
		task, err := d.CreateTask(name, "authority fixture", nil, 0, 600)
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
	task, other, empty := newTask("authority"), newTask("other authority"), newTask("empty authority")
	scope := strconv.FormatInt(task.ID, 10)
	rule, err := d.CreateInterceptRule("current rule name", "tool_name", "string", "Bash", "ask", "PRIVATE_RULE_MESSAGE", 1, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_rules WHERE id=$1`, rule.ID) })
	ended := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixtures := []struct {
		status, source, actor string
		audit                 *InterceptAudit
	}{
		{"allowed", "unknown", "", nil},
		{"allowed", "model", "human", &InterceptAudit{
			RunID: "same-run", ToolUseID: "same-call", Correlation: "exact", InputDigest: "input-hash", ConfigDigest: "config-hash", ModelInputDigest: "model-hash",
			RuleName: "captured rule name", InitialAction: "ask", EffectiveAction: "allow", ExecutionStatus: "succeeded", ExecutionEndedAt: &ended,
			UserMessage: "PRIVATE_USER", Context: []InterceptContextEntry{{Text: "PRIVATE_CONTEXT"}}, ModelInput: json.RawMessage(`{"secret":"PRIVATE_MODEL"}`),
			InitialReason: "PRIVATE_INITIAL_REASON", DecisionReason: "PRIVATE_DECISION_REASON", Output: "PRIVATE_OUTPUT", ApproverAddr: "PRIVATE_ADDRESS",
			Targets: []InterceptTarget{{Host: "PRIVATE_TARGET", ResolvedIPs: []string{"PRIVATE_IP"}}},
		}},
		{"denied", "rule", "rule", &InterceptAudit{Correlation: "exact", InitialAction: "deny", EffectiveAction: "deny", ExecutionStatus: "not_executed"}},
		{"pending", "model", "", &InterceptAudit{Correlation: "ambiguous", InitialAction: "ask", ExecutionStatus: "not_started"}},
		{"timeout", "model", "system", &InterceptAudit{Correlation: "unavailable", InitialAction: "ask", EffectiveAction: "deny", ExecutionStatus: "not_executed"}},
		{"allowed", "target", "human", &InterceptAudit{Correlation: "unavailable", InitialAction: "ask", EffectiveAction: "allow", ExecutionStatus: "unknown"}},
	}
	ids := make([]int64, 0, len(fixtures))
	for _, fixture := range fixtures {
		var id int64
		if fixture.status == "pending" {
			id, err = d.CreateInterceptPending(rule.ID, 0, scope, "worker display", "Bash", []byte(`{"secret":"PRIVATE_INPUT"}`), "PRIVATE_REASON", fixture.audit)
		} else {
			id, err = d.CreateDecidedIntercept(rule.ID, 0, scope, "worker display", "Bash", []byte(`{"secret":"PRIVATE_INPUT"}`), fixture.status, "PRIVATE_REASON", fixture.audit)
		}
		if err != nil {
			t.Fatal(err)
		}
		storedSource := fixture.source
		if fixture.audit == nil {
			// Even with a rule ID, an unrecorded source remains unknown.
			storedSource = ""
		}
		if _, err := d.Exec(`UPDATE intercept_pending SET decision_source=$2, decided_by=$3, created_at='2026-01-01T00:00:00Z' WHERE id=$1`, id, storedSource, fixture.actor); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, err := d.Exec(`UPDATE intercept_rules SET name='renamed current rule' WHERE id=$1`, rule.ID); err != nil {
		t.Fatal(err)
	}
	// Matching run/call IDs in another task cannot enlarge this task's projection.
	if _, err := d.CreateDecidedIntercept(0, 0, strconv.FormatInt(other.ID, 10), "OTHER_SCOPE", "Bash", []byte(`{}`), "allowed", "other", fixtures[1].audit); err != nil {
		t.Fatal(err)
	}
	conv, err := d.CreateConversation("test", "authority mixed-scope fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID) })
	if _, err := d.CreateDecidedIntercept(0, conv.ID, scope, "MIXED_SCOPE", "Bash", []byte(`{}`), "allowed", "mixed scope"); err != nil {
		t.Fatal(err)
	}
	got, err := d.ListTaskAuthority(ctx, task.ID, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got.TaskID != scope || got.Total != len(fixtures) || len(got.Items) != len(fixtures) || got.Coverage != AuthorityCoverage || got.OwnerGrant != AuthorityNotRecorded || got.IndependentEffect != AuthorityNotRecorded {
		t.Fatalf("wrong page metadata or scope: %+v", got)
	}
	for index, record := range got.Items {
		fixtureIndex := len(fixtures) - 1 - index
		fixture := fixtures[fixtureIndex]
		if record.ID != ids[fixtureIndex] || record.TaskID != scope || record.Status != fixture.status || record.DecisionSource != fixture.source || record.DecidedBy != fixture.actor {
			t.Fatalf("order, state or actor conflated: %+v", record)
		}
		if fixture.audit == nil {
			if record.AuditPresent || record.Correlation != AuthorityNotRecorded || record.ExecutionStatus != AuthorityNotRecorded || record.RuleName != "" {
				t.Fatalf("legacy metadata invented from current rule: %+v", record)
			}
		} else if !record.AuditPresent || record.Correlation != fixture.audit.Correlation || record.ExecutionStatus != fixture.audit.ExecutionStatus || record.RuleName != fixture.audit.RuleName || record.InitialAction != fixture.audit.InitialAction || record.EffectiveAction != fixture.audit.EffectiveAction {
			t.Fatalf("audit changed or reconstructed: %+v", record)
		}
	}
	for _, record := range got.Items {
		if record.ID == ids[1] && (record.RunID != "same-run" || record.ToolUseID != "same-call" || record.InputDigest != "input-hash" || record.ConfigDigest != "config-hash" || record.ModelInputDigest != "model-hash" || record.ExecutionEndedAt == nil || !record.ExecutionEndedAt.Equal(ended)) {
			t.Fatalf("captured binding lost: %+v", record)
		}
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"PRIVATE_", "OTHER_SCOPE", "MIXED_SCOPE", "renamed current rule", `"tool_input"`, `"output"`, `"context"`, `"reason"`, `"model_input"`, `"approver_addr"`, `"targets"`} {
		if strings.Contains(string(raw), marker) {
			t.Fatalf("sensitive or cross-scope metadata leaked (%q): %s", marker, raw)
		}
	}
	second, err := d.ListTaskAuthority(ctx, task.ID, 2, 2)
	if err != nil || second.Total != len(fixtures) || len(second.Items) != 2 || second.Items[0].ID != ids[3] || second.Items[1].ID != ids[2] {
		t.Fatalf("unstable page: %+v %v", second, err)
	}
	// SQL JSON null is missing audit evidence just like SQL NULL.
	if _, err := d.Exec(`UPDATE intercept_pending SET audit='null'::jsonb WHERE id=$1`, ids[0]); err != nil {
		t.Fatal(err)
	}
	last, err := d.ListTaskAuthority(ctx, task.ID, len(fixtures), 1)
	if err != nil || len(last.Items) != 1 || last.Items[0].AuditPresent || last.Items[0].Correlation != AuthorityNotRecorded {
		t.Fatalf("JSON-null audit synthesized: %+v %v", last, err)
	}
	for _, id := range []int64{empty.ID, task.ID} {
		page := 1
		if id == task.ID {
			page = AuthorityMaxPage
		}
		result, err := d.ListTaskAuthority(ctx, id, page, 100)
		if err != nil || result.Items == nil || len(result.Items) != 0 {
			t.Fatalf("empty page became missing task: %+v %v", result, err)
		}
		if id == empty.ID && result.Total != 0 {
			t.Fatalf("empty task inherited records: %+v", result)
		}
	}
	for _, field := range []string{"archived_at", "deleted_at"} {
		if _, err := d.Exec(`UPDATE tasks SET `+field+`=NOW() WHERE id=$1`, task.ID); err != nil {
			t.Fatal(err)
		}
		if page, err := d.ListTaskAuthority(ctx, task.ID, 1, 20); !errors.Is(err, ErrAuthorityTaskNotFound) || page != nil {
			t.Fatalf("%s task exposed: %+v %v", field, page, err)
		}
		if _, err := d.Exec(`UPDATE tasks SET `+field+`=NULL WHERE id=$1`, task.ID); err != nil {
			t.Fatal(err)
		}
	}
	if page, err := d.ListTaskAuthority(ctx, 9223372036854775807, 1, 20); !errors.Is(err, ErrAuthorityTaskNotFound) || page != nil {
		t.Fatalf("unknown task accepted: %+v %v", page, err)
	}
	large := newTask("bounded authority")
	if _, err := d.Exec(`INSERT INTO intercept_pending(task_id,agent_name,tool_name,status,created_at)
SELECT $1,'bounded fixture','Bash','allowed','2026-01-01T00:00:00Z'::timestamptz FROM generate_series(1,105)`, fmt.Sprint(large.ID)); err != nil {
		t.Fatal(err)
	}
	first, err := d.ListTaskAuthority(ctx, large.ID, 1, 100)
	if err != nil || first.Total != 105 || len(first.Items) != 100 {
		t.Fatalf("first bounded page: %+v %v", first, err)
	}
	rest, err := d.ListTaskAuthority(ctx, large.ID, 2, 100)
	if err != nil || rest.Total != 105 || len(rest.Items) != 5 || rest.Items[0].ID >= first.Items[len(first.Items)-1].ID {
		t.Fatalf("remaining bounded page: %+v %v", rest, err)
	}
}
