package db

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Hold the record table while freeze establishes its snapshot on the task
// table. Wait until PostgreSQL observes the reader blocked on its FIRST
// record query, then commit conflicting writes. No sleep selects the winner.
func TestCasefileConcurrentWriters(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, field := range []string{"archived_at", "deleted_at"} {
		t.Run(field, func(t *testing.T) {
			task, err := d.CreateTask("synthetic snapshot", "test", nil, 0, 600)
			if err != nil {
				t.Fatal(err)
			}
			scope := fmt.Sprint(task.ID)
			t.Cleanup(func() {
				_, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, scope)
				_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
				_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
			})
			for _, name := range []string{"before update", "before removal"} {
				if _, err := d.CreateDecidedIntercept(0, 0, scope, name, "Fixture", []byte("{}"), "allowed", ""); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			writer, err := d.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback()
			if _, err = writer.ExecContext(ctx, `LOCK TABLE intercept_pending IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			type result struct {
				data []byte
				err  error
			}
			done := make(chan result, 1)
			go func() {
				data, err := d.FreezeTaskAuthority(ctx, task.ID, CasefileProducer{})
				done <- result{data, err}
			}()
			for {
				var waiting bool
				err = writer.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation='intercept_pending'::regclass AND NOT granted AND mode='AccessShareLock')`).Scan(&waiting)
				if err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			for _, q := range []string{
				`UPDATE intercept_pending SET agent_name='after' WHERE task_id=$1 AND agent_name='before update'`,
				`DELETE FROM intercept_pending WHERE task_id=$1 AND agent_name='before removal'`,
				`INSERT INTO intercept_pending(task_id,tool_name) VALUES ($1,'after')`,
			} {
				if _, err = writer.ExecContext(ctx, q, scope); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = writer.ExecContext(ctx, `UPDATE tasks SET `+field+`=now() WHERE id=$1`, task.ID); err != nil {
				t.Fatal(err)
			}
			if err = writer.Commit(); err != nil {
				t.Fatal(err)
			}
			got := <-done
			var file AuthorityCasefile
			if got.err != nil || json.Unmarshal(got.data, &file) != nil || file.Count != 2 || len(file.Records) != 2 ||
				!bytes.Contains(got.data, []byte("before update")) || !bytes.Contains(got.data, []byte("before removal")) || bytes.Contains(got.data, []byte("after")) {
				t.Fatalf("mixed or rejected historical snapshot: %s %v", got.data, got.err)
			}
			if _, err = d.FreezeTaskAuthority(ctx, task.ID, CasefileProducer{}); !errors.Is(err, ErrAuthorityTaskNotFound) {
				t.Fatalf("later capture of hidden task: %v", err)
			}
		})
	}
}
