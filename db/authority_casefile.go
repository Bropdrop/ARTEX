package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const (
	CasefileMaxRecords     = 2000
	CasefileMaxBytes       = 4 << 20
	CasefileMaxStringBytes = 4096
)

var ErrCasefileLimit = errors.New("casefile exceeds the record, field or byte limit")

// CasefileProducer describes this installation. Unconfigured identifiers remain
// null; operators must rotate the incarnation when cloning/restoring a dataset.
type CasefileProducer struct {
	SourceNamespace    *string `json:"source_namespace"`
	DatasetIncarnation *string `json:"dataset_incarnation"`
	Synthetic          bool    `json:"synthetic"`
}

type AuthorityCasefile struct {
	CasefileProducer
	Schema            string            `json:"schema"`
	Producer          string            `json:"producer"`
	TaskID            string            `json:"task_id"`
	CapturedAt        time.Time         `json:"captured_at"`
	Selection         string            `json:"selection"`
	Coverage          string            `json:"coverage"`
	Complete          bool              `json:"complete"`
	Count             int               `json:"count"`
	OwnerGrant        string            `json:"owner_grant"`
	IndependentEffect string            `json:"independent_effect"`
	Origin            string            `json:"origin"`
	Claim             string            `json:"claim"`
	Records           []json.RawMessage `json:"records"`
}

// FreezeTaskAuthority produces the complete document before the first byte can
// be sent. A later write (including archival) does not invalidate the snapshot.
func (d *DB) FreezeTaskAuthority(ctx context.Context, taskID int64, producer CasefileProducer) ([]byte, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	captured, err := casefileCaptureTime(ctx, tx, taskID)
	if err != nil {
		return nil, err
	}
	body, err := encodeCasefileSnapshot(ctx, tx, taskID, producer, captured)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return body, nil
}

func casefileCaptureTime(ctx context.Context, tx *sql.Tx, taskID int64) (time.Time, error) {
	var captured time.Time
	err := tx.QueryRowContext(ctx, `SELECT statement_timestamp() FROM tasks task WHERE `+authorityVisibleTask, taskID).Scan(&captured)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrAuthorityTaskNotFound
	}
	return captured.UTC(), err
}

func encodeCasefileSnapshot(ctx context.Context, tx *sql.Tx, taskID int64, producer CasefileProducer, captured time.Time) ([]byte, error) {
	scope := strconv.FormatInt(taskID, 10)
	var count int
	// LIMIT also bounds the amount of counting work for a very large task.
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
 SELECT 1 FROM intercept_pending WHERE task_id=$1 AND conversation_id IS NULL LIMIT $2
) bounded`, scope, CasefileMaxRecords+1).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > CasefileMaxRecords {
		return nil, ErrCasefileLimit
	}
	// Reject oversized selected fields inside PostgreSQL, before any such data
	// crosses the connection. Excluded audit keys do not contribute to this cap.
	var oversized bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM intercept_pending ip WHERE ip.task_id=$1 AND ip.conversation_id IS NULL
 AND (GREATEST(octet_length(ip.tool_name),octet_length(ip.agent_name),octet_length(ip.status),
      octet_length(ip.decision_source),octet_length(ip.decided_by)) > $2 OR EXISTS (
   SELECT 1 FROM jsonb_each_text(`+authorityAuditProjection+`) AS field
   WHERE octet_length(field.value)>$2)))`, scope, CasefileMaxStringBytes).Scan(&oversized)
	if err != nil {
		return nil, err
	}
	if oversized {
		return nil, ErrCasefileLimit
	}
	file := AuthorityCasefile{
		CasefileProducer: producer, Schema: "wolftrax.authority.v1", Producer: "Wolftrax/1",
		TaskID: scope, CapturedAt: captured, Selection: "all_task_only",
		Coverage: AuthorityCoverage, Complete: true, Count: count, OwnerGrant: AuthorityNotRecorded,
		IndependentEffect: AuthorityNotRecorded, Origin: "UNAUTHENTICATED", Claim: "CLAIM_NOT_ASSESSED",
		Records: make([]json.RawMessage, 0, count),
	}
	rows, err := tx.QueryContext(ctx, authoritySelect, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	totalBytes := 0
	for rows.Next() {
		r, err := scanAuthorityRecord(rows)
		if err != nil {
			return nil, err
		}
		if r.ID <= 0 {
			return nil, errors.New("invalid authority record identity")
		}
		r.CreatedAt = r.CreatedAt.UTC()
		r.DecidedAt = casefileUTCTime(r.DecidedAt)
		r.ExecutionEndedAt = casefileUTCTime(r.ExecutionEndedAt)
		// Keep the existing sanitized fields, but carry int64 IDs losslessly
		// across JavaScript and systems whose JSON numbers are IEEE doubles.
		record, err := json.Marshal(struct {
			AuthorityRecord
			ID string `json:"id"`
		}{r, strconv.FormatInt(r.ID, 10)})
		if err != nil {
			return nil, err
		}
		totalBytes += len(record)
		if totalBytes > CasefileMaxBytes {
			return nil, ErrCasefileLimit
		}
		file.Records = append(file.Records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(file.Records) != count {
		return nil, errors.New("casefile count disagrees with selection")
	}
	body, err := json.Marshal(file)
	if err != nil {
		return nil, err
	}
	if len(body) > CasefileMaxBytes {
		return nil, ErrCasefileLimit
	}
	return body, nil
}

func casefileUTCTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

// ResolveAuthoritySource verifies historical linkage in one current statement
// snapshot. Imported text is a bound lookup value, never a URL, session name or
// activity address. Only navigation metadata is returned.
func (d *DB) ResolveAuthoritySource(ctx context.Context, taskID, recordID int64, runID, callID, toolName string) (*InterceptExecution, error) {
	if callID == "" {
		return nil, ErrInterceptExecutionUnavailable
	}
	rows, err := d.QueryContext(ctx, `SELECT a.id, a.node_id, COALESCE(a.worker,''), a.kind, COALESCE(a.tool,''), a.main_seg
FROM tasks task JOIN intercept_pending ip ON `+authorityTaskRecords+`
JOIN activity a ON a.exploration_id=task.exploration_id AND a.tool_use_id=$4 AND a.kind IN ('tool_use','tool_result')
WHERE `+authorityVisibleTask+` AND ip.id=$2
 AND COALESCE(NULLIF(ip.audit->'run_id','null'::jsonb),'""'::jsonb)=to_jsonb($3::text)
 AND ip.audit->>'correlation'='exact' AND ip.audit->'tool_use_id'=to_jsonb($4::text) AND ip.tool_name=$5
 AND NOT EXISTS (SELECT 1 FROM intercept_pending other WHERE other.task_id=ip.task_id
   AND other.conversation_id IS NULL AND other.id<>ip.id AND other.audit->>'tool_use_id'=$4)
ORDER BY a.id LIMIT 3`, taskID, recordID, runID, callID, toolName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scope := strconv.FormatInt(taskID, 10)
	out := &InterceptExecution{TaskID: &scope}
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.ID, &a.NodeID, &a.Worker, &a.Kind, &a.Tool, &a.MainSeg); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return validatedInterceptExecution(out, toolName)
}
