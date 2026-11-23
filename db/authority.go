package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	AuthorityDefaultPageSize = 20
	AuthorityMaxPageSize     = 100
	AuthorityMaxPage         = 1_000_000
	AuthorityCoverage        = "recorded_interception_decisions"
	AuthorityNotRecorded     = "not_recorded"
)

var (
	ErrAuthorityTaskNotFound = errors.New("task not found or unavailable")
	ErrAuthorityPagination   = errors.New("invalid authority pagination")
)

// AuthorityRecord is a read-only projection of one recorded interception
// decision. It deliberately contains no inputs, prompts, reasons, outputs,
// target addresses or approver addresses. Correlation is the captured audit
// value, not a claim that the original execution is still available; navigation
// must go through GetInterceptExecution separately.
type AuthorityRecord struct {
	ID               int64      `json:"id"`
	TaskID           string     `json:"task_id"`
	AgentName        string     `json:"agent_name"`
	ToolName         string     `json:"tool_name"`
	Status           string     `json:"status"`
	DecisionSource   string     `json:"decision_source"`
	DecidedBy        string     `json:"decided_by"`
	CreatedAt        time.Time  `json:"created_at"`
	DecidedAt        *time.Time `json:"decided_at"`
	AuditPresent     bool       `json:"audit_present"`
	Correlation      string     `json:"correlation"`
	RunID            string     `json:"run_id"`
	ToolUseID        string     `json:"tool_use_id"`
	InputDigest      string     `json:"input_digest"`
	ConfigDigest     string     `json:"config_digest"`
	ModelInputDigest string     `json:"model_input_digest"`
	RuleName         string     `json:"rule_name"`
	InitialAction    string     `json:"initial_action"`
	EffectiveAction  string     `json:"effective_action"`
	ExecutionStatus  string     `json:"execution_status"`
	ExecutionEndedAt *time.Time `json:"execution_ended_at"`
}

// AuthorityPage describes only the recorded interception decisions in this
// page. ARTEX does not record every dispatch here. Operator decisions and tool
// results are not signed owner grants or independently witnessed effects.
type AuthorityPage struct {
	TaskID            string            `json:"task_id"`
	Items             []AuthorityRecord `json:"items"`
	Total             int               `json:"total"`
	Page              int               `json:"page"`
	Size              int               `json:"size"`
	Coverage          string            `json:"coverage"`
	OwnerGrant        string            `json:"owner_grant"`
	IndependentEffect string            `json:"independent_effect"`
}

// ValidateAuthorityPagination also protects non-HTTP callers and bounds offset
// arithmetic. Invalid values are rejected rather than silently changing scope.
func ValidateAuthorityPagination(page, size int) error {
	if page < 1 || page > AuthorityMaxPage {
		return fmt.Errorf("%w: page must be between 1 and %d", ErrAuthorityPagination, AuthorityMaxPage)
	}
	if size < 1 || size > AuthorityMaxPageSize {
		return fmt.Errorf("%w: size must be between 1 and %d", ErrAuthorityPagination, AuthorityMaxPageSize)
	}
	return nil
}

// Both queries apply this database visibility predicate. In particular a
// retained interception row cannot make a deleted/archived task visible, and a
// malformed row naming both a conversation and task is not a task-only record.
const authorityVisibleTask = `task.id=$1 AND task.deleted_at IS NULL AND task.archived_at IS NULL`
const authorityTaskRecords = `ip.task_id=task.id::text AND ip.conversation_id IS NULL`

// Unlike the legacy approval list, this view does not infer an unrecorded
// decision source from a current rule link or the text of a reason.
const authorityDecisionSource = `COALESCE(NULLIF(ip.decision_source,''),'unknown')`

// Select only allowed metadata inside PostgreSQL. Raw audit content is never
// loaded into the authority reader, even as an intermediate result. RuleName is
// the captured name, not the current name from a mutable intercept_rules join.
const authorityAuditProjection = `CASE WHEN ip.audit IS NULL OR ip.audit='null'::jsonb THEN NULL
ELSE jsonb_build_object(
 'correlation', ip.audit->'correlation',
 'run_id', ip.audit->'run_id',
 'tool_use_id', ip.audit->'tool_use_id',
 'input_digest', ip.audit->'input_digest',
 'config_digest', ip.audit->'config_digest',
 'model_input_digest', ip.audit->'model_input_digest',
 'rule_name', ip.audit->'rule_name',
 'initial_action', ip.audit->'initial_action',
 'effective_action', ip.audit->'effective_action',
 'execution_status', ip.audit->'execution_status',
 'execution_ended_at', ip.audit->'execution_ended_at'
) END`

type authorityAuditMetadata struct {
	Correlation      string     `json:"correlation"`
	RunID            string     `json:"run_id"`
	ToolUseID        string     `json:"tool_use_id"`
	InputDigest      string     `json:"input_digest"`
	ConfigDigest     string     `json:"config_digest"`
	ModelInputDigest string     `json:"model_input_digest"`
	RuleName         string     `json:"rule_name"`
	InitialAction    string     `json:"initial_action"`
	EffectiveAction  string     `json:"effective_action"`
	ExecutionStatus  string     `json:"execution_status"`
	ExecutionEndedAt *time.Time `json:"execution_ended_at"`
}

func (r *AuthorityRecord) applyAuditMetadata(raw []byte) error {
	r.Correlation, r.ExecutionStatus = AuthorityNotRecorded, AuthorityNotRecorded
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var audit authorityAuditMetadata
	if err := json.Unmarshal(raw, &audit); err != nil {
		return fmt.Errorf("read authority audit metadata: %w", err)
	}
	r.AuditPresent = true
	r.RunID, r.ToolUseID = audit.RunID, audit.ToolUseID
	r.InputDigest, r.ConfigDigest, r.ModelInputDigest = audit.InputDigest, audit.ConfigDigest, audit.ModelInputDigest
	r.RuleName = audit.RuleName
	r.InitialAction, r.EffectiveAction = audit.InitialAction, audit.EffectiveAction
	r.ExecutionEndedAt = audit.ExecutionEndedAt
	if audit.Correlation != "" {
		r.Correlation = audit.Correlation
	}
	if audit.ExecutionStatus != "" {
		r.ExecutionStatus = audit.ExecutionStatus
	}
	return nil
}

// ListTaskAuthority reads a bounded, sanitized page from a consistent database
// snapshot. The live task check is performed in SQL, independently of the
// manager's in-memory task map. Count and selection use the same visibility and
// scope predicates, with no per-record detail or execution queries.
func (d *DB) ListTaskAuthority(ctx context.Context, taskID int64, page, size int) (*AuthorityPage, error) {
	if taskID <= 0 {
		return nil, ErrAuthorityTaskNotFound
	}
	if err := ValidateAuthorityPagination(page, size); err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := &AuthorityPage{
		TaskID: strconv.FormatInt(taskID, 10), Items: []AuthorityRecord{}, Page: page, Size: size,
		Coverage: AuthorityCoverage, OwnerGrant: AuthorityNotRecorded, IndependentEffect: AuthorityNotRecorded,
	}
	// GROUP BY preserves the distinction between an existing empty task and an
	// unavailable task; COUNT(ip.id) excludes the empty LEFT JOIN row.
	err = tx.QueryRowContext(ctx, `SELECT COUNT(ip.id)
FROM tasks task LEFT JOIN intercept_pending ip ON `+authorityTaskRecords+`
WHERE `+authorityVisibleTask+` GROUP BY task.id`, taskID).Scan(&out.Total)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuthorityTaskNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, authoritySelect+` LIMIT $2 OFFSET $3`, taskID, size, int64(page-1)*int64(size))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		record, err := scanAuthorityRecord(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

const authoritySelect = `SELECT ip.id, ip.task_id, ip.agent_name, ip.tool_name,
ip.status, ` + authorityDecisionSource + `, ip.decided_by, ip.created_at, ip.decided_at, ` + authorityAuditProjection + `
FROM tasks task JOIN intercept_pending ip ON ` + authorityTaskRecords + `
WHERE ` + authorityVisibleTask + `
ORDER BY ip.created_at DESC, ip.id DESC`

func scanAuthorityRecord(rows *sql.Rows) (AuthorityRecord, error) {
	var record AuthorityRecord
	var auditMetadata []byte
	err := rows.Scan(&record.ID, &record.TaskID, &record.AgentName, &record.ToolName,
		&record.Status, &record.DecisionSource, &record.DecidedBy, &record.CreatedAt, &record.DecidedAt, &auditMetadata)
	if err == nil {
		err = record.applyAuditMetadata(auditMetadata)
	}
	return record, err
}
