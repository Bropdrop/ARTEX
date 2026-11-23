package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

var casefileIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func casefileProducer() (db.CasefileProducer, error) {
	identity := func(key string) (*string, error) {
		v := os.Getenv(key)
		if v == "" {
			return nil, nil
		}
		if !casefileIdentityPattern.MatchString(v) {
			return nil, errors.New("invalid casefile identity configuration")
		}
		return &v, nil
	}
	namespace, err := identity("WOLFTRAX_SOURCE_NAMESPACE")
	if err != nil {
		return db.CasefileProducer{}, err
	}
	incarnation, err := identity("WOLFTRAX_DATASET_INCARNATION")
	return db.CasefileProducer{SourceNamespace: namespace, DatasetIncarnation: incarnation,
		Synthetic: os.Getenv("WOLFTRAX_SYNTHETIC") == "1"}, err
}

func (s *Server) taskAuthorityCasefile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	taskID, err := authorityTaskID(r.PathValue("id"))
	if err != nil || r.URL.RawQuery != "" {
		writeErr(w, 400, "expected a canonical task ID and the complete task selection")
		return
	}
	producer, err := casefileProducer()
	if err != nil {
		writeErr(w, 500, "invalid casefile identity configuration")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	data, err := pg.FreezeTaskAuthority(r.Context(), taskID, producer)
	switch {
	case errors.Is(err, db.ErrAuthorityTaskNotFound):
		writeErr(w, 404, "task not found or unavailable")
	case errors.Is(err, db.ErrCasefileLimit):
		writeErr(w, http.StatusRequestEntityTooLarge, "complete casefile exceeds 2000 records, 4096 UTF-8 bytes per field, or 4 MiB")
	case err != nil:
		writeErr(w, 500, "unable to export task authority records")
	default:
		digest := sha256.Sum256(data)
		w.Header().Set("X-Casefile-SHA256", hex.EncodeToString(digest[:]))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="wolftrax-task-`+r.PathValue("id")+`.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}

func (s *Server) taskAuthoritySource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	taskID, taskErr := authorityTaskID(r.PathValue("id"))
	recordID, recordErr := authorityTaskID(r.PathValue("record"))
	if taskErr != nil || recordErr != nil || r.URL.RawQuery != "" {
		writeErr(w, 400, "invalid task or record identity")
		return
	}
	var ref struct {
		SourceNamespace    string  `json:"source_namespace"`
		DatasetIncarnation string  `json:"dataset_incarnation"`
		RunID              *string `json:"run_id"`
		ToolUseID          string  `json:"tool_use_id"`
		ToolName           *string `json:"tool_name"`
	}
	// Escaped 4096-byte strings can require up to 6 input bytes per character.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 80<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&ref) != nil || dec.Decode(new(any)) != io.EOF || ref.RunID == nil || ref.ToolName == nil ||
		strings.TrimSpace(ref.ToolUseID) == "" || len(ref.ToolUseID) > db.CasefileMaxStringBytes || len(*ref.RunID) > db.CasefileMaxStringBytes || len(*ref.ToolName) > db.CasefileMaxStringBytes {
		writeErr(w, 400, "invalid casefile source reference")
		return
	}
	producer, err := casefileProducer()
	if err != nil {
		writeErr(w, 500, "invalid casefile identity configuration")
		return
	}
	if producer.SourceNamespace == nil || producer.DatasetIncarnation == nil || ref.SourceNamespace != *producer.SourceNamespace || ref.DatasetIncarnation != *producer.DatasetIncarnation {
		writeErr(w, 409, "source namespace or dataset incarnation is unknown or incompatible")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	target, err := pg.ResolveAuthoritySource(r.Context(), taskID, recordID, *ref.RunID, ref.ToolUseID, *ref.ToolName)
	if errors.Is(err, db.ErrInterceptSessionDeleted) || errors.Is(err, db.ErrInterceptExecutionUnavailable) {
		writeErr(w, 409, "exact source is unavailable or ambiguous for this task")
		return
	}
	if err != nil {
		writeErr(w, 500, "unable to resolve authority source")
		return
	}
	writeJSON(w, 200, target)
}
