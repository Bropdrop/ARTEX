package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

func authorityTaskID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != raw {
		return 0, errors.New("task id must be a canonical positive integer")
	}
	return id, nil
}

func authorityPageParams(q url.Values) (int, int, error) {
	read := func(key string, fallback int) (int, error) {
		values, ok := q[key]
		if !ok {
			return fallback, nil
		}
		if len(values) != 1 {
			return 0, fmt.Errorf("%s must appear once", key)
		}
		value, err := strconv.Atoi(values[0])
		if err != nil || strconv.Itoa(value) != values[0] {
			return 0, fmt.Errorf("%s must be a canonical positive integer", key)
		}
		return value, nil
	}
	page, err := read("page", 1)
	if err != nil {
		return 0, 0, err
	}
	size, err := read("size", db.AuthorityDefaultPageSize)
	if err != nil {
		return 0, 0, err
	}
	if err := db.ValidateAuthorityPagination(page, size); err != nil {
		return 0, 0, err
	}
	return page, size, nil
}

// taskAuthority is observational only. It never dispatches a tool, approves a
// request, or upgrades a recorded tool result into independent effect proof.
func (s *Server) taskAuthority(w http.ResponseWriter, r *http.Request) {
	taskID, err := authorityTaskID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid authority query")
		return
	}
	page, size, err := authorityPageParams(query)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	result, err := pg.ListTaskAuthority(r.Context(), taskID, page, size)
	if errors.Is(err, db.ErrAuthorityTaskNotFound) {
		writeErr(w, http.StatusNotFound, "task not found or unavailable")
		return
	}
	if err != nil {
		// Audit values and database diagnostics do not belong in this projection.
		writeErr(w, http.StatusInternalServerError, "unable to load authority records")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}
