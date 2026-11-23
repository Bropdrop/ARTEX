//go:build wolftrax_browser

package server

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// From the repo root, after building web/out, set an explicitly disposable
// ARTEX_PG_DSN and run go test -tags wolftrax_browser ./server -run '^TestInvestigationBrowser$' -count=1 -v.
// Requires python3, Playwright, and chromium. The tag keeps this loopback server
// and browser out of ordinary Go suites.
func TestInvestigationBrowser(t *testing.T) {
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Fatal("set an explicitly disposable ARTEX_PG_DSN")
	}
	static := os.Getenv("WOLFTRAX_STATIC")
	if static == "" {
		static = "../web/out"
	}
	if _, err := os.Stat(filepath.Join(static, "function/tasks/detail/index.html")); err != nil {
		t.Fatalf("build the static app before running the browser test: %v", err)
	}
	f := newCasefileFixture(t)
	t.Setenv("WOLFTRAX_SOURCE_NAMESPACE", "browser-fixture")
	t.Setenv("WOLFTRAX_DATASET_INCARNATION", "disposable-"+rand.Text())
	t.Setenv("WOLFTRAX_SYNTHETIC", "1")

	// Only these two production routes are reachable. Non-investigation shell
	// components receive local test responses. No Manager workers are started.
	files := http.FileServer(http.Dir(static))
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && !strings.HasPrefix(r.URL.Path, "/api/"):
			files.ServeHTTP(w, r)
		case r.Method != http.MethodGet:
			http.Error(w, "fixture is read-only", http.StatusMethodNotAllowed)
		case r.URL.Path == f.path || r.URL.Path == f.path+"/casefile":
			f.handler.ServeHTTP(w, r)
		case r.URL.Path == "/api/tasks/"+f.scope:
			writeJSON(w, 200, map[string]string{"id": f.scope, "name": "Synthetic reading room", "status": "done"})
		case strings.HasSuffix(r.URL.Path, "/stream"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			writeJSON(w, 200, struct{}{})
		default:
			files.ServeHTTP(w, r)
		}
	}))
	defer host.Close()
	out := t.TempDir()
	render := func(phase string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "python3", "../web/scripts/investigation-pg-browser.py", host.URL, f.scope, phase, out)
		cmd.Env = append(os.Environ(), "WOLFTRAX_FIXTURE_TOKEN="+f.token)
		log, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s browser check: %v\n%s", phase, err, log)
		}
		t.Log(strings.TrimSpace(string(log)))
	}
	record := func(tool string) int64 {
		t.Helper()
		id, err := f.d.CreateDecidedIntercept(0, 0, f.scope, "<script>fixtureLabel()</script>", tool,
			json.RawMessage(`{"argument":"EXCLUDED_FIXTURE_VALUE"}`), "allowed", "EXCLUDED_FIXTURE_REASON",
			&db.InterceptAudit{ExecutionStatus: "succeeded", Correlation: "unavailable"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := record("Catalog fixture")
	render("before")

	// A separate fixture writer runs between the completed browser sessions.
	// The browser itself has only GET access to the fixture.
	if _, err := f.d.Exec(`UPDATE intercept_pending SET status='denied' WHERE id=$1 AND task_id=$2`, first, f.scope); err != nil {
		t.Fatal(err)
	}
	record("Index fixture")
	render("after")
}
