package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Exercise the authenticated md-zip download using a synthetic stored exchange.
// The SHA pin is computed in the fixture. Its match tests the referee's artifact
// verdict, and cannot establish independent origin or any vulnerability claim.
func TestWolftraxFindingsExporterReferee(t *testing.T) {
	s, finding, request := trafficEvidenceServer(t)
	payload := []byte{0, 255, 0, 128, 13, 10, 17}
	seedServerEvidenceFlow(t, s, "wolftrax-fixture-v1", payload) // empty request body
	_, err := s.evidenceStore().Bind(t.Context(), finding.FindingID, []db.TrafficRef{
		{TrafficID: "wolftrax-fixture-v1", Role: "supporting", Note: "Synthetic exporter/referee fixture v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	download := request(http.MethodGet, fmt.Sprintf("/api/exploration/findings/export?format=md-zip&scope=selected&ids=%d", finding.FindingID), "")
	if download.Code != http.StatusOK {
		t.Fatalf("export failed with HTTP %d", download.Code)
	}
	verify := func(t *testing.T, data []byte, pin bool, status string, code, bindings int, issue string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "findings.zip")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"../scripts/wolftrap_evidence.py", "verify", path}
		digest := fmt.Sprintf("%x", sha256.Sum256(data))
		if pin {
			args = append(args, "--expected-sha256", digest)
		}
		output, err := exec.CommandContext(t.Context(), "python3", args...).Output()
		actualCode := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			actualCode = exit.ExitCode()
		}
		var report struct {
			Status   string
			Origin   string `json:"origin_status"`
			Claim    string `json:"claim_status"`
			Bindings int    `json:"bindings_verified"`
			Digest   string `json:"archive_sha256"`
			Errors   []struct{ Code string }
		}
		if err := json.Unmarshal(output, &report); err != nil {
			t.Fatal(err)
		}
		if actualCode != code || report.Status != status || report.Digest != digest || report.Bindings != bindings ||
			report.Origin != "UNAUTHENTICATED" || report.Claim != "CLAIM_NOT_ASSESSED" {
			t.Fatalf("referee exit %d: %s", actualCode, output)
		}
		if issue == "" && len(report.Errors) != 0 || issue != "" && (len(report.Errors) != 1 || report.Errors[0].Code != issue) {
			t.Fatalf("unexpected referee issues: %s", output)
		}
		t.Logf("synthetic md-zip sha256=%s status=%s bindings=%d issue=%q", digest, status, bindings, issue)
	}
	t.Run("unpinned", func(t *testing.T) { verify(t, download.Body.Bytes(), false, "INCONCLUSIVE", 2, 1, "UNPINNED_ARCHIVE") })
	t.Run("matching_pin", func(t *testing.T) { verify(t, download.Body.Bytes(), true, "VERIFIED", 0, 1, "") })
	t.Run("corrupt_binary", func(t *testing.T) {
		archive, err := zip.NewReader(bytes.NewReader(download.Body.Bytes()), int64(download.Body.Len()))
		if err != nil {
			t.Fatal(err)
		}
		// Keep a well-formed ZIP (including CRCs) but change an evidence byte.
		// Matching a fresh archive pin must still fail the internal body check.
		var corrupt bytes.Buffer
		zw := zip.NewWriter(&corrupt)
		var sawEmptyRequest, sawBinaryResponse bool
		for _, member := range archive.File {
			r, err := member.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(member.Name, "/request.bin") {
				sawEmptyRequest = len(data) == 0
			}
			if strings.HasSuffix(member.Name, "/response.bin") {
				if !bytes.Equal(data, payload) {
					t.Fatal("export did not preserve the binary fixture")
				}
				sawBinaryResponse = true
				data[0] ^= 1
			}
			w, err := zw.Create(member.Name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if !sawEmptyRequest || !sawBinaryResponse {
			t.Fatal("export omitted expected body bytes")
		}
		verify(t, corrupt.Bytes(), true, "INVALID", 1, 0, "BODY_HASH_MISMATCH")
	})
}
