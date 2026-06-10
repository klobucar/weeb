package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "charm.land/log/v2"
)

// TestMain points the history file at a throwaway dir for the WHOLE test
// binary: many existing tests drive Client.Do, which now records history, and
// none of them should touch the developer's real cache dir.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "weeb-history-test")
	if err != nil {
		panic(err)
	}
	historyPath = func() (string, error) {
		return filepath.Join(dir, "history.jsonl"), nil
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// useHistoryFile points historyPath at a fresh per-test file and restores the
// previous resolver afterwards.
func useHistoryFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.jsonl")
	old := historyPath
	historyPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { historyPath = old })
	return path
}

func TestHistoryRedaction(t *testing.T) {
	spec := RequestSpec{
		Method: "GET",
		URL:    "https://api.example.com/me",
		Headers: []Header{
			{Key: "Authorization", Value: "Bearer hunter2"},
			{Key: "X-Api-Key", Value: "sekrit"},
			{Key: "Accept", Value: "application/json"},
		},
	}
	e := newHistoryEntry(spec, Result{Method: "GET", URL: spec.URL, Status: 200})

	got := map[string]string{}
	for _, h := range e.Headers {
		got[h.Key] = h.Value
	}
	if got["Authorization"] != "REDACTED" {
		t.Errorf("Authorization stored as %q, want REDACTED", got["Authorization"])
	}
	if got["X-Api-Key"] != "REDACTED" {
		t.Errorf("X-Api-Key stored as %q, want REDACTED", got["X-Api-Key"])
	}
	if got["Accept"] != "application/json" {
		t.Errorf("Accept stored as %q, want kept verbatim", got["Accept"])
	}
}

func TestHistoryRoundTrip(t *testing.T) {
	useHistoryFile(t)

	for i := 0; i < 3; i++ {
		e := newHistoryEntry(RequestSpec{
			Method:  "POST",
			URL:     fmt.Sprintf("https://x/%d", i),
			Headers: []Header{{Key: "Accept", Value: "*/*"}},
			Body:    []byte(`{"n":1}`),
		}, Result{Method: "POST", URL: fmt.Sprintf("https://x/%d", i), Status: 201})
		if err := appendHistory(e); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := loadHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("loaded %d entries, want 3", len(entries))
	}
	last := entries[2]
	if last.URL != "https://x/2" || last.Method != "POST" || last.Status != 201 {
		t.Errorf("last entry = %+v", last)
	}
	if last.Body != `{"n":1}` || last.BodyBase64 || last.BodyTruncated {
		t.Errorf("body round-trip = %+v", last)
	}
	if _, err := time.Parse(time.RFC3339, last.Time); err != nil {
		t.Errorf("timestamp %q is not RFC3339: %v", last.Time, err)
	}
}

func TestHistoryBinaryAndLargeBodies(t *testing.T) {
	bin := []byte{0xff, 0xfe, 0x00, 0x01}
	e := newHistoryEntry(RequestSpec{Method: "POST", URL: "https://x", Body: bin}, Result{})
	if !e.BodyBase64 || e.Body != base64.StdEncoding.EncodeToString(bin) {
		t.Errorf("binary body not base64-encoded: %+v", e)
	}
	spec, err := replaySpec(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spec.Body, bin) {
		t.Errorf("replayed body = %v, want %v", spec.Body, bin)
	}

	big := bytes.Repeat([]byte("a"), historyBodyMax+1)
	e = newHistoryEntry(RequestSpec{Method: "POST", URL: "https://x", Body: big}, Result{})
	if !e.BodyTruncated || e.Body != "" || e.BodySize != int64(len(big)) {
		t.Errorf("large body should store size only: %+v", e)
	}
	if _, err := replaySpec(e); err == nil {
		t.Error("replay of a truncated body should refuse")
	}
}

func TestHistoryReplayDropsRedactedHeaders(t *testing.T) {
	e := historyEntry{
		Method: "GET",
		URL:    "https://api.example.com/me",
		Headers: []Header{
			{Key: "Authorization", Value: "REDACTED"},
			{Key: "X-Api-Key", Value: "REDACTED"},
			{Key: "Accept", Value: "application/json"},
		},
	}
	spec, err := replaySpec(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Headers) != 1 || spec.Headers[0].Key != "Accept" {
		t.Errorf("replay headers = %+v, want only Accept", spec.Headers)
	}
}

func TestHistoryCap(t *testing.T) {
	path := useHistoryFile(t)

	for i := 0; i < historyMaxLines; i++ {
		if err := appendHistory(historyEntry{Method: "GET", URL: fmt.Sprintf("https://x/%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := loadHistory()
	if len(entries) != historyMaxLines {
		t.Fatalf("at the cap: %d entries, want %d", len(entries), historyMaxLines)
	}

	// One more append crosses the threshold and triggers the rewrite.
	if err := appendHistory(historyEntry{Method: "GET", URL: "https://x/last"}); err != nil {
		t.Fatal(err)
	}
	entries, err := loadHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != historyKeepLines {
		t.Fatalf("after cap: %d entries, want %d", len(entries), historyKeepLines)
	}
	if entries[len(entries)-1].URL != "https://x/last" {
		t.Errorf("newest entry lost in rewrite: %+v", entries[len(entries)-1])
	}
	if data, _ := os.ReadFile(path); strings.Count(string(data), "\n") != historyKeepLines {
		t.Errorf("file has %d lines, want %d", strings.Count(string(data), "\n"), historyKeepLines)
	}
}

// TestHistoryRecordedByDo proves the Do chokepoint records: one entry per
// executed request, carrying the resolved method/URL and the response status,
// with credential values redacted.
func TestHistoryRecordedByDo(t *testing.T) {
	useHistoryFile(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	c := newClient(log.New(io.Discard), plainErrorChan{})
	c.Do(RequestSpec{Method: "get", URL: srv.URL,
		Headers: []Header{{Key: "Authorization", Value: "Bearer x"}}})

	entries, err := loadHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("Do recorded %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Method != "GET" || e.URL != srv.URL || e.Status != http.StatusTeapot {
		t.Errorf("entry = %+v", e)
	}
	if len(e.Headers) != 1 || e.Headers[0].Value != "REDACTED" {
		t.Errorf("Authorization not redacted: %+v", e.Headers)
	}

	// A pure build error (no URL) never produces an entry.
	c.Do(RequestSpec{Method: "GET"})
	if entries, _ = loadHistory(); len(entries) != 1 {
		t.Errorf("build error recorded history: %d entries", len(entries))
	}
}

func TestHistoryDisabled(t *testing.T) {
	path := useHistoryFile(t)
	t.Setenv("WEEB_HISTORY", "0")

	c := newClient(log.New(io.Discard), plainErrorChan{})
	c.recordHistory(RequestSpec{Method: "GET", URL: "https://x"}, Result{Method: "GET", URL: "https://x", Status: 200})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("WEEB_HISTORY=0 should not write a history file (stat err = %v)", err)
	}
}

func TestHistoryListing(t *testing.T) {
	now := time.Now()
	entries := []historyEntry{
		{Time: now.Add(-3 * time.Hour).Format(time.RFC3339), Method: "POST", URL: "https://x/old", Status: 500, DurationMS: 12},
		{Time: now.Add(-2 * time.Minute).Format(time.RFC3339), Method: "GET", URL: "https://x/new", Status: 200, DurationMS: 145},
	}

	var buf bytes.Buffer
	renderHistoryList(&buf, entries)
	out := buf.String()

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("listing has %d lines, want 2:\n%s", len(lines), out)
	}
	// Newest first: number 1 is the GET.
	for _, want := range []string{"1", "GET", "200", "145ms", "https://x/new", "2m ago"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("line 1 %q missing %q", lines[0], want)
		}
	}
	for _, want := range []string{"2", "POST", "500", "https://x/old", "3h ago"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("line 2 %q missing %q", lines[1], want)
		}
	}

	buf.Reset()
	renderHistoryList(&buf, nil)
	if !strings.Contains(buf.String(), "no history yet") {
		t.Errorf("empty listing = %q", buf.String())
	}
}
