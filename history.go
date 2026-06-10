package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Request history: every request executed through Client.Do is appended to a
// JSON Lines file so `weeb history` can list and `weeb history N` can re-run
// it. Recording is strictly best-effort — a history failure must never fail
// (or slow) the request itself — and credential header values are never
// stored: they are redacted on write, dropped on replay, and restored live by
// the resolveSpec env prefills (WEEB_TOKEN / WEEB_HEADERS).

const (
	historyBodyMax   = 4 << 10 // request bodies stored inline only up to this
	historyMaxLines  = 1000    // append rewrites the file once it exceeds this…
	historyKeepLines = 500     // …keeping the newest this many entries
	historyListLimit = 20      // `weeb history` shows at most this many
)

// redactedValue replaces credential header values in stored entries.
const redactedValue = "REDACTED"

// historyEntry is one line of the history file. The body is stored inline
// only up to historyBodyMax (base64 when not valid UTF-8); larger bodies keep
// the size alone and refuse to replay.
type historyEntry struct {
	Time          string   `json:"time"` // RFC3339
	Method        string   `json:"method"`
	URL           string   `json:"url"`
	Headers       []Header `json:"headers,omitempty"`
	Body          string   `json:"body,omitempty"`
	BodyBase64    bool     `json:"body_base64,omitempty"`
	BodyTruncated bool     `json:"body_truncated,omitempty"`
	BodySize      int64    `json:"body_size,omitempty"`
	Status        int      `json:"status,omitempty"` // 0 = never got a response
	DurationMS    int64    `json:"duration_ms"`
}

// historyPath resolves the history file location. A var (like maxBodyBytes)
// so tests can point it at a temp dir.
var historyPath = defaultHistoryPath

// defaultHistoryPath shares the 0700 weeb cache dir with the TUI log. Unlike
// the log there is no temp-dir fallback: history is best-effort and a shared
// temp dir is no place for request URLs.
func defaultHistoryPath() (string, error) {
	dir, err := weebCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "history.jsonl"), nil
}

// historyEnabled gates both writing and reading; WEEB_HISTORY=0/false opts out.
func historyEnabled() bool { return envBool("WEEB_HISTORY", true) }

// redactedHeaderKey reports whether a header carries credentials and must not
// have its value stored: the well-known credential headers, plus anything
// whose name smells like a secret (API keys and tokens travel under many
// custom names).
func redactedHeaderKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	switch lk {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	return strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "key")
}

// recordHistory appends one finished request, best-effort: any failure is
// logged through THE RECORD and otherwise ignored, so history can never break
// a request. Called (deferred) from Do once the send was actually attempted.
func (c *Client) recordHistory(spec RequestSpec, res Result) {
	if !historyEnabled() {
		return
	}
	if err := appendHistory(newHistoryEntry(spec, res)); err != nil {
		c.log.Warn("history write failed", "err", err)
	}
}

// newHistoryEntry snapshots a request/result pair for storage, redacting
// credential values and capping the inline body.
func newHistoryEntry(spec RequestSpec, res Result) historyEntry {
	e := historyEntry{
		Time:       time.Now().Format(time.RFC3339),
		Method:     res.Method,
		URL:        res.URL,
		Status:     res.Status,
		DurationMS: res.Timing.Total.Milliseconds(),
		BodySize:   int64(len(spec.Body)),
	}
	for _, h := range spec.Headers {
		if strings.TrimSpace(h.Key) == "" {
			continue
		}
		v := h.Value
		if redactedHeaderKey(h.Key) {
			v = redactedValue
		}
		e.Headers = append(e.Headers, Header{Key: h.Key, Value: v})
	}
	switch {
	case len(spec.Body) == 0:
	case len(spec.Body) > historyBodyMax:
		e.BodyTruncated = true // size only; replay will refuse
	case utf8.Valid(spec.Body):
		e.Body = string(spec.Body)
	default:
		e.Body = base64.StdEncoding.EncodeToString(spec.Body)
		e.BodyBase64 = true
	}
	return e
}

// appendHistory writes one entry as a JSON line (file private to the user,
// like the log) and then enforces the size cap.
func appendHistory(e historyEntry) error {
	path, err := historyPath()
	if err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(line, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	return capHistory(path)
}

// capHistory rewrites the file keeping the newest historyKeepLines entries
// once it grows past historyMaxLines. The file is small (bodies capped at
// 4 KiB), so a full read-and-rewrite is correctness over cleverness.
func capHistory(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) <= historyMaxLines {
		return nil
	}
	keep := lines[len(lines)-historyKeepLines:]
	return os.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0o600)
}

// loadHistory reads all entries, oldest first. A missing file is empty
// history; malformed lines (a torn write, an old format) are skipped rather
// than poisoning the whole file.
func loadHistory() ([]historyEntry, error) {
	path, err := historyPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []historyEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e historyEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// replaySpec rebuilds a RequestSpec from a stored entry. Redacted headers are
// dropped entirely — resolveSpec's have[] check then doesn't see them, so the
// env prefills (WEEB_TOKEN / WEEB_HEADERS) re-inject live credentials instead
// of the literal "REDACTED" string ever going over the wire.
func replaySpec(e historyEntry) (RequestSpec, error) {
	if e.BodyTruncated {
		return RequestSpec{}, fmt.Errorf("body (%s) was too large to store; re-run the original command instead",
			humanSize(int(e.BodySize)))
	}
	spec := RequestSpec{Method: e.Method, URL: e.URL}
	for _, h := range e.Headers {
		if redactedHeaderKey(h.Key) {
			continue
		}
		spec.Headers = append(spec.Headers, h)
	}
	if e.Body != "" {
		if e.BodyBase64 {
			b, err := base64.StdEncoding.DecodeString(e.Body)
			if err != nil {
				return RequestSpec{}, fmt.Errorf("corrupt stored body: %w", err)
			}
			spec.Body = b
		} else {
			spec.Body = []byte(e.Body)
		}
	}
	return spec, nil
}

// renderHistoryList prints the newest historyListLimit entries, number 1 =
// newest — the number `weeb history N` replays. Takes the writer so tests can
// capture it; runHistory passes outW (URLs are server-influenced text and get
// sanitized at a TTY).
func renderHistoryList(w io.Writer, entries []historyEntry) {
	if len(entries) == 0 {
		fmt.Fprintln(w, "no history yet — run a request first")
		return
	}
	n := len(entries)
	limit := min(n, historyListLimit)
	now := time.Now()
	for i := 0; i < limit; i++ {
		e := entries[n-1-i]
		when := "?"
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
			when = relTime(t, now)
		}
		status := "-" // never got a response (transport error)
		if e.Status != 0 {
			status = strconv.Itoa(e.Status)
		}
		fmt.Fprintf(w, "%3d  %-8s %-7s %-4s %6dms  %s\n",
			i+1, when, e.Method, status, e.DurationMS, e.URL)
	}
}

// relTime renders a coarse relative age for the listing ("2h ago").
func relTime(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// runHistory handles `weeb history [N|--clear]`: no args lists the recent
// entries, N re-runs entry N through the normal one-shot path, --clear wipes
// the file.
func runHistory(args []string) int {
	if !historyEnabled() {
		fmt.Fprintln(os.Stderr, "weeb: history is disabled (WEEB_HISTORY=0)")
		return 2
	}

	switch {
	case len(args) == 0:
		entries, err := loadHistory()
		if err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 1
		}
		renderHistoryList(outW, entries)
		return 0

	case len(args) == 1 && args[0] == "--clear":
		path, err := historyPath()
		if err == nil {
			if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
				err = rerr
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 1
		}
		return 0

	case len(args) == 1:
		n, err := strconv.Atoi(args[0])
		if err == nil && n >= 1 {
			return runHistoryReplay(n)
		}
	}

	fmt.Fprintln(os.Stderr, "weeb: usage: weeb history [N|--clear]")
	return 2
}

// runHistoryReplay re-runs entry n (1 = newest) through the same one-shot
// flow as a curl import: env prefills resolved by Do, body to stdout (streamed
// raw when piped), stats and errors to stderr. The replayed request is itself
// recorded as a new entry.
func runHistoryReplay(n int) int {
	entries, err := loadHistory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 1
	}
	if n > len(entries) {
		fmt.Fprintf(os.Stderr, "weeb: no history entry %d (have %d)\n", n, len(entries))
		return 2
	}
	spec, err := replaySpec(entries[len(entries)-n])
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	if err := applyMaxBody(""); err != nil { // WEEB_MAX_BODY still applies
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()
	client := newClient(logger, newErrorChan())
	if !stdoutIsTTY() {
		spec.BodySink = os.Stdout // piped: stream the raw bytes, uncapped
	}
	res := client.Do(spec)
	return emitResult(res, false, false, envBool("WEEB_PRETTY", true))
}
