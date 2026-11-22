package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "charm.land/log/v2"
)

// runMode selects how diagnostics are routed. The two modes have different
// audiences and MUST NOT share a writer: in TUI mode charm/log emits ANSI that
// would corrupt the Bubble Tea screen, so it is never allowed near the terminal.
type runMode int

const (
	modeCLI runMode = iota
	modeTUI
)

// safeBuffer is a goroutine-safe, size-capped in-memory sink for the optional
// in-TUI debug pane. The logger writes to it (alongside the log file) so the
// debug pane can show recent structured lines without touching the TTY directly.
type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

const maxDebugBytes = 32 * 1024

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > maxDebugBytes {
		b.buf = b.buf[len(b.buf)-maxDebugBytes:]
	}
	return len(p), nil
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// newLogger builds the charm/log logger (THE RECORD) and selects its writer
// based on mode and the WEEB_LOG* environment variables. It returns the logger,
// an optional in-memory debug sink (non-nil only in TUI mode), and a cleanup
// func that closes any opened log file.
//
//	WEEB_LOG        debug|info|warn|error|off   (default: warn)
//	WEEB_LOG_FORMAT text|json|logfmt            (default: text)
//	WEEB_LOG_FILE   path; if set, logs go here instead of stderr; in TUI mode a
//	                temp file is used when this is unset.
func newLogger(mode runMode) (*log.Logger, *safeBuffer, func()) {
	levelStr := envOr("WEEB_LOG", "warn")
	formatStr := envOr("WEEB_LOG_FORMAT", "text")
	logFile := os.Getenv("WEEB_LOG_FILE")

	cleanup := func() {}
	var dbg *safeBuffer
	var w io.Writer

	off := false
	level, err := log.ParseLevel(levelStr)
	if err != nil {
		if levelStr == "off" {
			off = true
		} else {
			level = log.WarnLevel
		}
	}

	switch {
	case off:
		// "off" suppresses everything regardless of mode.
		w = io.Discard

	case mode == modeCLI:
		// CLI: stderr by default so stdout stays clean for pipes; a file if asked.
		if logFile != "" {
			if f, ferr := openLogFile(logFile); ferr == nil {
				w = f
				cleanup = func() { _ = f.Close() }
			} else {
				fmt.Fprintf(os.Stderr, "weeb: cannot open WEEB_LOG_FILE %q: %v (falling back to stderr)\n", logFile, ferr)
				w = os.Stderr
			}
		} else {
			w = os.Stderr
		}

	default:
		// TUI: a FILE only, never the terminal. Also tee into the in-memory debug
		// sink that feeds the toggleable debug pane.
		dbg = &safeBuffer{}
		path := logFile
		if path == "" {
			path = defaultLogPath()
		}
		if f, ferr := openLogFile(path); ferr == nil {
			w = io.MultiWriter(f, dbg)
			cleanup = func() { _ = f.Close() }
		} else {
			// We cannot print to the terminal here; keep logs in the debug pane only.
			w = dbg
		}
	}

	logger := log.NewWithOptions(w, log.Options{
		Level:           level,
		Formatter:       parseFormatter(formatStr),
		ReportTimestamp: true,
		Prefix:          "weeb",
	})
	return logger, dbg, cleanup
}

// weebCacheDir returns the private per-user weeb dir under the OS cache dir,
// created 0700. Both the TUI log and the request history live here — logged
// URLs and request metadata are sensitive, so the dir is never group/world
// readable.
func weebCacheDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, "weeb")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// defaultLogPath is the TUI log location: a 0700 dir under the per-user cache
// dir. The old default — the shared OS temp dir — left request URLs (which can
// carry tokens in query strings) world-readable on multi-user systems and let
// another user pre-create /tmp/weeb.log as a symlink for weeb to append
// through. The temp dir remains only as a last-resort fallback.
func defaultLogPath() string {
	dir, err := weebCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "weeb.log")
	}
	return filepath.Join(dir, "weeb.log")
}

// openLogFile creates the file private to the user: logged URLs are sensitive.
func openLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func parseFormatter(s string) log.Formatter {
	switch s {
	case "json":
		return log.JSONFormatter
	case "logfmt":
		return log.LogfmtFormatter
	default:
		return log.TextFormatter
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envTruthy reports whether an env var is set to a truthy value.
func envTruthy(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on", "y":
		return true
	default:
		return false
	}
}

// envBool reads a boolean env var, returning def when it is unset/empty and
// treating any non-truthy explicit value as false.
func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	return envTruthy(key)
}
