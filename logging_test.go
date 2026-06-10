package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The TUI log must live in a per-user directory with user-only permissions:
// logged request URLs can carry tokens, and the old world-readable
// $TMPDIR/weeb.log leaked them on shared systems.
func TestDefaultLogPathIsPerUserAndPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission semantics")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	path := defaultLogPath()
	if !strings.HasPrefix(path, home) {
		t.Fatalf("log path %q should live under the user dir %q", path, home)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("log dir mode = %o, want 0700", got)
	}

	f, err := openLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fileInfo, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("log file mode = %o, want 0600", got)
	}
}
