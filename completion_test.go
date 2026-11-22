package main

import (
	"strings"
	"testing"
)

func TestRunCompletionExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"zsh", []string{"zsh"}, 0},
		{"bash", []string{"bash"}, 0},
		{"fish", []string{"fish"}, 0},
		{"no shell", nil, 2},
		{"unknown shell", []string{"tcsh"}, 2},
		{"extra args", []string{"zsh", "bash"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			if got := runCompletion(tt.args, &buf); got != tt.want {
				t.Errorf("runCompletion(%v) = %d, want %d", tt.args, got, tt.want)
			}
			if tt.want != 0 && buf.Len() != 0 {
				t.Errorf("error case wrote to stdout: %q", buf.String())
			}
		})
	}
}

func TestRunCompletionZshScript(t *testing.T) {
	var buf strings.Builder
	if got := runCompletion([]string{"zsh"}, &buf); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	out := buf.String()
	for _, want := range []string{"#compdef weeb", "--persona", "cert"} {
		if !strings.Contains(out, want) {
			t.Errorf("zsh script missing %q", want)
		}
	}
}

func TestRunCompletionBashScript(t *testing.T) {
	var buf strings.Builder
	if got := runCompletion([]string{"bash"}, &buf); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	out := buf.String()
	for _, want := range []string{"complete", "weeb", "--max-body"} {
		if !strings.Contains(out, want) {
			t.Errorf("bash script missing %q", want)
		}
	}
}

func TestRunCompletionFishScript(t *testing.T) {
	var buf strings.Builder
	if got := runCompletion([]string{"fish"}, &buf); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	out := buf.String()
	for _, want := range []string{
		"complete -c weeb -f",
		"function __weeb_plain_request",
		"-l persona -x -a 'plain dere tsun yan'",
		"-s X -x -a 'GET POST PUT PATCH DELETE HEAD OPTIONS'",
		"-l output -r -F",
		"-a 'zsh bash fish'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fish script missing %q", want)
		}
	}
}

// Every entry of the shared lists must reach the fish script, in fish's own
// option syntax and under the right condition, so a flag added to
// completion.go needs no fish-specific change.
func TestFishCompletionCoversLists(t *testing.T) {
	out := fishCompletion()
	lines := strings.Split(out, "\n")
	hasLine := func(cond, opt string) bool {
		prefix := "complete -c weeb -n " + cond + " " + opt
		for _, l := range lines {
			if l == prefix || strings.HasPrefix(l, prefix+" ") {
				return true
			}
		}
		return false
	}
	for _, f := range completionMainFlags {
		if !hasLine("'__weeb_plain_request'", fishOpt(f)) {
			t.Errorf("main flag %q missing from fish script", f)
		}
	}
	for _, f := range completionCertFlags {
		if !hasLine("'__fish_seen_subcommand_from cert tls'", fishOpt(f)) {
			t.Errorf("cert flag %q missing from fish script", f)
		}
	}
	for _, list := range [][]string{completionSubcommands, completionMethods} {
		if !strings.Contains(out, "-n __fish_use_subcommand -a "+fishWords(list)) {
			t.Errorf("first-word list %v missing from fish script", list)
		}
	}
	// The plain-request guard must name every subcommand, or the main flags
	// would be offered after it.
	guard := map[string]bool{}
	for _, l := range lines {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "not __fish_seen_subcommand_from "); ok {
			for _, w := range strings.Fields(rest) {
				guard[w] = true
			}
		}
	}
	for _, s := range completionSubcommands {
		if !guard[s] {
			t.Errorf("plain-request guard missing subcommand %q", s)
		}
	}
}

func TestFishOptAndQuote(t *testing.T) {
	tests := []struct{ in, opt string }{
		{"--max-body", "-l max-body"},
		{"-H", "-s H"},
		{"-k", "-s k"},
		{"-oldstyle", "-o oldstyle"},
	}
	for _, tt := range tests {
		if got := fishOpt(tt.in); got != tt.opt {
			t.Errorf("fishOpt(%q) = %q, want %q", tt.in, got, tt.opt)
		}
	}
	if got, want := fishQuote(`it's a \ test`), `'it\'s a \\ test'`; got != want {
		t.Errorf("fishQuote = %s, want %s", got, want)
	}
}

// weeb view (#41) landed alongside fish completion: its flags, --type values
// and file names must reach the fish script too.
func TestFishCompletionView(t *testing.T) {
	s := fishCompletion()
	for _, want := range []string{
		"complete -c weeb -n '__fish_seen_subcommand_from view' -l type -x -a 'json xml html yaml md'",
		"complete -c weeb -n '__fish_seen_subcommand_from view' -l raw",
		"complete -c weeb -n '__fish_seen_subcommand_from view' -F",
		"complete -c weeb -n '__fish_seen_subcommand_from run' -F",
		"complete -c weeb -n '__fish_seen_subcommand_from cert tls' -l file -r -F",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("fish script missing %q", want)
		}
	}
}
