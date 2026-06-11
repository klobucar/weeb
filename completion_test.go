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
		{"no shell", nil, 2},
		{"unknown shell", []string{"fish"}, 2},
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
