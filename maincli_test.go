package main

import "testing"

func TestParseCLI(t *testing.T) {
	t.Run("method and url", func(t *testing.T) {
		a, err := parseCLI([]string{"GET", "https://x"})
		if err != nil {
			t.Fatal(err)
		}
		if a.method != "GET" || a.url != "https://x" {
			t.Errorf("got %+v", a)
		}
	})

	t.Run("url only defaults to GET", func(t *testing.T) {
		a, _ := parseCLI([]string{"https://x"})
		if a.method != "GET" || a.url != "https://x" {
			t.Errorf("got %+v", a)
		}
	})

	t.Run("post with header and body", func(t *testing.T) {
		a, err := parseCLI([]string{"POST", "https://x", "-H", "A: 1", "-d", "payload"})
		if err != nil {
			t.Fatal(err)
		}
		if a.method != "POST" || string(a.body) != "payload" {
			t.Errorf("got %+v", a)
		}
		if len(a.headers) != 1 || a.headers[0].Key != "A" || a.headers[0].Value != "1" {
			t.Errorf("headers = %+v", a.headers)
		}
	})

	t.Run("flags", func(t *testing.T) {
		a, err := parseCLI([]string{
			"https://x", "-X", "PUT", "--timeout", "5s",
			"--raw", "-q", "--no-tui", "--to-curl", "--persona", "tsun", "-v",
		})
		if err != nil {
			t.Fatal(err)
		}
		if a.method != "PUT" {
			t.Errorf("method = %q", a.method)
		}
		if a.timeout.String() != "5s" {
			t.Errorf("timeout = %v", a.timeout)
		}
		if !a.raw || !a.quiet || !a.noTUI || !a.toCurl || !a.stats {
			t.Errorf("flags not all set: %+v", a)
		}
		if a.persona != "tsun" {
			t.Errorf("persona = %q", a.persona)
		}
	})

	t.Run("no url is allowed (TUI prefill)", func(t *testing.T) {
		a, err := parseCLI([]string{"--persona", "tsun"})
		if err != nil {
			t.Fatalf("missing URL should not error at parse time: %v", err)
		}
		if a.url != "" || a.persona != "tsun" {
			t.Errorf("got %+v", a)
		}
	})

	t.Run("errors", func(t *testing.T) {
		if _, err := parseCLI([]string{"https://x", "--bogus"}); err == nil {
			t.Error("unknown flag should error")
		}
		if _, err := parseCLI([]string{"GET", "https://x", "extra"}); err == nil {
			t.Error("extra positional should error")
		}
		if _, err := parseCLI([]string{"https://x", "-d", "@/no/such/file/here"}); err == nil {
			t.Error("missing @file should error")
		}
		if _, err := parseCLI([]string{"https://x", "-H", "bad-header"}); err == nil {
			t.Error("header without colon should error")
		}
	})
}

func TestPrettyOn(t *testing.T) {
	t.Setenv("WEEB_PRETTY", "")
	if !(cliArgs{}).prettyOn() {
		t.Error("default should be pretty on")
	}
	if (cliArgs{raw: true}).prettyOn() {
		t.Error("--raw should force pretty off")
	}
	if !(cliArgs{pretty: true}).prettyOn() {
		t.Error("--pretty should force on")
	}
	if (cliArgs{pretty: true, raw: true}).prettyOn() {
		t.Error("--raw should win over --pretty")
	}

	t.Setenv("WEEB_PRETTY", "0")
	if (cliArgs{}).prettyOn() {
		t.Error("WEEB_PRETTY=0 should default off")
	}
	if !(cliArgs{pretty: true}).prettyOn() {
		t.Error("--pretty should override WEEB_PRETTY=0")
	}
}

func TestResolvePersona(t *testing.T) {
	t.Setenv("WEEB_PERSONA", "")

	if got, err := resolvePersona("tsun"); err != nil || got != "tsun" {
		t.Errorf("flag tsun -> %q, %v", got, err)
	}
	if _, err := resolvePersona("clown"); err == nil {
		t.Error("unknown flag persona should error")
	}
	if got, _ := resolvePersona(""); got != "plain" {
		t.Errorf("empty flag, no env -> %q, want plain", got)
	}

	t.Setenv("WEEB_PERSONA", "yan")
	if got, _ := resolvePersona(""); got != "yan" {
		t.Errorf("empty flag, env yan -> %q", got)
	}
	if got, _ := resolvePersona("plain"); got != "plain" {
		t.Errorf("flag should beat env: %q", got)
	}
}

func TestErrorChanFor(t *testing.T) {
	if _, ok := errorChanFor("plain").(plainErrorChan); !ok {
		t.Error("plain should give plainErrorChan")
	}
	if _, ok := errorChanFor("").(plainErrorChan); !ok {
		t.Error("empty should give plainErrorChan")
	}
	if _, ok := errorChanFor("tsun").(chanErrorChan); !ok {
		t.Error("tsun should give chanErrorChan")
	}
}
