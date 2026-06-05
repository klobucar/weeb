package main

import (
	"fmt"
	"net/http"

	errorchan "github.com/klobucar/go-errorchan"
)

// ErrKind classifies a failure so the renderer can pick an appropriate voice.
type ErrKind int

const (
	KindTransport  ErrKind = iota // dial / timeout / connection refused — no HTTP response at all
	KindHTTPStatus                // a response arrived, but the status is >= 400
	KindBadBody                   // a response arrived, but its body could not be read/parsed
	KindBadRequest                // we failed to even build or validate the request
)

func (k ErrKind) String() string {
	switch k {
	case KindTransport:
		return "transport"
	case KindHTTPStatus:
		return "http_status"
	case KindBadBody:
		return "bad_body"
	case KindBadRequest:
		return "bad_request"
	default:
		return "unknown"
	}
}

// ErrorChan is THE VOICE: the single seam that turns a failure into human-facing
// display text. Every user-visible error string in weeb is produced here and
// nowhere else — transport errors, timeouts, refused connections, 4xx/5xx, and
// JSON/body parse failures all route through Render. This is the go-errorchan
// seam; it must never emit structured diagnostics (that is charm/log's job) and
// charm/log must never format display text.
type ErrorChan interface {
	Render(kind ErrKind, statusCode int, err error) string
}

// chanErrorChan is the real go-errorchan adapter — THE VOICE in production. It
// turns each failure into an error value (synthesizing one when the caller has
// no underlying error, e.g. a bare HTTP status) and lets go-errorchan render the
// human persona string. go-errorchan keeps the original message verbatim after a
// " — " separator, so the display text stays debuggable.
type chanErrorChan struct {
	mode string
}

func (c chanErrorChan) Render(kind ErrKind, statusCode int, err error) string {
	if err == nil {
		switch kind {
		case KindHTTPStatus:
			text := http.StatusText(statusCode)
			if text == "" {
				text = "Unknown Status"
			}
			err = fmt.Errorf("server returned %d %s", statusCode, text)
		default:
			err = fmt.Errorf("request failed")
		}
	}
	// WithMode coerces an unknown mode to dere, so c.mode is always safe.
	// WithoutType keeps Go type names (*errors.errorString*) out of user-facing text.
	return errorchan.Wrap(err, errorchan.WithMode(c.mode), errorchan.WithoutType()).Error()
}

// plainErrorChan is the dependency-light fallback (selected with
// WEEB_PERSONA=plain). It returns plain, readable strings with no persona — handy
// for scripts, logs, or anyone who wants the boring version.
type plainErrorChan struct{}

func (plainErrorChan) Render(kind ErrKind, statusCode int, err error) string {
	switch kind {
	case KindHTTPStatus:
		text := http.StatusText(statusCode)
		if text == "" {
			text = "Unknown Status"
		}
		return fmt.Sprintf("✘ the server said %d %s", statusCode, text)
	case KindTransport:
		return fmt.Sprintf("✘ couldn't reach the server: %v", err)
	case KindBadBody:
		return fmt.Sprintf("✘ couldn't read the response body: %v", err)
	case KindBadRequest:
		return fmt.Sprintf("✘ that request doesn't look right: %v", err)
	default:
		if err != nil {
			return fmt.Sprintf("✘ %v", err)
		}
		return "✘ something went sideways"
	}
}

// newErrorChan returns the active ErrorChan implementation, selected by
// WEEB_PERSONA selects the human-facing error voice. The default is plain:
// errors are the one place personality can backfire (a frustrated user, often a
// first impression), so the fun is opt-in and the raw message always legible.
//
//	plain (default) no persona, just the error
//	dere            sweet, apologetic, takes the blame
//	tsun            annoyed at you, blames your code, grudgingly helpful
//	yan             unsettlingly affectionate (do not use in prod)
//	off             alias for plain
func newErrorChan() ErrorChan {
	return errorChanFor(envOr("WEEB_PERSONA", "plain"))
}

// errorChanFor builds the voice for an explicit persona mode (empty -> plain).
func errorChanFor(mode string) ErrorChan {
	switch mode {
	case "", "plain", "off":
		return plainErrorChan{}
	default:
		return chanErrorChan{mode: mode}
	}
}

// validPersonas are the accepted WEEB_PERSONA / --persona values.
var validPersonas = map[string]bool{
	"plain": true, "off": true,
	errorchan.ModeDere: true, errorchan.ModeTsun: true, errorchan.ModeYan: true,
}

// resolvePersona picks the persona for this run: the --persona flag wins, then
// WEEB_PERSONA, then the plain default. An explicit, unknown flag is an error;
// the env var stays lenient (an unknown value just falls back to a default).
func resolvePersona(flag string) (string, error) {
	if flag != "" {
		if !validPersonas[flag] {
			return "", fmt.Errorf("unknown persona %q (want: plain, dere, tsun, yan, off)", flag)
		}
		return flag, nil
	}
	return envOr("WEEB_PERSONA", "plain"), nil
}
