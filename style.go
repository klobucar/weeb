package main

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Palette — a small named set of 256-colors reused across every style and the
// syntax highlighter so the whole UI stays coherent.
var (
	cSubtle = lipgloss.Color("241")
	cFaint  = lipgloss.Color("238")
	cInk    = lipgloss.Color("232") // near-black, for text on a colored badge
	cBase   = lipgloss.Color("252")
	cPink   = lipgloss.Color("205")
	cMauve  = lipgloss.Color("141")

	// HTTP verb colors (also used for status classes).
	cGreen  = lipgloss.Color("78")  // GET / 2xx
	cBlue   = lipgloss.Color("39")  // POST
	cCyan   = lipgloss.Color("44")  // 3xx
	cOrange = lipgloss.Color("214") // PUT / PATCH / 4xx
	cRed    = lipgloss.Color("203") // DELETE / 5xx
	cViolet = lipgloss.Color("177") // HEAD / OPTIONS

	// JSON syntax colors.
	cJSONKey   = lipgloss.Color("117") // soft cyan
	cJSONStr   = lipgloss.Color("114") // green
	cJSONNum   = lipgloss.Color("215") // amber
	cJSONBool  = lipgloss.Color("212") // pink/magenta
	cJSONNull  = lipgloss.Color("244") // grey
	cJSONPunct = lipgloss.Color("240") // dim
)

// styles holds every lipgloss style weeb uses, built once per mode.
type styles struct {
	app         lipgloss.Style
	disabled    lipgloss.Style
	help        lipgloss.Style
	errText     lipgloss.Style
	paneTitle   lipgloss.Style
	headerKey   lipgloss.Style
	headerVal   lipgloss.Style
	meta        lipgloss.Style
	foldHead    lipgloss.Style
	foldHeadSel lipgloss.Style
	foldSel     lipgloss.Style

	keycap lipgloss.Style // a shortcut key, e.g. ctrl+s
	hint   lipgloss.Style // dim text in the help line / empty-state placeholder

	jsonKey   lipgloss.Style
	jsonStr   lipgloss.Style
	jsonNum   lipgloss.Style
	jsonBool  lipgloss.Style
	jsonNull  lipgloss.Style
	jsonPunct lipgloss.Style
}

func newStyles() styles {
	return styles{
		app:      lipgloss.NewStyle().Padding(0, 1),
		disabled: lipgloss.NewStyle().Foreground(cFaint),
		help:     lipgloss.NewStyle().Foreground(cSubtle),
		errText:  lipgloss.NewStyle().Foreground(cRed),

		paneTitle: lipgloss.NewStyle().Bold(true).Foreground(cMauve),
		headerKey: lipgloss.NewStyle().Foreground(cMauve),
		headerVal: lipgloss.NewStyle().Foreground(cBase),
		meta:      lipgloss.NewStyle().Foreground(cSubtle),

		// Foldable section headings: a bold cyan title; the selected one gets a
		// reverse-video bar so the fold cursor is obvious in the response pane.
		foldHead:    lipgloss.NewStyle().Bold(true).Foreground(cCyan),
		foldHeadSel: lipgloss.NewStyle().Bold(true).Foreground(cInk).Background(cCyan).Padding(0, 1),
		// foldSel highlights a selected body node in place; no padding so the JSON
		// indentation stays aligned with the surrounding lines.
		foldSel: lipgloss.NewStyle().Bold(true).Foreground(cInk).Background(cCyan),

		// Keycaps are bold purple text directly on the terminal background — no
		// chip fill, so nothing clashes with the user's theme and the mauve stays
		// fully saturated.
		keycap: lipgloss.NewStyle().Bold(true).Foreground(cMauve),
		hint:   lipgloss.NewStyle().Foreground(cSubtle),

		jsonKey:   lipgloss.NewStyle().Foreground(cJSONKey),
		jsonStr:   lipgloss.NewStyle().Foreground(cJSONStr),
		jsonNum:   lipgloss.NewStyle().Foreground(cJSONNum),
		jsonBool:  lipgloss.NewStyle().Bold(true).Foreground(cJSONBool),
		jsonNull:  lipgloss.NewStyle().Faint(true).Foreground(cJSONNull),
		jsonPunct: lipgloss.NewStyle().Foreground(cJSONPunct),
	}
}

// titleHue0/titleHue1 bound the static gradient used on the header title and
// dividers: a pink→blue sweep.
const (
	titleHue0 = 330.0
	titleHue1 = 210.0
)

// methodColor maps an HTTP verb to its signature color.
func methodColor(method string) color.Color {
	switch method {
	case "GET":
		return cGreen
	case "POST":
		return cBlue
	case "PUT", "PATCH":
		return cOrange
	case "DELETE":
		return cRed
	case "HEAD", "OPTIONS":
		return cViolet
	default:
		return cSubtle
	}
}

// statusColor maps an HTTP status code to a color by class.
func statusColor(code int) color.Color {
	switch {
	case code >= 200 && code < 300:
		return cGreen
	case code >= 300 && code < 400:
		return cCyan
	case code >= 400 && code < 500:
		return cOrange
	case code >= 500:
		return cRed
	default:
		return cSubtle
	}
}
