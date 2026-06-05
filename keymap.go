package main

import "charm.land/bubbles/v2/key"

// keyMap collects every binding the TUI responds to. The chosen ctrl-keys avoid
// the bubbles textinput/textarea line-editing bindings (ctrl+a/e/f/b/k/u/w/d/h/
// n/p/v) so typing in a field never clashes with a global action.
type keyMap struct {
	NextField     key.Binding
	PrevField     key.Binding
	MethodPrev    key.Binding
	MethodNext    key.Binding
	AddHeader     key.Binding
	DelHeader     key.Binding
	Send          key.Binding
	InspectCert   key.Binding
	ExportCurl    key.Binding
	TogglePretty  key.Binding
	ToggleDebug   key.Binding
	ToggleRainbow key.Binding
	Quit          key.Binding

	// Response-pane folding (active only when the response pane is focused, so
	// these reuse plain keys that the form's text widgets would otherwise eat).
	SectionPrev key.Binding
	SectionNext key.Binding
	FoldSection key.Binding
	FoldAll     key.Binding
	UnfoldAll   key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		NextField:     key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next field")),
		PrevField:     key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "prev field")),
		MethodPrev:    key.NewBinding(key.WithKeys("left"), key.WithHelp("←", "prev method")),
		MethodNext:    key.NewBinding(key.WithKeys("right"), key.WithHelp("→", "next method")),
		AddHeader:     key.NewBinding(key.WithKeys("ctrl+o"), key.WithHelp("ctrl+o", "add header")),
		DelHeader:     key.NewBinding(key.WithKeys("ctrl+r"), key.WithHelp("ctrl+r", "remove header")),
		Send:          key.NewBinding(key.WithKeys("ctrl+s"), key.WithHelp("ctrl+s", "send")),
		InspectCert:   key.NewBinding(key.WithKeys("ctrl+t"), key.WithHelp("ctrl+t", "inspect TLS cert")),
		ExportCurl:    key.NewBinding(key.WithKeys("ctrl+x"), key.WithHelp("ctrl+x", "export as curl")),
		TogglePretty:  key.NewBinding(key.WithKeys("ctrl+p"), key.WithHelp("ctrl+p", "pretty/sniff body")),
		ToggleDebug:   key.NewBinding(key.WithKeys("ctrl+g"), key.WithHelp("ctrl+g", "debug log")),
		ToggleRainbow: key.NewBinding(key.WithKeys("ctrl+y"), key.WithHelp("ctrl+y", "rainbow")),
		Quit:          key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")),

		SectionPrev: key.NewBinding(key.WithKeys("left", "shift+up"), key.WithHelp("←", "prev section")),
		SectionNext: key.NewBinding(key.WithKeys("right", "shift+down"), key.WithHelp("→", "next section")),
		FoldSection: key.NewBinding(key.WithKeys("enter", " "), key.WithHelp("enter", "fold section")),
		FoldAll:     key.NewBinding(key.WithKeys("-", "_"), key.WithHelp("-", "fold all")),
		UnfoldAll:   key.NewBinding(key.WithKeys("+", "="), key.WithHelp("+", "unfold all")),
	}
}
