package main

import "testing"

// FuzzRenderBody drives every pretty renderer and fold-tree builder with
// arbitrary bodies under each content type. It looks for panics and hangs.
// Without -fuzz, `go test` replays the seeds and testdata/fuzz as regression
// tests; run it with
//
//	go test -run '^$' -fuzz '^FuzzRenderBody$' -fuzztime 60s .
func FuzzRenderBody(f *testing.F) {
	for _, s := range []string{
		`{"a":[1,{"b":null}]}`, `<a x="1"><b/>t</a>`, "<!doctype html><p>hi<script>x</script>",
		"a: &x [1]\nb: *x\n", "# Title\n\n[link](javascript:alert(1))\n", "\x1b]52;c;aGk=\x07",
	} {
		f.Add([]byte(s))
	}
	st := newStyles()
	types := []string{"application/json", "application/xml", "text/html", "application/yaml", "text/markdown", "text/plain", ""}
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, ct := range types {
			_ = renderBody(body, ct, "", st, true, true, 80)
			_ = renderBody(body, ct, "", st, false, true, 80)
		}
		if root := parseJSONTree(body, "application/json", "", true); root != nil {
			_ = renderTree(root, st, nil)
		}
		if root := parseXMLTree(body, "application/xml", "", true); root != nil {
			_ = renderXMLTree(root, st, nil)
		}
		if root := parseHTMLTree(body, "text/html", "", true); root != nil {
			_ = renderXMLTree(root, st, nil)
		}
		if root := parseYAMLTree(body, "application/yaml", "", true); root != nil {
			_ = renderYAMLTree(root, st, nil)
		}
	})
}
