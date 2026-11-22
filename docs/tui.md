# Interactive interface

[Back to weeb](../README.md)

Run `weeb` for an empty request or pass a URL to prefill the form. Use **Tab** to move between fields, **Left/Right** to choose a method, and **Ctrl+S** to send.

```sh
weeb POST https://api.example.com/users \
  -H 'Content-Type: application/json' -d @body.json
```

## Browse a response

Tab into the response pane to scroll or fold its sections. The formatted view highlights JSON, XML, HTML, and YAML and lets you fold individual nodes. Markdown renders in the terminal with [Glamour](https://github.com/charmbracelet/glamour). Other text displays as-is.

weeb uses the response's content type to identify the format. For generic content types such as `text/plain`, it checks the URL extension and then looks for recognizable patterns in the body. YAML detection uses the content type or a `.yaml` or `.yml` extension. Press **Ctrl+P** to toggle formatting, or set `WEEB_PRETTY=0` to start in the raw view.

| Key | Action |
| --- | --- |
| **Up / Down** | Scroll the response |
| **Left / Right** | Select a section or node |
| **Enter** | Fold or unfold the selection |
| **- / +** | Fold or unfold all sections |

## Request and view shortcuts

| Key | Action |
| --- | --- |
| **Tab / Shift+Tab** | Move between fields and panes |
| **Up / Down** | Move between form fields or between lines in the body editor |
| **Left / Right** | Change the method when the method field has focus |
| **Ctrl+O / Ctrl+R** | Add or remove a header row |
| **Ctrl+S** | Send the request |
| **Esc** | Stop the request or stream in progress |
| **Ctrl+T** | [Inspect the TLS certificate chain](tls.md) for the current URL |
| **Ctrl+X** | Show and copy the equivalent curl command |
| **y / Shift+Y** | Copy the selected path or value when the response pane has focus |
| **Ctrl+P** | Toggle the formatted body view |
| **Ctrl+G** | Toggle the debug log pane |
| **Ctrl+Y** | Toggle rainbow mode |
| **Ctrl+C** | Quit |

## Copy paths and values

Press **y** to copy a path such as `.items[3]` in JSON or YAML or `/root/item[3]` in XML or HTML. Press **Shift+Y** to copy the selected value or section. Selecting **Body** copies the raw body.

Copies use OSC 52 and work over SSH when your terminal allows clipboard writes. In iTerm2, enable *Applications in terminal may access clipboard*. In tmux, use `set -g set-clipboard on`. weeb copies plain text with control characters stripped and shows a notice when a selection exceeds the clipboard limit.

## Follow an event stream

The response pane follows new SSE or NDJSON events. Scroll up to pause following and return to the bottom to resume. **Esc** closes the stream and keeps the events on screen. **Ctrl+P** switches between formatted event blocks and raw lines.

The pane keeps up to 2,000 events or 4 MiB, subject to a lower `--max-body` cap. It marks dropped older events and truncates individual events at 1 MiB or the lower configured cap.

## View local files

`weeb view` opens a file in the foldable response pane. Pass `-` or omit the filename to read stdin. Use **q** or **Ctrl+C** to close the viewer.

```sh
weeb view data.json
weeb view - < page.html
kubectl get pod web -o yaml | weeb view --type yaml
weeb view data.json > pretty.json
```

The viewer uses the filename extension, then looks at the contents. For YAML on stdin, pass `--type yaml`. For XML without an XML declaration, pass `--type xml`. You can also force `json`, `html`, or `md`.

When stdout is piped or redirected, weeb reindents JSON and XML and prints HTML, YAML, and Markdown as source. Use `--raw` for unchanged bytes in a pipe or to start in the raw view at a terminal. `--max-body SIZE` sets the input limit, which defaults to 64 MiB or the configured `WEEB_MAX_BODY`. Use `0` for no limit.

The demos were recorded with [VHS](https://github.com/charmbracelet/vhs).

## Built with

[Bubble Tea](https://github.com/charmbracelet/bubbletea) · [Lip Gloss](https://github.com/charmbracelet/lipgloss) · [Bubbles](https://github.com/charmbracelet/bubbles) · [Glamour](https://github.com/charmbracelet/glamour) · [Log](https://github.com/charmbracelet/log) · [go-errorchan](https://github.com/klobucar/go-errorchan)
