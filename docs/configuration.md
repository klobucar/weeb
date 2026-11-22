# Configuration

[Back to weeb](../README.md)

## Request defaults

| Variable | Effect |
| --- | --- |
| `WEEB_BASE_URL` | Resolve relative URLs such as `/me` against this base. |
| `WEEB_HEADERS` | Add default request headers in the form `Name:value;Other-Name:other value`. Use `\;` for a semicolon inside a value and `\\` for a backslash. |
| `WEEB_TOKEN` | Add a bearer token unless the request already has an `Authorization` header. |

## Display and storage

| Variable | Effect |
| --- | --- |
| `WEEB_RAINBOW` | Set to `1` or `true` to start the interactive interface in rainbow mode. |
| `WEEB_PRETTY` | Start in the formatted body view by default. Set to `0` or `false` to start in the raw view. |
| `WEEB_MAX_BODY` | Set the buffer cap, such as `256m`. The default is `64m`. Use `0` to remove the cap. `--max-body` takes precedence. |
| `WEEB_HISTORY` | Set to `0` or `false` to disable recording and the [history command](http.md#history). |
| `NO_COLOR` | Set to a nonempty value to disable color in command-line output at a terminal. For HTTP responses, this also selects the raw body view. |

## Error messages

weeb prints plain errors by default. Set `WEEB_PERSONA` to `dere`, `tsun`, or `yan` to use an anime-inspired error voice. `--persona` takes precedence for a single run.

```sh
weeb https://example.invalid --no-tui --persona tsun
```

## Logging

In headless mode, structured logs go to stderr by default. The interactive interface writes logs to `weeb/weeb.log` under the user cache directory. Press **Ctrl+G** to open the debug log pane.

| Variable | Effect |
| --- | --- |
| `WEEB_LOG` | Set the log level to `debug`, `info`, `warn`, `error`, or `off`. The default is `warn`. |
| `WEEB_LOG_FORMAT` | Choose `text`, `json`, or `logfmt`. The default is `text`. |
| `WEEB_LOG_FILE` | Write logs to this path. |
