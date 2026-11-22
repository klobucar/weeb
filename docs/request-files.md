# Request files

[Back to weeb](../README.md)

Use `weeb run` to list or send requests from a `.http` file created for the VS Code REST Client or JetBrains HTTP Client.

```http
@base = https://api.example.com
@token = {{$processEnv API_TOKEN}}

### Log in
# @name login
POST {{base}}/login
Content-Type: application/json

< ./login.json

### Who am I?
# @name me
GET {{base}}/me
    ?fields=id,name
    &verbose=true
Authorization: Bearer {{token}}
```

```sh
weeb run api.http
weeb run api.http me
weeb run api.http 2
weeb run api.http me --env dev
```

Omit the selector to list requests by number, name or title, method, and URL. Selecting a request opens it in the interactive form. Piping stdout or adding `--no-tui` sends it once and writes the body to stdout. The usual [request defaults](configuration.md#request-defaults) still apply.

## File syntax

- Separate requests with `###` and an optional title. Use `# @name NAME` or `// @name NAME` to assign a name. Add `# @no-redirect` to return the redirect response itself.
- Start with `[METHOD] URL [HTTP/version]`. The method defaults to `GET`. Put optional `?` and `&` query continuations directly below the request line, followed by headers and a blank line before the body.
- Lines beginning with `#` or `//` are comments before the request line and among headers. The body preserves them as text.
- Use `< ./file` to include file bytes or `<@ ./file` to expand variables in the included file. Paths resolve relative to the `.http` file. Multipart bodies use CRLF line endings.

## Variables

Define a file variable with `@name = value` and reference it as `{{name}}` in URLs, headers, bodies, or other variable definitions. `{{$processEnv VAR}}` and `{{$env.VAR}}` read process environment variables. weeb also generates `{{$guid}}`, `{{$uuid}}`, `{{$timestamp}}`, and `{{$isoTimestamp}}`.

Use `--env NAME` to select an environment from `http-client.env.json` beside the request file. weeb merges the selected environment with `$shared` and `http-client.private.env.json`. File variables take precedence. Listings retain variable references for process and private environment values, and diagnostics replace those resolved values with their references.

Undefined variables produce an error with the line number. Run requests separately if the collection uses response chaining. JetBrains handler scripts are skipped, and directives such as `@prompt` and dynamic variables such as `$randomInt` or `$datetime` are outside the supported syntax.
