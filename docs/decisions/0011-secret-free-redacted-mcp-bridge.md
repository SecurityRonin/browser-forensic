# 11. Secret-free, PII-redacted MCP browsing-state bridge

## Context

An AI agent can use live browsing context — what the user is doing right now,
whether they visited a site — but browser evidence is dense with secrets. URLs
carry OAuth codes, password-reset tokens, and API keys in their query strings;
titles and search terms carry emails and secrets; cookies and the login-data
store hold credentials outright. Exposing any of that to a model would leak the
user's secrets to a third party.

## Decision

Expose a narrow MCP server, `browser-forensic-mcp`, built as two walls. The
primary wall is structural: the server depends only on the history and discovery
readers and never calls a cookie, password, or autofill reader, so secrets are
never read in the first place. The second wall is redaction defense-in-depth:
URLs are reduced to `scheme://host/path` (dropping the query and fragment where
tokens live) and free text is masked for emails and long token-like substrings.
The surface is bounded — three tools (`browsing_context`, `did_user_visit`,
`list_browsers`), each allow-listed and capped, with no unbounded history dump —
and every free-text field is tagged `untrusted_evidence: true` so the agent does
not treat evidence as instructions.

## Consequences

An agent gets bounded, allow-listed browsing context with the secret classes
structurally unreachable, not merely filtered. The bound is deliberately tight:
the three shipped tools are a subset of what was scoped, and widening the surface
is a deliberate future step, not a default. The `untrusted_evidence` tagging
guards against prompt injection through artifact content.

## Status

Accepted.
