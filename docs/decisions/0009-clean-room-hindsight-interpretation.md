# 9. Clean-room Hindsight-parity interpretation engine

## Context

Raw browser artifacts carry structure an examiner has to decode by hand: Google
search terms buried in URLs, tracking cookies that encode visitor IDs and visit
times, and integer timestamps whose units (seconds, millis, micros, WebKit) are
not labelled. Hindsight established the community reference for this
interpretation, but it is Python. This suite needs the same interpretation in
pure Rust, with results an examiner can reconcile against the reference.

## Decision

Implement `browser-forensic-interpret` as a clean-room reimplementation of the
Hindsight interpretation plugins. Two entry points, `interpret_url` and
`interpret_cookie`, extract Google search terms and query-string parameters and
decode tracking cookies (Google Analytics `__utm*` / `_ga`, Quantcast `__qca`, F5
BIG-IP `BIGipServer*`), with a generic embedded-timestamp fallback. Timestamp
units are inferred from magnitude through a ladder that mirrors Hindsight's
`to_datetime`, so the caller never declares units. Cookie interpretation runs only
where a plaintext value exists; Chrome-encrypted cookie values are never
surfaced.

## Consequences

Interpretation output is reconcilable against the Hindsight reference, which
serves as an independent oracle. The magnitude-based timestamp ladder matches
ground truth without a caller-supplied unit. Parity is bounded to the plugins
reimplemented; new Hindsight plugins require new work here.

## Status

Accepted.
