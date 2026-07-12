# 2. One normalized BrowserEvent schema

## Context

Chrome, Firefox, and Safari store the same conceptual artifacts — history,
cookies, downloads — in different schemas, epochs, and file formats. A consumer
that had to branch on the source browser for every field would carry that
complexity through the entire downstream pipeline.

## Decision

Every parser, across every browser and every artifact, emits the same
`BrowserEvent` envelope: `timestamp_ns` (Unix nanoseconds, UTC), `browser`,
`artifact`, `source`, `description`, and an open `attrs` map for
artifact-specific fields. Timestamp normalization to Unix nanoseconds happens
inside the parsers, so the envelope never leaks a browser-specific epoch.

## Consequences

Downstream analysis, filtering, and export are browser-agnostic — the same jq
pipeline works across Chromium, Firefox, and Safari output. Artifact-specific
detail lives in `attrs` rather than a rigid columnar type, keeping the envelope
stable as parsers gain fields. The trade-off is that `attrs` is loosely typed;
consumers read keys defensively.

## Status

Accepted.
