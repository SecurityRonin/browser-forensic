# 5. Knowledge-as-code via forensicnomicon

## Context

Browser forensics depends on a body of reference knowledge: which directories and
marker files identify each browser and embedded-Chromium app, how each app embeds
Chromium, the epoch offsets for WebKit and Core Data timestamps, SQLite and
mozLz4 magic numbers, and per-artifact evidence descriptions. Embedding these
tables inside the parsing engine would fork that knowledge from the rest of the
fleet and let it drift.

## Decision

Consume the fleet `forensicnomicon` catalog as the single source of that
knowledge. `browser-forensic-discovery` uses `browser_profiles`
(`attribute_container`, the Chromium and Firefox profile markers, `AppKind`);
`browser-forensic-core` uses the timestamp epoch offsets and the evidence catalog
(`EvidenceStrength`, `evidence_for`); `browser-forensic-carve` and
`browser-forensic-firefox` use the SQLite and mozLz4 constants. The suite holds
parsing logic; the catalog holds the facts.

## Consequences

Reference facts update once, fleet-wide, in `forensicnomicon`, and every consumer
picks them up on a version bump. New embedded-Chromium apps are recognized by
cataloguing them there, not by editing the sweep. The suite takes a dependency on
the catalog crate and its release cadence.

## Status

Accepted.
