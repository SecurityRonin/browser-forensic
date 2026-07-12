# 6. Capable by default — no feature-gating of forensic capability

## Context

Cargo features are the usual lever for trimming a build. For a forensic suite,
gating capability behind features creates a real hazard: an examiner who builds
without the interpretation, web-storage, or decode feature gets a binary that
silently parses less than the evidence contains, with no signal that anything was
omitted. Missing capability in a forensic tool reads identically to clean input.

## Decision

Compile all forensic capability in by default. Interpretation, timestamp and blob
decoding, and web-storage parsing are always present; there is no feature flag
that removes a class of evidence from the build. Optional behavior is expressed at
run time through flags and subcommands (`--interpret`, `--format`, the artifact
subcommands), never through conditional compilation that changes what the binary
can see.

## Consequences

Every build of `br4n6` reads the same breadth of evidence, so an examiner cannot
accidentally ship a blind binary. Binary size and compile time are not tunable
downward by dropping capability. Run-time flags, which are visible and auditable,
carry all the configurability instead.

## Status

Accepted.
