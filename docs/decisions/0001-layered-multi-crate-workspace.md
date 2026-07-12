# 1. Layered multi-crate workspace

## Context

A browser-forensic suite spans several concerns: domain types, per-browser
artifact parsers, and cross-cutting capabilities (integrity, carving, web
storage, interpretation, memory scanning, discovery), plus two front ends (a CLI
and an MCP server). A single crate would force every consumer — including a Rust
tool that only wants the Chromium history parser — to compile the whole surface,
and would couple the medium-agnostic parsers to the binaries.

## Decision

Split the workspace into thirteen crates arranged in dependency layers:
`forensicnomicon` feeds `browser-forensic-core` (domain types, timestamp
conversions, the read-only SQLite opener); the per-browser parsers
(`-chrome`, `-firefox`, `-safari`) and `-discovery` sit above core; the
capability crates (`-storage`, `-integrity`, `-carve`, `-interpret`, `-memory`)
layer on top; `-triage` orchestrates them into one report; and `-cli` and `-mcp`
are the front ends. Every library crate is independently consumable, and
`-integrity`, `-carve`, and `-memory` accept a `Path` or `&[u8]` so they carry no
dependency on any image or memory-dump layer. All crates inherit one uniform,
CI-verified MSRV of 1.80 from the workspace so every library crate stays broadly
publishable.

## Consequences

A downstream tool depends on exactly the parser it needs. The medium-agnostic
crates are reusable outside this suite. A uniform low MSRV keeps the library
crates consumable by older toolchains, at the cost of forgoing newer-Rust
features workspace-wide. The layering must stay acyclic, which constrains where
shared helpers live (they belong in `-core`).

## Status

Accepted.
