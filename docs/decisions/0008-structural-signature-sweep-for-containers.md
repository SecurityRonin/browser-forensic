# 8. Structural signature sweep for embedded-Chromium discovery

## Context

Hundreds of desktop apps embed Chromium (Electron, WebView2, CEF) and keep the
same history, cookies, and web-storage databases a browser does. An allow-list of
known apps would only ever find the apps already in the list, silently missing
every unlisted or custom Electron app — precisely the ones an investigation may
care about most.

## Decision

Detect containers structurally. `sweep_containers` walks the evidence tree and
flags any directory carrying a Chromium or Firefox profile signature, regardless
of the directory's name, so an unknown app is still discovered. The
`forensicnomicon` app catalog is consulted only to *attribute* a match to a known
app (name, vendor, embedding kind); it is never the gate that decides whether a
directory is a container. A profile-shaped directory that matches no catalog
entry is reported generically rather than dropped.

## Consequences

Custom and unlisted embedded-Chromium apps are found by shape, and nothing is
silently omitted. Attribution is best-effort and improves as the catalog grows,
independently of detection. The structural signature may occasionally flag a
directory that looks like a profile but is not; reporting it (labelled) is the
safe failure mode for a forensic sweep.

## Status

Accepted.
