---
type: Research
title: terrascan (Tenable) — Container Hardening Patterns
description: Statically-detectable Dockerfile misconfiguration patterns sourced from terrascan's Rego policy set, mapped to agentsec coverage.
tags: [research, docker, container, terrascan]
timestamp: "2026-07-12T00:00:00Z"
---

# terrascan (Tenable) — Container Hardening Patterns

## What this covers

terrascan is an IaC/container policy scanner whose rules are written in Rego (Open Policy
Agent). The patterns below are Dockerfile hardening checks translated from terrascan's real
Rego rule bodies into agentsec's own Python-regex guard style — every pattern is sourced
directly from the fetched Rego source, not inferred from general container-security advice.

## Root user by omission or by explicit switch-back

A Dockerfile that never declares a `USER` instruction inherits the base image's default user
— root, for the overwhelming majority of public base images. A Dockerfile that DOES declare
`USER` but ends on `root` (either explicitly, `USER root`, or numerically, `USER 0`) is
equally exposed: code execution inside the container (a dependency RCE, an unsafe
deserialization, a prompt-injected shell-out) then runs as root, turning any further
container-escape primitive into a host-level compromise rather than a contained incident.
terrascan's own rule (`lastUserRoot.rego`) only inspects the LAST `USER` instruction's literal
value for the string `"root"` — a Dockerfile with an earlier non-root `USER` that later
switches back is still exposed, and the rule (correctly) still catches it.

## Base image freshness has no visible diff

`FROM <image>` with no tag, or an explicit `:latest` tag, means the bytes that image name
resolves to can change between any two builds with zero visible change to the Dockerfile
itself — a supply-chain risk indistinguishable from a deliberate, reviewed dependency bump.
This is deliberately the narrower half of "pin to a digest": a tagged-but-non-digest image
(`python:3.12-slim`) is a separate, related gap (still mutable at the registry, just less
volatile than `:latest`) that a no-tag/`:latest` check does not itself resolve.

## `ADD`'s two silent behaviors

`ADD` auto-extracts recognized local archives at the destination and can fetch a remote URL
directly into the image — both behaviors are easy to trigger without realizing it, and
neither is visible from the instruction's own syntax the way `RUN tar -xzf ...` or `RUN curl
... -o ...` would be. A remote-URL `ADD` additionally has no way to verify the fetched
content's integrity (no checksum), unlike an explicit download-then-verify step.

## `sudo` inside a Dockerfile RUN is a signal, not a mitigation

A `RUN` instruction that invokes `sudo` inside a Dockerfile build step is a strong signal that
a privilege-escalation binary is present in the final image at all — during the build, the
Dockerfile's whole `RUN` already executes as root (or whatever `USER` precedes it), so `sudo`
adds nothing to the build itself; its presence in the image is the concern, not its use during
build. Detected across shell connectors (`&&`, `;`, `||`), not just the leading position.

## SSH exposure needs real port-token parsing, not substring matching

A Dockerfile `EXPOSE 22` in an application image (as opposed to a base OS/infra image with a
legitimate SSH use case) is almost always leftover debug tooling or a misconfigured base
image, since a FastAPI/React application container rarely has a legitimate reason to run an
SSH daemon. The detail worth recording: a naive substring check for `"22"` in the EXPOSE
argument produces false positives on `EXPOSE 2200` or `EXPOSE 8220` — the check needs to
tokenize the argument list into real port numbers (optionally with a `/tcp`/`/udp` suffix)
and compare the whole token, not search for a substring.

## Citations

- [tenable/terrascan](https://github.com/tenable/terrascan) — `pkg/policies/opa/rego/docker/docker_run/lastUserRoot.rego`, `docker_from/imageVersionnotusinglatest.rego`, `docker_run/runWithSudo.rego`, `docker_expose/exposeport.rego`, and the local-archive/remote-URL `ADD`-misuse policies (all fetched and read directly).
