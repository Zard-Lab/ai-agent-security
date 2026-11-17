---
type: Research
title: Bearer — Environment Secret Logging Patterns
description: Statically-detectable environment-secret-to-log-sink patterns adapted from Bearer's taint-tracking detector into a same-line static check.
tags: [research, secrets, logging, bearer]
timestamp: "2026-07-12T00:00:00Z"
---

# Bearer — Environment Secret Logging Patterns

## What this covers

Bearer is a Go/tree-sitter SAST tool built around a dataflow-taint engine: a source (like an
environment-variable read) is tagged, then tracked through the codebase to wherever it
eventually flows. agentsec has no dataflow engine, so the pattern below is a deliberately
narrowed translation — same tainted source, but detected only where it reaches a sink on the
*same physical line*, the highest-value slice a purely static, line-local scan can prove
without a real taint tracker.

## The value, not just the field name, reaches the log

A secret-sounding environment read (`os.getenv("DB_PASSWORD")`, `os.environ["API_KEY"]`,
`process.env.STRIPE_SECRET_KEY`) passed directly into a logging or console call puts the
credential's actual VALUE — not merely a field name — into the log stream on every
invocation, with zero redaction. This is a different, narrower failure than a request-body
or generic-object log (which may or may not contain a secret depending on runtime data): here
the source is unconditionally a live credential, every time the line executes.

Bearer's real detector (`environmentVariableQuery` in `pkg/detectors/python/python.go`) tags
every `os.environ[...]`/`os.environ.get(...)`/`os.getenv(...)` read as tainted `environment`
data and tracks it through Bearer's generic sink catalog (log calls, HTTP requests, datastore
writes, etc.) — the pattern here keeps only the log/print/console sink, the slice provable
without a dataflow engine.

## A boolean presence-check is meaningfully different from logging the value

`console.log(!!process.env.API_KEY)` or `logger.info('key present: %s', bool(os.getenv(...)))`
confirms a variable is set without ever putting its actual value on the wire — a legitimate,
common pattern for startup diagnostics. A detector that can't distinguish "logged the
boolean" from "logged the secret" either over-fires on safe diagnostic code or under-fires by
requiring the value form so specifically it misses real secret disclosure. The distinction
matters enough to check for explicitly (a `!!`/`Boolean(...)`/`typeof` coercion immediately
before the environment read) rather than treat any co-occurrence of "env read" and "console
call" as equally risky.

## Same concept, two ecosystems, two sinks

The Python-side sink (`logging`/`print`) and the JS/TS-side sink (`console.*`) are the same
underlying taint-source concept applied to each ecosystem's idiomatic environment-read syntax
(`os.getenv`/`os.environ` vs `process.env`) and log call. Neither language's environment-read
idiom is a substring of the other, so the two need independent detection even though the
underlying risk (an env secret's value reaching a log sink) is identical — the console sink
carries an extra real-world wrinkle worth naming: session-replay and error-monitoring tools
that patch `console.*` globally (Sentry, LogRocket, Datadog RUM) capture it too, so a
console-logged secret often has a wider blast radius than the developer watching their own
terminal output would assume.

## Citations

- [Bearer/bearer](https://github.com/Bearer/bearer) — `pkg/detectors/python/python.go`'s `environmentVariableQuery` (fetched and read directly).
