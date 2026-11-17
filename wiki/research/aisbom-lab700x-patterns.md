---
type: Research
title: AI Model Artifact Scanning Patterns (aisbom)
description: Statically-detectable malicious-model-artifact patterns distilled from a static ML model file scanner, mapped to agentsec's new binary-artifact guard family.
tags: [research, llm, model-artifact, pickle, keras, gguf, onnx]
status: stable
generated: { by: agent:research-cycle, at: 2026-10-08T00:00:00Z }
stale_after: 2027-01-06
---

# AI Model Artifact Scanning Patterns

## What this covers

Most static security tooling reads source code. This page covers a different surface: the
**binary ML model artifact files** an app loads at runtime — `.pkl`/`.pt`/`.h5`/`.gguf`/`.onnx` —
and the malicious patterns that can hide inside them regardless of what the app's own source code
does. Distilled from the detection design of AIsbom (`Lab700xOrg/aisbom`, see "Source and licence"
below), a public static model-artifact scanner, and mapped to agentsec's own guard family for the
same surface.

## Why model artifact files are a distinct threat surface

Several serialization formats used for ML models were designed for trusted environments and
execute code as a side effect of *loading*, not of being deliberately run:

- **Pickle-family** (`.pkl`, `.pt`, `.pth`, `.bin`, `.joblib`, `.dill`) — Python's pickle format can
  encode an arbitrary callable reference (`GLOBAL`/`STACK_GLOBAL` opcodes) that executes the moment
  the stream is deserialized. This is the mechanism behind malicious Hugging-Face-hosted model
  weights (MITRE ATLAS T0004).
- **Keras** (`.keras`, `.h5`, `.hdf5`) — a `Lambda` layer stores an arbitrary Python callable as
  part of the model's own architecture config; restoring the model calls it.
- **GGUF** — the format llama.cpp and similar runtimes use for quantized models can embed a Jinja
  chat template that runs on every inference request. A template carrying an attribute-traversal
  chain (`__class__.__mro__[1].__subclasses__()`-style) is a documented Jinja sandbox-escape
  construct (CWE-94), and unlike a pickle it doesn't need loading-time code execution — it runs as
  ordinary use of the model.
- **ONNX** — stores tensor weights inline by default, but a tensor can point at bytes in a separate
  file via an `external_data` location string with no sandboxing; a path that walks outside the
  model's own directory is a path-traversal read (CWE-22) the moment something resolves it. A
  custom operator domain (outside ONNX's standard set) requires a native-code operator library to
  be loaded — a supply-chain dependency the model's author chose, not its consumer.

## Detection patterns

| Format | What's inspected | How, without executing anything |
|---|---|---|
| Pickle-family | `GLOBAL`/`STACK_GLOBAL` opcode naming a dangerous module/function (`os.system`, `subprocess.Popen`, debugger/event-loop/import-mechanism gadgets, `dill`'s code-reconstruction globals) | Disassemble only — a read-only opcode walk (Python's `pickletools.genops`), never `pickle.load`/`loads` |
| Keras | `class_name: "Lambda"` (or Keras 3's `__lambda__` serialized-callable tag) in the model config; a base64 string whose decoded header matches CPython's `marshal` code-object signature | `.keras` is a plain zip — read the `config.json` member directly; legacy `.h5`/HDF5 has no open-source-friendly structural parser needed — the `model_config` attribute's JSON is recoverable by locating the attribute name and brace-matching the object after it (HDF5 stores attribute values uncompressed and contiguous) |
| GGUF | Jinja sandbox-escape tokens (`__class__`, `__mro__`, `__subclasses__`, ...), the `\|attr()` filter, a dangerous callable used as a call (not merely mentioned — `{% if role == 'system' %}` is a string comparison), a context-leaking object, in the embedded chat template | Walk the binary key-value metadata block directly (every field length is bounds-checked against the bytes present); the template itself is treated as a plain string — never rendered, parsed, or compiled |
| ONNX | A tensor's `external_data` location escaping the model's own directory (absolute/UNC/URL/`../` traversal); an operator domain outside the standard ONNX set | Walk the protobuf WIRE FORMAT directly by field number (no `.proto` schema, no `onnx`/`protobuf` package) — recursing into `If`/`Loop`/`Scan` nodes' nested subgraphs, since a hidden branch can carry either signal |

## Coverage status

Five new agentsec checklist items (§4, Agentic AI / RAG Security): a presence-only flag for any
committed binary model artifact, plus one content-scanning guard per format above. All five use
bounded reads (weight data, which can run to gigabytes, is never inspected by design; a zip-wrapped
checkpoint is opened through its central directory at the END of the file and only the pickle or
config member is read, up to a cap), report a MEDIUM "could not be fully scanned" finding instead of
a clean result when an artifact could not be walked to the end, and are entirely dependency-free (standard library only: `pickletools`, `struct`, `zipfile`,
`zlib`, `base64`), matching agentsec's own zero-runtime-dependency posture.

## Source and licence

- **Upstream:** AIsbom, `Lab700xOrg/aisbom`, https://github.com/Lab700xOrg/aisbom (the
  `aisbom/safety.py`, `aisbom/scanner.py` and `aisbom/protobuf_reader.py` modules).
- **Licence:** Apache License 2.0. Checked by fetching the upstream `LICENSE` file from the default
  branch on 2026-10-18 (it opens "Apache License / Version 2.0, January 2004"); the same fetch found
  no upstream `NOTICE` file to carry forward. Not pinned to an upstream commit, so re-check if the
  upstream licence changes. Compatible with this repository's Apache-2.0 licence.
- **What was carried over:** the dangerous-globals table (pickle), the Keras Lambda / marshal
  signatures, the Jinja escape-token lists (GGUF) and the ONNX protobuf field numbers were ported
  near-verbatim, with the stdlib-only, non-executing design kept; each guard module's docstring and
  `wiki/guards/<id>.md` names the upstream file it came from. The detection code itself (bounded
  reads, the incomplete-scan disclosure, the owner-side-only opt-outs) is agentsec's own.
