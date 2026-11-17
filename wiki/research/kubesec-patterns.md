---
type: Research
title: kubesec (ControlPlane) — Kubernetes Manifest Security Patterns
description: Statically-detectable Kubernetes workload-manifest misconfiguration patterns, sourced from kubesec's own rule engine, mapped to agentsec coverage.
tags: [research, kubernetes, k8s, container, iac]
timestamp: "2026-07-13T00:00:00Z"
---

# kubesec (ControlPlane) — Kubernetes Manifest Security Patterns

## What this covers

kubesec is a Kubernetes manifest security scorer: it evaluates a Pod-shaped workload manifest
(Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob/ReplicaSet) against a rule set covering
container privilege, host-namespace isolation, capability grants, and credential exposure. Every
pattern below is sourced directly from kubesec's own rule implementation, not inferred from
general Kubernetes hardening advice.

## Container-escape-shaped misconfigurations

| Pattern | What it means | Detection |
|---|---|---|
| Privileged container | `securityContext.privileged: true` disables nearly all container isolation — full host device/kernel access | `privileged: true` present in a workload manifest |
| Docker-socket mount | A `hostPath` volume to `/var/run/docker.sock` gives the container the same control as the node's Docker daemon — the classic "socket = root" escalation | `hostPath.path` referencing `/var/run/docker.sock` |
| Dangerous capability grant | `capabilities.add` containing `SYS_ADMIN` (a "huge hammer" covering mount, ptrace-adjacent syscalls, kernel keyring) or `ALL` (every capability at once) | `SYS_ADMIN`/`ALL` present in a `capabilities.add` list |

## Host-namespace sharing

`hostPID`/`hostNetwork`/`hostIPC: true` each share a piece of the underlying NODE with the pod,
breaking the isolation Kubernetes is supposed to provide:

- **`hostPID`** — a compromised container can see and signal every process on the node, including
  other pods'.
- **`hostNetwork`** — exposes the node's real network interfaces and bypasses NetworkPolicy
  enforcement entirely.
- **`hostIPC`** — grants access to other processes' shared-memory segments and semaphores.

These fields are occasionally needed by legitimate infrastructure workloads (a CNI plugin, a
node-monitoring DaemonSet) but almost never by an application workload — the class of manifest
most deployments actually ship.

## The default-mount credential nobody asked for

Kubernetes automounts the pod's service-account token
(`/var/run/secrets/kubernetes.io/serviceaccount/token`) into every container **by default**,
unless a manifest explicitly opts out with `automountServiceAccountToken: false`. A workload that
never calls the Kubernetes API still ends up with a live, exfiltratable cluster credential sitting
in every one of its containers — for no functional reason. This is a "presence of a positive
opt-out" check, the opposite polarity of most misconfiguration patterns: the finding is the
ABSENCE of `false`, not the presence of `true`.

## Hardening controls left unset

Two more controls follow the same "absence of a positive opt-in" shape as the service-account
token check: **`readOnlyRootFilesystem`** (a writable container image filesystem gives a
compromised process somewhere to persist a payload outside its declared volumes) and
**`runAsNonRoot`** (without it, a container runs as whatever user its image defaults to — root, if
the image was built without a `USER` directive, or if a later base-image change silently regresses
to root, regardless of what the Dockerfile itself says).

## Confinement layers turned off explicitly

`seccompProfile.type: Unconfined` and `appArmorProfile.type: Unconfined` each explicitly disable a
kernel-level syscall/capability confinement layer that's on by default in modern Kubernetes. An
`Unconfined` profile removes that whole layer of defense for the container — the same *widened
blast radius* risk as the privilege/capability patterns above, just from the syscall-filtering
angle. A named custom profile is a legitimate, hardened choice and is not flagged; only the literal
`Unconfined` string is.

## A single process gaining more privilege than its parent

`allowPrivilegeEscalation: true` lets a process inside the container escalate past its starting
privilege level — most commonly via a setuid/setgid binary or a file capability baked into the
image. It's a narrower path to the same class of risk as running fully privileged, worth checking
independently since a manifest can correctly avoid `privileged: true` while still leaving this
door open.

## RBAC: the most severe misconfiguration in the whole rule set

A `ClusterRoleBinding`/`RoleBinding` whose `subjects` list includes `system:anonymous` grants
whatever that role can do to ANYONE who can reach the API server — authenticated or not. This is
categorically worse than every other pattern here: those widen what a compromised container can
do; this one defeats authentication itself, before any compromise has even happened. Real-world
incidents involving an anonymous binding to `cluster-admin` have led to full cluster takeover.

## What's a real finding vs. a scoring nuance

kubesec is a points-based scorer, not a strict pass/fail tool — some of its rules reward a
hardening step's presence rather than penalize a violation's presence. Translating a scoring
bonus's absence into a hard security *finding* isn't always a faithful port: most ordinary
manifests simply don't set every hardening knob, and treating that omission as a violation would
generate significant noise relative to the signal. The patterns worth porting as findings are the
ones with a clear, asymmetric bad state — an explicit `true` on a dangerous field, a dangerous
capability explicitly *added*, a credential mount not explicitly disabled — not "didn't configure
every optional hardening control." (Left out for exactly this reason: a numeric UID/GID threshold
kubesec applies to `runAsUser`/`runAsGroup`, and a blanket flag on any `Secret` consumed via
environment variables — both real signals, but each needs its own severity/threshold judgment call
before it can be a trustworthy default-on finding.)
