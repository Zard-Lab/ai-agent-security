"""Live-host hardening audit (`agentsec harden-host`).

The opt-in counterpart to the static host-config guards: instead of reading a repo's
committed host config, it reads the RUNNING host (sshd -T, ufw status, systemctl,
listening sockets) and emits the same `Finding` model. It is a deliberate, separate
subcommand (not part of `audit`) because reading the live host departs from agentsec's
repo-static, zero-host-read posture. Every probe is read-only and never raises.
"""
from __future__ import annotations

from agentsec.hostaudit.audit import HostAuditResult, audit_host

__all__ = ["HostAuditResult", "audit_host"]
