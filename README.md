# email-security-audit

A [Claude Code](https://claude.com/claude-code) skill that audits and fixes a domain's email authentication (**SPF, DKIM, DMARC**) and reads DMARC aggregate reports — so nobody can spoof your domain.

Built after stopping a live sextortion spoofing attack on a real business: audit → `p=none` → `p=quarantine` → `p=reject`, verified by the DMARC reports that later caught a real spoofer in the act.

## What it does

**Mode 1 — Audit a domain.** Checks SPF, DKIM, DMARC, and MX against a public resolver, grades the problems worst-first, and outputs **exact copy-paste DNS records** to fix them — including the safe `none → quarantine → reject` rollout so you never block your own mail.

**Mode 2 — Read DMARC reports.** Point it at the `.xml` / `.zip` / `.gz` report files that Google, Microsoft and others email you, and it groups traffic by source, **tells spoofers from legitimate forwarders**, and flags anything blocked by policy.

## The parser (standalone)

`scripts/parse_dmarc.py` needs nothing but Python 3 — standard library only, cross-platform (Windows / macOS / Linux):

```bash
python scripts/parse_dmarc.py <files-or-folder> [--known-ip <your-server-ip>]
```

Example output:

```
[OK] 198.51.100.10   23 msgs   YOUR SERVER
[-]  203.0.113.55     2 msgs   legitimate (DKIM signed) - forwarder/partner/service
[!]  192.0.2.44       1 msgs   SPOOFER (blocked by policy)
```

The verdict logic is the point: a foreign IP with a valid DKIM signature is a **forwarder or authorized partner**, not an attacker — a spoofer cannot forge your DKIM. A foreign IP failing both DKIM and SPF is the real thing.

## Install as a Claude Code skill

Copy this folder into `~/.claude/skills/`. Claude Code picks it up automatically whenever a task involves email authentication, spoofing, or DMARC reports.

## Why it matters

Most small businesses have no DMARC record at all — which is exactly what lets anyone send mail "as" their domain. This skill closes that door and proves it closed.

## License

MIT
