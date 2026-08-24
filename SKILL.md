---
name: email-security-audit
description: Use when auditing or fixing a domain's email authentication (SPF, DKIM, DMARC) — someone is sending mail as / spoofing a domain, you are setting up anti-spoofing, mail lands in spam, or you need to read DMARC aggregate (rua) report files (.xml/.zip/.gz). Covers checking records, producing exact DNS fixes, the none→quarantine→reject rollout, and telling spoofers from legitimate forwarders in reports.
---

# Email Security Audit (SPF / DKIM / DMARC)

## Overview
Diagnose and fix a domain's email authentication so nobody can spoof it, and read the DMARC reports that prove it worked. Core principle: **DMARC is the lock; SPF and DKIM are the keys it checks. A missing DMARC record is an open door to spoofing** — every other issue is secondary to that.

## When to use
- "Someone is sending emails as me / in my name" — spoofing, or sextortion scams that forge your own address
- Setting up anti-spoofing for a domain
- Mail lands in recipients' spam and the cause is unknown
- DMARC report files arrived (.xml / .zip / .gz from google.com, outlook.com) and need reading
- Pre-checking any domain's email-security posture (yours, a client's, a prospect's)

## Mode 1 — Audit a domain

Query a **public** resolver (8.8.8.8), never the local one (stale cache):

| Record | Name to query | Look for |
|--------|---------------|----------|
| SPF | root domain, TXT | `v=spf1 ...` |
| DKIM | `<selector>._domainkey.<domain>`, TXT | `v=DKIM1` — try selectors: `default, google, k1, mail, dkim, selector1, selector2, s1, s2` |
| DMARC | `_dmarc.<domain>`, TXT | `v=DMARC1 ...` |
| MX | root domain, MX | where mail is received (tells you the provider) |

Commands — Windows: `Resolve-DnsName -Type TXT -Server 8.8.8.8 <name>` · Unix: `dig +short TXT <name> @8.8.8.8`

**Grade findings, worst first:**
- **DMARC missing** → CRITICAL. This is what allows spoofing. Fix first, always.
- **DMARC `p=none`** → monitoring only; not protecting yet.
- **SPF missing** → high · **SPF `~all`** → soft, prefer `-all` · **SPF `+all`** → CRITICAL (allows anyone).
- **DKIM missing on every selector** → medium (weakens DMARC; DMARC can still pass via SPF).

**Always output exact, copy-paste DNS records to fix each issue**, not just advice. Starter DMARC record:
```
v=DMARC1; p=none; rua=mailto:reports@<domain>; fo=1
```

**The 3-stage DMARC rollout — never skip straight to reject:**
1. `p=none` — listen 1–2 weeks, collect reports, confirm your real mail passes.
2. `p=quarantine` — spoofed mail lands in the recipient's spam.
3. `p=reject` — spoofed mail is rejected entirely.

After it is stable at `reject`, remove `rua` (→ `v=DMARC1; p=reject`) to stop the report emails. Reports are temporary scaffolding, not forever.

## Mode 2 — Read DMARC aggregate reports

Reports are emailed to the `rua` address as .xml / .zip / .gz. Parse them:
```
python scripts/parse_dmarc.py <files-or-folder> [--known-ip <your-server-ip>]
```

**Read the output by the DKIM, SPF, and disposition columns:**
- Your server IP, DKIM/SPF **pass** → your legitimate mail. ✅
- **Foreign IP + DKIM fail + SPF fail** → a **spoofer**. If DMARC is active, `disposition` = quarantine/reject means it was blocked. 🚨
- **Foreign IP + DKIM pass (d=your-domain)** → **NOT** a spoofer. Legitimate forwarding, or an authorized partner/service — a spoofer cannot forge your DKIM signature. Confirm you recognize the source.
- SPF may `pass` for a different envelope domain yet fail *alignment* (e.g. envelope = your host's domain). Normal for some server/forwarded mail; DKIM covers it.

## Common mistakes
- Jumping to `p=reject` without the none→quarantine monitoring window → blocks your own mail silently.
- Treating a foreign IP with DKIM=pass as an attacker → it is forwarding/authorized; the valid DKIM proves it.
- Removing `rua` too early → you lose the visibility that confirms the rollout is safe.
- Auditing against the local resolver (cached) instead of a public one → you see stale records.
- Hardening SPF to `-all` while forgetting a legitimate sender (Google Workspace, a CRM, a partner) → their mail fails. Confirm all real senders from the reports first.

## Real-world impact
Deployed on a live domain under an active sextortion spoofing attack. Audit found DMARC entirely missing; rolled out none→quarantine→reject over ~2 weeks. Reports later caught a real spoofer (foreign IP, DKIM+SPF fail, disposition=quarantine — auto-blocked) while a legitimate partner forwarding mail (DKIM pass) kept flowing untouched.
