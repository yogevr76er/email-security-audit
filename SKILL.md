---
name: email-security-audit
description: Use when auditing or fixing a domain's email authentication (SPF, DKIM, DMARC) — someone is sending mail as / spoofing a domain, you are setting up anti-spoofing, mail lands in spam, you need to read DMARC aggregate (rua) report files (.xml/.zip/.gz), or you are guiding a non-technical person through fixing it themselves (who may not even know where their DNS is managed). Covers checking records, producing exact DNS fixes, the none→quarantine→reject rollout, telling spoofers from legitimate forwarders, and step-by-step platform-specific setup.
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

## Mode 3 — Guided fix (walk a non-technical owner through it themselves)

The whole point: replace "call your IT person" with "do it yourself, guided." **You are the IT consultant who owns the whole thing end to end** — discovery, the fix, the gradual rollout, and the days of report-reading that follow — not a one-shot answer. Go slow, **one question per message**, explain *why* before *how*, and never assume the person knows what DNS, a record, or a nameserver is.

### Step 0 — Find where their DNS actually lives (most people have no idea)
Do not ask "where do you edit your DNS?" cold — many owners genuinely don't know. Discover it for them from the **nameservers**:
`Resolve-DnsName -Type NS <domain> -Server 8.8.8.8` · `dig +short NS <domain> @8.8.8.8`

| Nameserver looks like | DNS is managed at |
|-----------------------|-------------------|
| `*.cloudflare.com` | Cloudflare |
| `ns-cloud-*.googledomains.com` | Google Cloud DNS |
| `*.domaincontrol.com` | GoDaddy |
| `*.registrar-servers.com` | Namecheap |
| `ns*.wixdns.net` | Wix |
| a web host's NS (e.g. `*.livedns.co.il`) | that host's cPanel |

Then confirm in plain language: "Where did you buy the domain?" · "Who built or hosts your website?" · "Do you log in anywhere to manage the site?" The MX record also names the mail provider (Google Workspace, Microsoft 365, or the host itself).

Order: run the NS lookup **first** and infer the provider yourself, then confirm with the person. Only fall back to leading with the plain-language questions when you can't run a lookup (no DNS access, or the domain isn't resolving yet).

### Step 1 — Ask the two questions that decide everything (one at a time)
1. Where the DNS is edited (from Step 0).
2. Where mail is sent from as this domain — website/cPanel server, Google Workspace, Microsoft 365, a bulk sender, or several. This decides what SPF must include and whether `-all` is safe.

### Step 2 — Give click-by-click steps for THEIR platform

| Platform | Where to add a TXT record |
|----------|---------------------------|
| cPanel | Zone Editor → Manage (next to the domain) → Add Record → type **TXT** |
| Cloudflare | DNS → Records → Add record → type **TXT** |
| GoDaddy / Namecheap / registrar | DNS management / Advanced DNS → Add → **TXT** |
| Wix | Domains → your domain → DNS records |
| Google Workspace (to enable DKIM) | Admin console → Apps → Google Workspace → Gmail → Authenticate email |
| Microsoft 365 | admin.microsoft.com → Settings → Domains → DNS |

Pre-empt the #1 confusion: a name starting with `_` (like `_dmarc`) must be a **TXT** record — never A or CNAME. In cPanel, picking "A" throws an "underscore not allowed" error.

### Step 3 — Walk the gradual rollout; never let them jump to reject
`p=none` (listen ~1 week, confirm their real mail passes) → `p=quarantine` → `p=reject`. Explain what each stage does before they save it. Jumping straight to reject can silently block their own mail.

### Step 4 — If they're scared, reassure BEFORE fixing
Many arrive because of a spoofing/sextortion email that appears to come from themselves. First, calm them: it is not a hack, nobody accessed the account, the From address was merely forged, and the "we recorded you" threat is an empty mass-scam. A calm person can follow steps; a panicked one cannot. Then fix.

### Step 5 — Stay with them through the daily reports (most guides quit here — don't)
Set the expectation up front: once `rua` is set, a report arrives **roughly once a day** from each provider (Google, Microsoft…) as an .xml/.zip/.gz attachment. This is normal status, not an alarm — every provider that received mail "from" the domain files one, even when everything is fine.

Offer to read each report *with* them: point Mode 2's parser at it and translate the output into plain language — "this is all you, you're clean," or "here's an unknown sender that was blocked." Don't leave them staring at raw XML.

The reports are what drive the rollout — they are not decoration. Only move `none → quarantine → reject` once about a week of reports confirms every legitimate sender passes. Once it's stable at reject, remove `rua` to switch the daily emails off. That full arc — from "where does my DNS live?" to the day you turn the reports off — is the job.

## "I still get it myself, even after reject"

A common, confusing follow-up: the reports show spoofers rejected, yet the owner still finds the forged mail in their **own** inbox. This is expected, not a failure — separate the two goals:

- **DMARC is enforced by the *receiving* server.** Gmail, Outlook.com, and any DMARC-respecting host obey your `reject`, so your customers, suppliers, and the outside world never see the forgery. That is the whole point, and it is working — the reports prove it.
- **But the owner's own inbox often sits on a server that doesn't enforce DMARC on inbound mail** (many cPanel / shared hosts don't check it by default). A forgery sent *from you, to you* lands on that server and slips into the inbox, even while the rest of the world rejects it.

So: DMARC protects **who receives mail in your name** (reputation). Cleaning **your own inbox** is a separate, local step.

**To stop the owner seeing it — filter on authentication failure, NEVER on `From`.**
A rule like "From contains me → Junk" also junks the legitimate mail the owner sends to themselves. Instead, filter on the auth result: real self-sent mail leaves the owner's own server and passes SPF+DKIM aligned; the forgery arrives from outside and fails. **First read the forged message's Internet headers** to see exactly which header the server writes (`Authentication-Results`, `Received-SPF`), then match the failure (e.g. `dmarc=fail`) — that catches only the forgery. Note that SPF alone can `pass` for the spoofer's *own* envelope domain, so match DMARC/alignment failure, not bare `spf=fail`.

The fuller fix is enabling DMARC enforcement on the inbound server itself (server / WHM level), where available.

## Common mistakes
- Jumping to `p=reject` without the none→quarantine monitoring window → blocks your own mail silently.
- Treating a foreign IP with DKIM=pass as an attacker → it is forwarding/authorized; the valid DKIM proves it.
- Removing `rua` too early → you lose the visibility that confirms the rollout is safe.
- Auditing against the local resolver (cached) instead of a public one → you see stale records.
- Hardening SPF to `-all` while forgetting a legitimate sender (Google Workspace, a CRM, a partner) → their mail fails. Confirm all real senders from the reports first.
- Filtering your own inbox by `From` (= your own address) instead of by authentication result → also junks the mail you legitimately send to yourself. Match the auth-failure header instead.
- Assuming `reject` cleans your own inbox → it protects external recipients; your own server may not enforce DMARC on inbound mail. See "I still get it myself, even after reject" above.

## Real-world impact
Deployed on a live domain under an active sextortion spoofing attack. Audit found DMARC entirely missing; rolled out none→quarantine→reject over ~2 weeks. Reports later caught a real spoofer (foreign IP, DKIM+SPF fail, disposition=quarantine — auto-blocked) while a legitimate partner forwarding mail (DKIM pass) kept flowing untouched.
