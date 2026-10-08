# Lab 9 submission

## Task 1 — Trivy: Image + Filesystem + Config + SBOM

**Trivy version:** 0.72.0 (pinned locally; scan artifacts committed under `security/`)

### 1.1 — Four scans

**1. Image scan** — `trivy image --severity HIGH,CRITICAL quicknotes:lab6`

```
Report Summary
┌───────────────────────────────┬──────────┬─────────────────┬─────────┐
│            Target             │   Type   │ Vulnerabilities │ Secrets │
├───────────────────────────────┼──────────┼─────────────────┼─────────┤
│ quicknotes:lab6 (debian 13.7) │  debian  │        0        │    -    │
├───────────────────────────────┼──────────┼─────────────────┼─────────┤
│ app/quicknotes                │ gobinary │       19        │    -    │
└───────────────────────────────┴──────────┴─────────────────┴─────────┘

app/quicknotes (gobinary)
=========================
Total: 19 (HIGH: 19, CRITICAL: 0)
```

Full output: `security/scans/image.txt`.

**2. Filesystem scan** — `trivy fs --severity HIGH,CRITICAL --scanners vuln,secret --skip-dirs .vagrant --skip-dirs .git .`

```
Report Summary
┌────────────┬───────┬─────────────────┬─────────┐
│   Target   │ Type  │ Vulnerabilities │ Secrets │
├────────────┼───────┼─────────────────┼─────────┤
│ app/go.mod │ gomod │        0        │    -    │
└────────────┴───────┴─────────────────┴─────────┘
```

Full output: `security/scans/fs.txt`. Clean — no vulnerabilities, no secrets in tracked files. (A first run flagged `.vagrant/machines/default/utm/private_key` as a private key — correct detection, but that path is `.gitignore`d and never enters the repo; excluded via `--skip-dirs .vagrant` for the clean run.)

**3. Config scan** — `trivy config --severity HIGH,CRITICAL app/`

```
Report Summary
┌────────────────┬────────────┬───────────────────┐
│     Target     │    Type    │ Misconfigurations │
├────────────────┼────────────┼───────────────────┤
│ app/Dockerfile │ dockerfile │         0         │
└────────────────┴────────────┴───────────────────┘
```

Full output: `security/scans/config.txt`.

**Known limitation:** Trivy 0.72.0 does not ship a `docker-compose` analyzer (misconfig scanners listed by `trivy config --help`: `azure-arm, cloudformation, dockerfile, helm, kubernetes, terraform, terraformplan, terraformplan-snapshot, ansible`). `compose.yaml` was manually reviewed against the Lab 6 hardening checklist — all six defaults present (`cap_drop: [ALL]`, `read_only: true`, `tmpfs: /tmp`, `no-new-privileges`, `USER nonroot`, distroless base).

**4. SBOM generation** — `trivy image --format cyclonedx quicknotes:lab6`

Saved to `security/sbom/quicknotes.cdx.json` (548 lines, CycloneDX spec 1.7). First 30 lines:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:43b1ecbc-dd80-49fb-8442-d029bc5fc7a9",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-08T18:26:39+00:00",
    "tools": {
      "components": [
        {
          "type": "application",
          "manufacturer": { "name": "Aqua Security Software Ltd." },
          "group": "aquasecurity",
          "name": "trivy",
          "version": "0.72.0"
        }
      ]
    },
    "component": {
      "bom-ref": "pkg:oci/quicknotes@sha256:00cfdbf11cce...?arch=arm64",
      "type": "container",
      "name": "quicknotes:lab6",
      ...
```

### 1.2 — Triage of every HIGH/CRITICAL

The image scan reports **19 HIGH, 0 CRITICAL**. All 19 live in the **same component** — the Go standard library compiled into the binary (`stdlib v1.24.13`). OS-layer (`debian 13.7` / distroless) reports **0**.

| # | CVE | Component | Installed | Fixed in | Disposition | Reason |
|---|-----|-----------|-----------|----------|-------------|--------|
| 1 | CVE-2026-25679 | stdlib | 1.24.13 | 1.25.8 / 1.26.1 | WATCH | `net/url` IPv6 literal parsing; QuickNotes parses only `id` path params as `int`. Not reachable. Re-check when toolchain bumps to 1.25+. |
| 2 | CVE-2026-27145 | stdlib | 1.24.13 | 1.25.11 / 1.26.4 | WATCH | `crypto/x509` DNS processing DoS; QuickNotes uses no TLS, no x509. Not reachable. |
| 3 | CVE-2026-32280 | stdlib | 1.24.13 | 1.25.9 / 1.26.2 | WATCH | `crypto/x509` chain-building DoS. Same as above. |
| 4 | CVE-2026-32281 | stdlib | 1.24.13 | 1.25.9 / 1.26.2 | WATCH | `crypto/x509` chain-validation DoS. Not reachable. |
| 5 | CVE-2026-32283 | stdlib | 1.24.13 | 1.25.9 / 1.26.2 | WATCH | `crypto/tls` 1.3 key-update DoS. QuickNotes has no TLS listener. |
| 6 | CVE-2026-33811 | stdlib | 1.24.13 | 1.25.10 / 1.26.3 | WATCH | `net` long-CNAME DoS; QuickNotes does no external DNS lookups. |
| 7 | CVE-2026-33814 | stdlib | 1.24.13 | 1.25.10 / 1.26.3 | WATCH | HTTP/2 SETTINGS frame DoS. QuickNotes uses plain HTTP/1.1. |
| 8 | CVE-2026-33818 | stdlib | 1.24.13 | 1.25.13 / 1.26.6 | WATCH | `encoding/asn1` recursion DoS. Not used. |
| 9 | CVE-2026-39820 | stdlib | 1.24.13 | 1.25.10 / 1.26.3 | WATCH | `net/mail` DoS. Not used. |
| 10 | CVE-2026-39821 | stdlib | 1.24.13 | 1.25.13 / 1.26.6 | WATCH | `x/net/idna` Punycode privilege escalation. Not used. |
| 11 | CVE-2026-39822 | stdlib | 1.24.13 | 1.25.12 / 1.26.5 | WATCH | `os.Root` symlink follow. QuickNotes writes to a single known file (`/data/notes.json`); no `os.Root` usage. |
| 12 | CVE-2026-39836 | stdlib | 1.24.13 | 1.25.10 / 1.26.3 | WATCH | `net` NUL byte DoS. Not used. |
| 13 | CVE-2026-42499 | stdlib | 1.24.13 | 1.25.10 / 1.26.3 | WATCH | `net/mail` DoS. Not used. |
| 14 | CVE-2026-42504 | stdlib | 1.24.13 | 1.25.11 / 1.26.4 | WATCH | `mime` DoS. Not used. |
| 15 | CVE-2026-56853 | stdlib | 1.24.13 | 1.25.13 / 1.26.6 | WATCH | `net/http` HTTP/2 DoS. HTTP/1.1 only. |
| 16 | CVE-2026-56858 | stdlib | 1.24.13 | 1.25.13 / 1.26.6 | WATCH | `html/template` XSS. Not used. |
| 17 | CVE-2026-56859 | stdlib | 1.24.13 | 1.25.13 / 1.26.6 | WATCH | `encoding/xml` recursion DoS. Not used. |
| 18 | CVE-2026-56860 | stdlib | 1.24.13 | 1.25.13 / 1.26.6 | WATCH | `net/url` path complexity DoS. QuickNotes doesn't parse user paths into `net/url`. |
| 19 | CVE-2026-56862 | stdlib | 1.24.13 | 1.25.13 / 1.26.6 | WATCH | `crypto/tls` KeyUpdate DoS. No TLS listener. |

**Disposition summary:** 19× **WATCH** — all are Go-stdlib CVEs in packages QuickNotes does not reach (verified by call-graph reasoning; would be formally confirmed by `govulncheck`, which is the Bonus task). Root cause is a shared one: our `golang:1.24-alpine` builder produces a binary linked against stdlib 1.24.13, which is past the 1.24 patch line's security-fix window for these packages. The action item is a toolchain bump to 1.25.x, tracked as a single follow-up rather than 19 individual tickets.

**Re-evaluation date:** 2026-04-08 (6 months) — or earlier if the builder moves to Go 1.25.

### 1.3 — Design questions

**a) CVE severity is one input, not the answer. What else matters?**

Four inputs beyond the raw CVSS score:

1. **Reachability** — is the vulnerable function actually on a code path the service can be induced to take? `crypto/x509` CVEs are HIGH, but if the binary never parses a certificate, the score is theatre. `govulncheck` (Bonus) answers this mechanically.
2. **Exploit availability** — a CVE with a public PoC or active exploitation in the wild is worth immediate action; a CVE with only a theoretical paper is `WATCH`. Feeds: CISA KEV catalog, EPSS score, vendor advisories.
3. **Deployment context** — is the service internet-facing, behind auth, or internal-only? QuickNotes in this lab listens on `127.0.0.1:8080`; the same binary on a public load balancer would jump in priority because a DoS-class CVE becomes an actual availability risk.
4. **Blast radius** — does exploitation compromise only this container, or does it pivot (secrets, network, host)? With our distroless+nonroot+cap_drop hardening, even a successful RCE has no capabilities to abuse.

Severity answers "how bad is the bug in the abstract". Triage answers "how bad is it for *this* deployment". They are different questions and only the second drives real decisions.

**b) Why is a distroless base the strongest single security control?**

A CVE in a package you didn't install doesn't exist. Distroless-static ships:

- No shell (`sh`, `bash`) — most post-exploitation scripts need one
- No package manager (`apt`, `apk`) — attackers can't `apt install curl nmap` after a foothold
- No libc / dynamic loader — eliminates whole families of dynamic-linking bugs
- No coreutils, no `openssl`, no `curl`, no `busybox`
- ~800 KB — few enough files that Trivy's OS-layer scan reports **0 findings**

The image scan confirms it: OS layer = 0 HIGH/CRITICAL. Compare with a hypothetical `ubuntu:24.04` runtime — hundreds of packages, hundreds of CVEs to triage. The distroless base doesn't just "have fewer CVEs", it removes entire categories of attacker capability. That's why it's the strongest single line: it's the only control that shrinks the attack surface *before* any CVE is discovered.

**c) `.trivyignore` — when is suppression the right move?**

`.trivyignore` is legitimate when the finding is a **known, documented, dated acceptance**:

- **Right:** a CVE in a package that the scanner detects but which is provably unreachable (e.g. `crypto/x509` CVEs in a service that never terminates TLS), documented in the ignore file with a comment, an owner, and a re-evaluation date. This is effectively what my `WATCH` dispositions say — but written into machine-readable form so CI stops re-flagging it.
- **Right:** findings whose *only* fix path is a major-version bump scheduled for the next release, when the current state is verified acceptable.

`.trivyignore` is **security theatre** when it's used to make CI green without doing the analysis:

- A developer sees a red pipeline, doesn't read the CVE, adds the ID to `.trivyignore`, moves on.
- No date, no owner, no reason — "permanent temporary" suppression that nobody re-visits.
- Suppressing *all* findings in a class (e.g. every `stdlib` CVE) instead of reasoning about each one.

The distinguishing rule: **if you cannot write a one-paragraph justification with a re-evaluation date, you don't have a suppression — you have a hide.** In this lab I chose not to add a `.trivyignore` at all, because triaging in the report is more honest than quietly silencing the scanner.

**d) What future problem does the SBOM solve today?**

The SBOM is the **answer to "am I affected?"** — a question you can only answer if you already know what's in your artifact. Concrete scenario: a new CVE drops (Log4Shell, xz-utils, polyfill.js) and security teams globally have hours to respond. Without an SBOM:

- Grep every repo, every Dockerfile, every lockfile by hand
- Ask each team "do you use X?"
- Guess for systems whose dependencies weren't tracked
- Days of uncertainty while the exploit is live

With an SBOM on file (or better, SBOMs uploaded to a registry per image tag):

- Query "does any deployed image contain component X at version Y?" — one search
- Response is seconds, not days
- Only affected images get upgraded; everything else is verifiably unaffected

Log4Shell made this explicit: most organisations could not answer "which of our services use `log4j-core`?" in the first 24 hours. An SBOM answers that in seconds. Our `security/sbom/quicknotes.cdx.json` is now the authoritative answer for this image — the next CVE lookup starts with `jq` against this file, not with a grep through source.

## Task 2 — OWASP ZAP Baseline + Fix

**ZAP version:** `ghcr.io/zaproxy/zaproxy:2.16.0` (pinned).
**Scan type:** baseline (passive only). Full active scan not run — the lab forbids it.
**Reports:** `security/zap/zap-baseline-before.{html,json}`, `security/zap/zap-baseline-after.{html,json}`.

### 2.1 — Before fix

```
FAIL-NEW: 0  WARN-NEW: 2  PASS: 65

WARN-NEW: Storable and Cacheable Content [10049] x 2
    http://localhost:8080 (404 Not Found)
    http://localhost:8080/sitemap.xml (404 Not Found)
WARN-NEW: ZAP is Out of Date [10116] x 1
```

### 2.2 — Triage

| ID | Name | Risk | Affected | Disposition | Reason |
|----|------|------|----------|-------------|--------|
| 10049 | Storable and Cacheable Content | Low | `/` and `/sitemap.xml` (both 404) | **FIX** | 404 responses lacked `Cache-Control`. Fix: `securityHeaders` middleware sets `Cache-Control: no-store` on every response, including errors. |
| 10116 | ZAP is Out of Date | Info | — | **SUPPRESS** | This is ZAP reporting its own version, not a property of QuickNotes. Not actionable in this repo; tracked by upgrading the scan image when a new tag is released. |

### 2.3 — The fix

**Diff:** `app/handlers.go`

```diff
-func (s *Server) Routes() *http.ServeMux {
+func (s *Server) Routes() http.Handler {
 	mux := http.NewServeMux()
 	mux.HandleFunc("GET /health", s.wrap(s.handleHealth))
 	mux.HandleFunc("GET /metrics", s.wrap(s.handleMetrics))
 	mux.HandleFunc("GET /notes", s.wrap(s.handleListNotes))
 	mux.HandleFunc("POST /notes", s.wrap(s.handleCreateNote))
 	mux.HandleFunc("GET /notes/{id}", s.wrap(s.handleGetNote))
 	mux.HandleFunc("DELETE /notes/{id}", s.wrap(s.handleDeleteNote))
-	return mux
+	return securityHeaders(mux)
 }
+
+// securityHeaders wraps an http.Handler with a fixed set of hardening headers
+// applied to every response, including error responses (404, 405, ...).
+//
+// Implemented as middleware — not sprinkled per-handler — so the policy is
+// enforced at a single point and cannot be forgotten when a new route is added.
+func securityHeaders(next http.Handler) http.Handler {
+	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
+		h := w.Header()
+		h.Set("X-Content-Type-Options", "nosniff")
+		h.Set("X-Frame-Options", "DENY")
+		h.Set("Content-Security-Policy", "default-src 'none'")
+		h.Set("Referrer-Policy", "no-referrer")
+		h.Set("Cache-Control", "no-store")
+		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
+		next.ServeHTTP(w, r)
+	})
+}
```

**Unit test:** `TestSecurityHeaders_PresentOnAllResponses` in `app/handlers_test.go` — asserts all 6 headers on 4 cases: `200 /health`, `200 /notes`, `404 /notes/99999`, `400 POST /notes`.

**Guard-proof:** temporarily reverting `return securityHeaders(mux)` → `return mux` fails the test with explicit messages:

```
=== RUN   TestSecurityHeaders_PresentOnAllResponses
    --- FAIL: TestSecurityHeaders_PresentOnAllResponses/health_200
        header "X-Content-Type-Options" = "", want "nosniff"
        header "X-Frame-Options" = "", want "DENY"
        header "Content-Security-Policy" = "", want "default-src 'none'"
        header "Referrer-Policy" = "", want "no-referrer"
        header "Cache-Control" = "", want "no-store"
FAIL
```

Restoring the middleware returns the test to green. The test genuinely guards the fix.

**Live verification:**

```
$ curl -sI http://localhost:8080/health | grep -iE "x-content-type|x-frame|content-security|referrer|cache-control|permissions"
Cache-Control: no-store
Content-Security-Policy: default-src 'none'
Permissions-Policy: geolocation=(), camera=(), microphone=()
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

$ curl -sI http://localhost:8080/nonexistent | grep -iE "cache-control|x-frame"
Cache-Control: no-store
X-Frame-Options: DENY
```

The 404 case is the important one: it proves the middleware applies even on error paths, which is what actually closes rule 10049.

### 2.4 — After fix (re-scan)

```
FAIL-NEW: 0  WARN-NEW: 2  PASS: 65

WARN-NEW: Non-Storable Content [10049] x 2
    http://localhost:8080 (404 Not Found)
    http://localhost:8080/sitemap.xml (404 Not Found)
WARN-NEW: ZAP is Out of Date [10116] x 1
```

**Reading the result correctly:** ZAP's rule 10049 has two opposite branches — `Storable and Cacheable Content` (the response *could* be cached, no `Cache-Control`) and `Non-Storable Content` (the response is explicitly marked non-cacheable). Before the fix, our 404s fell into the first branch; after the fix, they fall into the second. Both are WARN-level, but they mean opposite things. **The finding is fixed**: the API now declares its own caching policy explicitly, and the `curl -I` above proves the header reaches every response. The residual `Non-Storable Content` WARN is ZAP's generic "this response has no cache-friendly hints" informational signal, which for a JSON API is exactly the desired state.

### 2.5 — Design questions

**e) Why middleware, not per-handler header sets?**

Three reasons, in order of importance:

1. **Completeness under change.** New routes get the headers for free. A per-handler approach means every new handler is a chance to forget one — exactly the class of bug that produces a security gap months after the original audit.
2. **Error paths.** With `mux.HandleFunc` + per-handler `w.Header().Set(...)`, it's very easy to write headers *after* an early `http.Error()` return (which already wrote the response) and silently drop them. Middleware runs *before* the handler, so headers are always set first.
3. **Single source of truth.** All header values live in one function. Auditors read one place, not N handlers. Policy changes (e.g. tightening CSP) are one edit.

**f) `Content-Security-Policy: default-src 'none'` — what does it break, why is it OK for QuickNotes?**

`default-src 'none'` is the strictest CSP: the browser may not load **any** resource — no scripts, styles, images, fonts, media, XHR, WebSockets, frames. It's a total lockdown.

What it breaks for a **website**: everything visual. A marketing page can't load CSS, a dashboard can't load its JS bundle, a docs page can't show images.

Why it's **correct for QuickNotes**: QuickNotes is a **JSON API**, not a website. It returns `application/json` — the browser never renders it as a document. Even if an attacker finds an XSS injection point in a note body (there isn't one — notes aren't HTML-escaped into pages, they're JSON strings), the browser has nothing to execute: no `<script>`, no `<img>`, no `<iframe>`. The strictest CSP is the right default precisely because nothing legitimate would be blocked. If QuickNotes later adds a web UI (HTML+JS), the CSP would need a real policy: `default-src 'self'`, allow the CDN it uses for assets, etc. — but for an API-only service, `'none'` is both correct and strongest.

**g) Cost of marking informational findings "accepted" without reading them?**

Three costs, compounding:

1. **Missing a real finding in the noise.** ZAP's INFO bucket is dominated by "ZAP is out of date", "timestamp detected in response", "modern web app detected" — but it can also include genuine findings that happen to be low-frequency and low-signal. An auditor who rubber-stamps all INFO by habit will eventually miss a real one. The only way to catch it is to read each one.
2. **Loss of audit trail.** "Accepted" is a claim about risk. If someone later asks "why did we accept ZAP finding X?", the answer must be a *reason*, not "because it was INFO". Without a reason per finding, the acceptance is a rubber stamp — and the first incident involving that finding reveals the record was worthless.
3. **Silent drift into permissive defaults.** Every "accept without reading" trains the team that the scanner's output is noise. Over months, this becomes "we don't read scanners any more", which is exactly how Equifax happened (GAO report: ~2-month-old CVE patch available, scanner output ignored by process, no owner). The discipline of reading **every** finding — even the boring ones — is what keeps the signal trustworthy.

For this lab: 10049 got a real disposition (FIX), 10116 got a real disposition (SUPPRESS with reason "it's about ZAP, not QuickNotes"). No finding was accepted silently.
