# Decisions

Format: `- Ruling: <what> — <why> — <cost if wrong>`.

## Process

- Ruling: continue the interrupted earlier build of this project (6 commits: core model, collectors, rules, library, engine) rather than start over — the existing code was coherent, typed and lint-clean, and restarting would discard ~3k reviewed lines — if its design had hidden flaws they carry forward; mitigated by writing the full test suite against it, which surfaced and fixed three real bugs (TSC labels with commas parsed as YAML flow keys, lenient base64 decoding, mock fixture validation).
- Ruling: Python 3.12 with uv, runtime deps limited to PyYAML, Jinja2 and cryptography — all mature, pinned in `uv.lock`; stdlib covers HTTP, CSV, tar and hashing — a larger ecosystem (pydantic, httpx) would shorten some code but add surface area to review.

## Scope and honesty

- Ruling: collectors read exports, snapshots or a mock API; no live AWS/Okta/HRIS/MDM calls — the contract forbids network in tests, and evidence pipelines in practice consume exports produced by trusted jobs — users must produce the input files themselves; documented in docs/COLLECTORS.md.
- Ruling: the GitHub collector has a real API mode, but it is exercised only against the bundled offline mock (in-process and over a loopback socket) — proves the HTTP path end to end without touching third-party systems — live GitHub quirks (pagination is not needed for these endpoints, but rate limits and SSO-enforced tokens are) are untested.
- Ruling: TSC catalog ships identifiers with short labels paraphrased for this project; the ISO catalog ships Annex A identifiers with control headings only — the criteria text (AICPA) and control statements (ISO) are copyrighted — labels are navigation aids, not authority; README and catalog headers say so.
- Ruling: the sample library's framework mappings are presented as this project's judgement for a fictional company — there is no licence-free official mapping to reproduce — an auditor may map differently; the README disclaimer and library header state it.
- Ruling: every package page carries the "supports an audit, does not replace one" disclaimer, and so do the CLI output and the README — the spec requires it, and the risk of a tool output being mistaken for an attestation is real — none.

## Evaluation semantics

- Ruling: rules are pure functions; the engine owns freshness and exceptions — one implementation of the tricky semantics, uniform across rules and plugins — rules cannot express per-item freshness (e.g. per-device check-in age), which rules model explicitly as parameters instead.
- Ruling: status precedence ERROR > NO_EVIDENCE(missing) > FAIL > NO_EVIDENCE(empty population) > STALE > EXCEPTED > PASS — a known deviation matters more than the age of its proof, and "tested nothing" must never read as PASS — some teams may prefer STALE to dominate; changing it is a one-line edit plus the decision-table tests.
- Ruling: point-in-time selection uses the UTC calendar date of `collected_at` (≤ as_of) — dates are what auditors reason in, and it makes `--as-of` reproducible — evidence collected late on as_of in a western timezone counts for that UTC day.
- Ruling: collection time is the config `collected_at`, then a source-embedded timestamp, then the clock; never file mtimes — mtimes change on copy/clone and are not evidence of when an export was taken — operators who forget to set it get "now", which can hide staleness; the sample config sets it explicitly.
- Ruling: manual-document controls set `freshness_days: 400` and enforce cadence via the rule's `max_age_days` — the document's age (performed_on) is what matters, not when its descriptor was recorded — a stale descriptor of an old document is still caught by the rule.
- Ruling: "dormant" uses IdP last login, with a grace period for never-used new accounts; service accounts are included in dormancy and admin checks but excluded from MFA by default (parameter `include_service_accounts`) — matches common SOC 2 control wording — policies differ; all thresholds are parameters.
- Ruling: Linux OS baselines compare the distribution version string (e.g. Ubuntu `24.04 >= 22.04`) — that is what MDM exports carry — kernel-based or other-distro baselines need a different parameterization.
- Ruling: CODEOWNERS `dir/*` matches only direct children while `dir` / `dir/` match the subtree, and the last matching rule wins — this is GitHub's documented behaviour — edge cases GitHub handles differently (if any) would mis-report ownership; property tests cover the core semantics.

## Exceptions

- Ruling: exceptions match by control, optional rule and fnmatch resource globs; expired or not-yet-approved entries never apply but are reported when they would have matched — makes risk acceptance explicit and auditable — glob patterns that are too broad could hide new deviations; the register's `unused` and matched-resources output make breadth visible.
- Ruling: excepted findings stay in the package next to the approving exception id — an auditor must see both the deviation and its approval — none.

## Package

- Ruling: integrity = SHA-256 manifest + `MANIFEST.sha256` (shasum format) + optional Ed25519 over manifest bytes — verifiable with standard tools and without controlmap; one signature covers everything — Ed25519 keys are not X.509-anchored; origin depends on out-of-band key distribution (documented; `--public-key` enforces it).
- Ruling: the package includes only evidence referenced by results (all selected records of the kinds each rule read), not the whole store — keeps packages minimal and self-consistent — historical records not used by any rule are not shipped; the store remains the system of record.
- Ruling: deterministic tar.gz (sorted members, zero mtimes/owners, fixed modes, gzip mtime 0) — two parties can rebuild and compare digests — archive top-level directory name is part of the bytes, so builds must use the same output name to compare archives (manifests compare regardless).
- Ruling: verification reports all problems instead of stopping at the first — one run tells an auditor everything wrong — slightly more code paths; all tested.

## Engineering

- Ruling: coverage gate at 90% branch coverage (measured 97.55%) — above the contract's 80% with headroom for future changes — none.
- Ruling: the mock GitHub server binds only to loopback addresses — it is a test fixture, not a service — none.
