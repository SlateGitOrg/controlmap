# Design decisions

Key design decisions in controlmap, each with the reasoning and what it would cost if it turned out wrong. Format: `- <what> — <why> — <cost if wrong>`.

## Process

- the core model, collectors, rules, library and engine are built incrementally on one coherent, typed, lint-clean codebase rather than rewritten — a rewrite would discard ~3k reviewed lines — if the design had hidden flaws they carry forward; mitigated by the full test suite, which surfaced and fixed three real bugs (TSC labels with commas parsed as YAML flow keys, lenient base64 decoding, mock fixture validation).
- Python 3.12 with uv, runtime deps limited to PyYAML, Jinja2 and cryptography — all mature, pinned in `uv.lock`; stdlib covers HTTP, CSV, tar and hashing — a larger ecosystem (pydantic, httpx) would shorten some code but add surface area to review.

## Scope and honesty

- collectors read exports, snapshots or a mock API; no live AWS/Okta/HRIS/MDM calls — tests must not touch the network, and evidence pipelines in practice consume exports produced by trusted jobs — users must produce the input files themselves; documented in docs/COLLECTORS.md.
- the GitHub collector has a real API mode, but it is exercised only against the bundled offline mock (in-process and over a loopback socket) — proves the HTTP path end to end without touching third-party systems — live GitHub quirks (pagination is not needed for these endpoints, but rate limits and SSO-enforced tokens are) are untested.
- TSC catalog ships identifiers with short labels paraphrased for this project; the ISO catalog ships Annex A identifiers with control headings only — the criteria text (AICPA) and control statements (ISO) are copyrighted — labels are navigation aids, not authority; README and catalog headers say so.
- the sample library's framework mappings are presented as this project's judgement for a fictional company — there is no licence-free official mapping to reproduce — an auditor may map differently; the README disclaimer and library header state it.
- every package page carries the "supports an audit, does not replace one" disclaimer, and so do the CLI output and the README — the risk of a tool output being mistaken for an attestation is real — none.

## Evaluation semantics

- rules are pure functions; the engine owns freshness and exceptions — one implementation of the tricky semantics, uniform across rules and plugins — rules cannot express per-item freshness (e.g. per-device check-in age), which rules model explicitly as parameters instead.
- status precedence ERROR > NO_EVIDENCE(missing) > FAIL > NO_EVIDENCE(empty population) > STALE > EXCEPTED > PASS — a known deviation matters more than the age of its proof, and "tested nothing" must never read as PASS — some teams may prefer STALE to dominate; changing it is a one-line edit plus the decision-table tests.
- point-in-time selection uses the UTC calendar date of `collected_at` (≤ as_of) — dates are what auditors reason in, and it makes `--as-of` reproducible — evidence collected late on as_of in a western timezone counts for that UTC day.
- collection time is the config `collected_at`, then a source-embedded timestamp, then the clock; never file mtimes — mtimes change on copy/clone and are not evidence of when an export was taken — operators who forget to set it get "now", which can hide staleness; the sample config sets it explicitly.
- manual-document controls set `freshness_days: 400` and enforce cadence via the rule's `max_age_days` — the document's age (performed_on) is what matters, not when its descriptor was recorded — a stale descriptor of an old document is still caught by the rule.
- freshness is judged only over the records a rule relied on; rules may report that subset as `RuleOutcome.used`, and `manual.document_current` reports only the latest document — keeping past quarterly reviews next to the current one is normal practice and must not turn document-backed controls STALE — a third-party rule that reads a subset but does not report `used` still gets the old, stricter behaviour (all records count), which errs towards STALE, not towards PASS.
- each successful collector run writes a content-addressed run manifest; at evaluation the latest run per source (by run time, among runs whose newest record is on/before `as_of`) retires subjects it no longer reports, unless the record is newer than that run — a repository removed from the config or a deleted descriptor must stop being evaluated, while point-in-time evaluation stays reproducible — removing a failing repository from the config makes its finding disappear from later evaluations; this is visible in the config history and logged at INFO, but not yet listed in the package (roadmap). Stores without run manifests (written before this change) keep the old behaviour until the next collect.
- the run that applies at `as_of` is chosen by the newest `collected_at` among its records, not by when it ran — runs execute "now" while their evidence carries explicit timestamps (the sample config pins them), so wall-clock time cannot place a run in evaluation time — a run with no records uses its wall-clock time.
- attachments are re-hashed store → package and the verifier cross-checks each attachment against the digest in its evidence record (the expected digest is also in the file name) — the manifest only proves the package was not changed after it was built, not that the packaged bytes are the bytes the record hashed — none beyond one extra hash per attachment.
- "dormant" uses IdP last login, with a grace period for never-used new accounts; service accounts are included in dormancy and admin checks but excluded from MFA by default (parameter `include_service_accounts`) — matches common SOC 2 control wording — policies differ; all thresholds are parameters.
- Linux OS baselines compare the distribution version string (e.g. Ubuntu `24.04 >= 22.04`) — that is what MDM exports carry — kernel-based or other-distro baselines need a different parameterization.
- CODEOWNERS `dir/*` matches only direct children while `dir` / `dir/` match the subtree, and the last matching rule wins — this is GitHub's documented behaviour — edge cases GitHub handles differently (if any) would mis-report ownership; property tests cover the core semantics.

## Exceptions

- exceptions match by control, optional rule and fnmatch resource globs; expired or not-yet-approved entries never apply but are reported when they would have matched — makes risk acceptance explicit and auditable — glob patterns that are too broad could hide new deviations; the register's `unused` and matched-resources output make breadth visible.
- excepted findings stay in the package next to the approving exception id — an auditor must see both the deviation and its approval — none.

## Package

- integrity = SHA-256 manifest + `MANIFEST.sha256` (shasum format) + optional Ed25519 over manifest bytes — verifiable with standard tools and without controlmap; one signature covers everything — Ed25519 keys are not X.509-anchored; origin depends on out-of-band key distribution (documented; `--public-key` enforces it).
- the package includes only evidence referenced by results (the records each rule relied on: all selected records of the kinds it read, or the subset it reports in `RuleOutcome.used`), not the whole store — keeps packages minimal and self-consistent — historical records not used by any rule (e.g. superseded access reviews) are not shipped; the store remains the system of record.
- deterministic tar.gz (sorted members, zero mtimes/owners, fixed modes, gzip mtime 0) — two parties can rebuild and compare digests — archive top-level directory name is part of the bytes, so builds must use the same output name to compare archives (manifests compare regardless).
- verification reports all problems instead of stopping at the first — one run tells an auditor everything wrong — slightly more code paths; all tested.

## Engineering

- coverage gate at 90% branch coverage (measured 97.70%) — well above a conventional 80% bar, with headroom for future changes — none.
- the mock GitHub server binds only to loopback addresses — it is a test fixture, not a service — none.
