# Architecture

controlmap is a pipeline with four hand-offs. Each hand-off is a plain data structure, so
every stage can be tested on its own:

```
sources ──collect──▶ Evidence records ──store──▶ evidence store
library + register ──validate──▶ Library, ExceptionRegister
store + library + register + as_of ──evaluate──▶ EvaluationRun
EvaluationRun + store ──package──▶ package directory / tar.gz ──verify──▶ VerifyReport
```

## 1. Evidence model (`model.py`, `canonical.py`)

An `Evidence` record is one normalized observation about one subject:

| field | meaning |
|---|---|
| `kind` | schema of `data`, e.g. `idp.users`, `cloud.storage_buckets`, `manual.access_review` |
| `subject` | what was observed: `aws:<account>`, `owner/repo@branch`, `idp:<tenant>` |
| `source` | the configured collector instance name |
| `collected_at` | aware UTC timestamp of the observation |
| `data` | normalized JSON (dates are ISO strings, lists are sorted where order is meaningless) |
| `origin` | where the raw data came from (relative path or URL). It is **not hashed** |
| `attachments` | `(name, sha256, size)` of files referenced by the record |

`digest = SHA-256(canonical_json(identity))`. Here `identity` is every field except `origin`,
with attachments reduced to `(name, sha256)`. Canonical JSON means sorted keys, `(",", ":")`
separators, UTF-8, and no NaN. Data is normalized in `__post_init__`, so a record hashes the
same before and after a JSON round trip. `Evidence.from_dict` recomputes the digest and rejects
a record whose embedded digest disagrees.

## 2. Collectors (`collectors/`)

`Collector` is an ABC with three class attributes: `type_name`, `description` and
`allowed_keys`. Settings are parsed in `__init__` through `Settings`, which reports errors as
`<where>.<key>: <problem>`. That way a misconfigured collector fails before any collection
starts. `register_collector` is a class decorator. Third-party collectors load from the
`controlmap.collectors` entry-point group. A plugin that fails to import is logged and skipped,
so it cannot take down the built-ins.

API access goes through a `Transport` protocol with a single method, `get(url, headers) ->
HttpResponse`. Production uses `UrllibTransport`, which allows only `http(s)` and returns
non-2xx statuses instead of raising. Tests and the demo use `MockGitHubTransport`, or a real
loopback server from `mockapi.serve`, so API mode runs offline.

The collection timestamp is resolved in this order: the `collected_at` config setting, then a
timestamp embedded in the source (`captured_at` in the AWS snapshot, `recorded_at` in a document
descriptor), then the clock. File modification times are never used.

CODEOWNERS matching (`codeowners.py`) compiles each gitignore-style pattern into one anchored
regex. `*` and `?` stay within a path segment, `**/` matches zero or more directories, and a
pattern containing `/` is anchored to the root. `dir/` and `dir` match the whole subtree, while
`dir/*` matches only direct children. Ownership is resolved last-match-wins. Matching one path
costs O(R·L) in the worst case for R rules and path length L. Regex compilation is cached per
rule.

## 3. Store (`store.py`)

```
<store>/objects/<aa>/<digest>.json      canonical JSON, one record per file
<store>/attachments/<aa>/<sha256>        raw attachment bytes
```

`put` is idempotent and writes atomically (temp file plus rename). Attachments are re-hashed
before they are copied, so a file that changed between collection and storage is rejected.
Loading a record re-derives its digest and checks it against the file name.

## 4. Library and rules (`library.py`, `rules/`, `frameworks.py`)

The library loader validates:

- control ids are unique and match `XX-NN`;
- every TSC id exists in the bundled catalog and every Annex A id (accepted as `8.5`, `A.8.5`
  or `A8.5`) exists among the 93 ISO/IEC 27001:2022 controls;
- every rule exists, unknown parameters are rejected, and parameter types are checked (a boolean
  is never accepted as an int). Defaults are filled in;
- freshness windows are at least 1 day, and resolve per rule → per control → library default.

A rule is a pure function `RuleContext -> RuleOutcome(checked, findings, notes)`. Its
`requires` is either a tuple of evidence kinds or a function of its parameters. For example,
`manual.document_current` requires `manual.<doc_kind>`.

## 5. Engine (`engine.py`)

**Evidence selection.** For an evaluation date `as_of`, the engine keeps, for each
`(kind, subject)`, the newest record whose `collected_at` UTC date is on or before `as_of`.
Ties are broken by digest, so the choice is deterministic. One pass over the records costs
O(N), plus O(K log K) to sort the K selected records.

**Rule status decision table** (first match wins):

| condition | status |
|---|---|
| the rule raised (`RuleError`, `KeyError`, `TypeError`, `ValueError`, `AttributeError`) | `ERROR` |
| a required evidence kind has no record | `NO_EVIDENCE` |
| at least one finding not covered by an active exception | `FAIL` |
| the rule tested zero items | `NO_EVIDENCE` |
| some evidence used is older than the freshness window | `STALE` |
| findings exist and all are excepted | `EXCEPTED` |
| otherwise | `PASS` |

**Roll-up.** A control takes the worst of its rule statuses, ranked
`PASS < EXCEPTED < STALE < NO_EVIDENCE < FAIL < ERROR`. Crosswalk rows roll up the same way
over their controls.

**Complexity.** For C controls with B rule bindings, selection is O(N). Each rule binding is
linear in the items of the evidence kinds it reads, and exception matching costs O(F·X·P) for F
findings, X exceptions and P resource patterns. The cross-source rules (leavers, inventory
reconciliation) build dictionaries keyed by e-mail, so they are O(users + employees + devices)
rather than quadratic. Benchmarks with `make bench` show linear growth from 100 to 10,000
employees.

A property test (`tests/test_engine.py::test_results_do_not_depend_on_record_order`) checks
that the evaluation output does not depend on the order of stored records.

## 6. Exceptions (`exceptions.py`)

An exception's state on a date is `pending` before `approved_on`, `active` up to and including
`expires_on`, and `expired` after that. During one evaluation an `ExceptionTracker`:

- marks a finding as excepted by the first *active* entry whose control, optional rule and
  `fnmatch` resource pattern match it;
- remembers inactive entries that would have matched. Their ids appear in the control's notes,
  and the register flags them `expired-but-matched` or `pending-but-matched`;
- produces a report with `expiring-soon` (30 days or fewer left), `unused` (active but matched
  nothing) and `exceeds-max-duration` flags.

## 7. Crosswalk (`crosswalk.py`)

For each in-scope TSC criterion, the crosswalk collects the controls that map to it and the
union of their Annex A ids. For each Annex A control it does the reverse. Building it costs
O((T + A)·C), where T is the number of criteria, A the number of Annex A controls and C the
number of controls (38 + 93 rows × 22 controls for Acme). Criteria with no control are reported
as gaps instead of being hidden.

## 8. Package (`package/`)

The builder assembles every file in memory (rendered pages, `results.json`, `crosswalk.*`,
`exceptions.*`, the library source, and the evidence records referenced by any result). It
writes them into a sibling staging directory and renames that into place, so a failed build
leaves nothing behind. Then:

1. `manifest.json` lists `{path, sha256, size}` for every file, sorted by path, plus the
   company, `as_of`, `generated_at`, the status summary and the tool version;
2. `MANIFEST.sha256` holds the same digests plus the manifest's own, in `shasum -c` format;
3. if a key is given, `signature.json` holds an Ed25519 signature over the exact bytes of
   `manifest.json` and the raw public key with its SHA-256 fingerprint;
4. optionally, a `.tar.gz` with sorted members, zero mtimes, uid/gid 0 and fixed modes, so the
   archive bytes depend only on the file names and contents.

**Verification** (`verify.py`) needs only the package. It does not need the store, the library
or controlmap's configuration:

1. the manifest parses and every path is relative, has no `..`, and is not reserved;
2. each listed file exists, is not a symlink, and has the recorded size and SHA-256;
3. no unlisted file or symlink is present;
4. `MANIFEST.sha256` equals the manifest's digests plus the manifest's own digest;
5. each `evidence/<digest>.json` parses as an `Evidence` whose recomputed digest equals its name;
6. every evidence digest referenced in `results.json` is in the package, and the manifest summary
   equals the results' counts;
7. the signature verifies, and if `--public-key` is given, the signer is that key.

Archives are extracted with the `data` filter after an explicit pre-check that rejects links,
devices, absolute paths, `..`, and archives with more than one root. Verification is O(total
bytes) for hashing plus O(files) for bookkeeping.

## 9. Determinism

Given the same evidence, library, register, `as_of`, `generated_at` and signing key, the package
directory and the archive are byte-for-byte identical. `generated_at` defaults to the current
time but honours `SOURCE_DATE_EPOCH`. Ed25519 signatures are deterministic by construction.

## 10. Extension points

| Extend | How |
|---|---|
| New source | Subclass `Collector`, set `type_name`/`allowed_keys`, decorate with `@register_collector`, expose through the `controlmap.collectors` entry point |
| New rule | Decorate a function with `@rule(name, description=..., requires=..., params=[Param(...)])` in a module listed under the `controlmap.rules` entry point |
| New framework mapping | Edit the library YAML. Catalog validation catches typos |
