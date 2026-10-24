# Data

## Bundled framework catalogs (`src/controlmap/data/`)

| File | Content | Source | Licence / notes |
|---|---|---|---|
| `tsc2017.yaml` | 61 SOC 2 Trust Services Criteria identifiers (2017 TSC; CC1–CC9, A1, C1, PI1, P1–P8) with category and a short topic label | Identifiers from the AICPA 2017 Trust Services Criteria (revised points of focus 2022); **labels paraphrased by this project** | Identifiers are factual references. The criteria text is AICPA copyright and is not reproduced. |
| `iso27001_2022.yaml` | 93 ISO/IEC 27001:2022 Annex A control identifiers, themes and control headings | ISO/IEC 27001:2022 Annex A structure (5.1–5.37, 6.1–6.8, 7.1–7.14, 8.1–8.34) | Headings only. The control statements are ISO copyright and are not reproduced. |

Both catalogs are written by hand and validated at load time: ids must match the expected
patterns, and entries must have exactly the expected keys. `tests/test_library.py` asserts the
totals (93 Annex A controls, 37 organizational, 33 common criteria).

## Sample company (`examples/acme/`)

**All synthetic, written for this repository, released under the repository's MIT licence.**

| Path | What |
|---|---|
| `data/github/*.protection.json`, `*.CODEOWNERS` | Shaped like `gh api .../branches/main/protection` responses and CODEOWNERS files |
| `data/aws/prod-snapshot-2026-09-28.json` | Snapshot shaped like AWS CLI output. Account id `111122223333` is the AWS documentation example account |
| `data/idp/okta-users-2026-09-30.csv` | Okta-style user report with 11 fictional users at `acme.example` |
| `data/hris/roster-2026-09-30.csv` | HR roster with 9 fictional employees |
| `data/endpoints/mdm-inventory-2026-09-20.csv` | 7 fictional laptops with fake serial numbers |
| `data/documents/` | Procedural evidence descriptors plus two small attachments |
| `data/mock-github.yaml` | Fixture for the offline mock GitHub API (the token is a placeholder, not a secret) |
| `expected.yaml` | The documented expected status of every control |

No real people, companies, accounts or credentials appear in the data. The `.example`
domain is reserved for documentation (RFC 2606).

## Benchmark data

`scripts/bench.py` generates seeded synthetic companies (100 to 10,000 employees) in a
temporary directory at run time and deletes them afterwards. Nothing is downloaded.
