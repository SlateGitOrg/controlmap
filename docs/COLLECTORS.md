# Collectors and input formats

Every collector entry in `controlmap.yaml` takes `name` (unique), `type`, and an optional
`collected_at` (ISO date or timestamp) that overrides the observation time. Relative paths
resolve against the directory that holds `controlmap.yaml`. String values may use
`${VAR}` or `${VAR:-default}`. Unknown keys are rejected.

## `github` — branch protection and CODEOWNERS

Evidence: `github.branch_protection` (subject `owner/repo@branch`) and `github.codeowners`
(subject `owner/repo`).

**File mode** saves the REST responses you already trust:

```bash
gh api repos/acme/api/branches/main/protection > api.main.protection.json
# a 404 "Branch not protected" answer is recorded as `protection: null`
gh api repos/acme/api/contents/.github/CODEOWNERS --jq .content | base64 -d > api.CODEOWNERS
```

```yaml
- name: github
  type: github
  collected_at: 2026-09-30T09:00:00Z
  repos:
    - {repo: acme/api, branch: main, protection: data/github/api.main.protection.json, codeowners: data/github/api.CODEOWNERS}
    - {repo: acme/old, branch: main, protection: null}      # unprotected, no CODEOWNERS
```

**API mode** reads the repo's default branch (unless `branch` is given), then
`/branches/{b}/protection`, then `.github/CODEOWNERS`, `CODEOWNERS` and `docs/CODEOWNERS`
in that order:

```yaml
- name: github
  type: github
  api: {base_url: "${GITHUB_API_URL:-https://api.github.com}", token_env: GITHUB_TOKEN}
  repos: [{repo: acme/api}, {repo: acme/web, branch: release}]
```

Reading branch protection needs a token that can read repository administration. HTTP 401 or
403 produces a clear collector error. This mode is tested only against the bundled offline mock
(`controlmap mock-github --fixture examples/acme/data/mock-github.yaml`).

Normalized protection fields: `protected`, `pull_request_required`, `required_approvals`,
`dismiss_stale_reviews`, `require_code_owner_reviews`, `enforce_admins`,
`required_status_checks` (sorted contexts), `strict_status_checks`, `allow_force_pushes`,
`allow_deletions`, `required_linear_history`, `required_signatures`.

## `aws_snapshot` — cloud configuration snapshot

Evidence: one record per section, with subject `aws:<account_id>`. A section missing from the
snapshot yields no record, so dependent rules report `NO_EVIDENCE`. It is never read as
"empty, therefore compliant".

The snapshot is one JSON file bundling the raw output of read-only AWS CLI calls:

```json
{
  "format": "controlmap-aws-snapshot/1",
  "account_id": "111122223333",
  "captured_at": "2026-09-28T02:00:00Z",
  "iam":        {"account_summary": <aws iam get-account-summary>,
                 "password_policy": <aws iam get-account-password-policy> | null},
  "s3":         {"buckets": [{"Name": "...",
                              "encryption": <aws s3api get-bucket-encryption> | null,
                              "public_access_block": <aws s3api get-public-access-block> | null}]},
  "cloudtrail": {"describe_trails": <aws cloudtrail describe-trails>,
                 "trail_status": {"<trail name or ARN>": <aws cloudtrail get-trail-status>}},
  "kms":        {"keys": [{"alias": "alias/x", "KeyMetadata": <describe-key .KeyMetadata>,
                           "rotation": <aws kms get-key-rotation-status> | null}]},
  "ec2":        {"describe_security_groups": <aws ec2 describe-security-groups>},
  "rds":        {"describe_db_instances": <aws rds describe-db-instances>}
}
```

| section | evidence kind | rules |
|---|---|---|
| `iam` | `cloud.iam_account` | `cloud.root_account_protected`, `cloud.password_policy` |
| `s3` | `cloud.storage_buckets` | `cloud.storage_encrypted`, `cloud.storage_public_access_blocked` |
| `cloudtrail` | `cloud.audit_trails` | `cloud.audit_logging` |
| `kms` | `cloud.kms_keys` | `cloud.kms_rotation` |
| `ec2` | `cloud.security_groups` | `cloud.admin_ports_restricted` |
| `rds` | `cloud.databases` | `cloud.database_hardening` |

controlmap never calls AWS itself. The snapshot is produced by a process the company already
trusts, for example a scheduled job with a read-only role.

## `idp_csv` — identity-provider user export

Evidence: `idp.users` (subject `idp:<tenant>`). Keys: `path`, `tenant`, `preset`
(`generic` | `okta`), `columns` (overrides per field), `admin_groups`.

| field | generic header | okta preset header | notes |
|---|---|---|---|
| id | `id` | `Okta ID` | required |
| email | `email` | `Username` | required, lower-cased, unique |
| status | `status` | `Status` | required. Mapped to `active` / `pending` / `suspended` / `deprovisioned` |
| mfa_factors | `mfa_factors` | `MFA Factors` | required. Split on `;` or `\|`. `None` or `-` means no factor |
| last_login | `last_login` | `Last Login` | date or timestamp |
| created | `created` | `Created` | |
| groups | `groups` | `Groups` | split on `;` or `\|`. `is_admin` is true if any group is in `admin_groups` |
| type | `type` | `User Type` | `human` (default) or `service` |

## `hris_csv` — HR roster

Evidence: `hris.roster` (subject `hris:<name>`). Headers: `employee_id`, `email`, `status`
(`active` / `leave` / `terminated`), `start_date`, `termination_date` (required when
terminated, and not before the start), `department`, `manager_email`, `training_completed_on`.

## `endpoint_csv` — MDM/EDR inventory

Evidence: `endpoint.inventory` (subject `mdm:<name>`). Headers: `device_id`, `hostname`,
`serial`, `owner_email`, `platform` (`macOS` / `Windows` / `Linux`), `os_version`,
`disk_encrypted` (yes/no/true/false/encrypted…), `edr_agent`, `edr_last_seen`,
`screen_lock_minutes`, `last_checkin`.

## `manual_documents` — procedural evidence

Evidence: `manual.<kind>`. The subject is the descriptor's `id`, or else its file stem. Every
`*.yaml`/`*.yml` file directly inside `path` is one descriptor:

```yaml
kind: access_review            # [a-z][a-z0-9_]*
title: Q3 2026 production access review
performed_on: 2026-07-15       # what rules measure age from
approved_by: VP Engineering    # a role, not a person
approved_on: 2026-07-18        # must not be before performed_on
summary: 41 accounts reviewed; 3 revoked.
attachments: [files/access-review-2026-q3.csv]   # inside the directory; hashed and packaged
recorded_at: 2026-07-18T15:30:00Z               # observation time (else collected_at / clock)
```

Rule `manual.document_current` (params `doc_kind`, `max_age_days`, `require_approval`) checks
the most recent document of a kind performed on or before the evaluation date.

## Writing a collector plugin

```python
from typing import ClassVar
from controlmap.collectors import Collector, register_collector

@register_collector
class VendorListCollector(Collector):
    type_name: ClassVar[str] = "vendor_csv"
    description: ClassVar[str] = "Vendor register export"
    allowed_keys: ClassVar[frozenset[str]] = frozenset({"path"})

    def collect(self):
        rows = ...  # parse self.settings.path("path")
        return [self.evidence("vendors.register", "vendors", {"vendors": rows},
                              self.relpath(self.settings.path("path")), self.collected_at())]
```

Expose it in your package's `pyproject.toml`:

```toml
[project.entry-points."controlmap.collectors"]
vendor_csv = "mypkg.vendors:VendorListCollector"
```
