# Threat model

controlmap is a defensive compliance tool. Its security claims are narrow: **after evidence
is collected, nobody can change it, or the results and pages derived from it, without
detection**. If the package is signed, a verifier can also check **who** produced it. This
document states what that does and does not cover.

## Assets

1. Evidence records and attachments: the observations controls are judged on.
2. Evaluation results and the auditor-facing pages: what people actually read.
3. The signing key, if one is used.
4. API tokens (GitHub API mode only).

## In scope

| Threat | Mitigation | Test |
|---|---|---|
| Someone edits a page or result after the package is built (for example flips FAIL to PASS) | SHA-256 per file in `manifest.json` and `MANIFEST.sha256` | `test_modified_file_is_detected`, demo step |
| Files are removed from, or added to, a package | Missing and unlisted file checks, symlink rejection | `test_deleted_and_added_files_are_detected`, `test_symlinks_are_rejected` |
| An attacker rewrites a file *and* consistently rewrites the manifest and checksum list | The Ed25519 signature over `manifest.json` no longer verifies | `test_rewriting_manifest_breaks_the_signature` |
| The same, on an unsigned package, for evidence records | Each record is named by its own content digest, and the verifier recomputes it | `test_unsigned_consistent_rewrite_of_evidence_is_still_caught` |
| Results point at evidence that is not in the package | Reference check from results to evidence | `test_results_must_reference_packaged_evidence` |
| A package is re-signed with the attacker's own key | `--public-key` pins the expected signer, and the fingerprint is printed | `test_signed_package_with_trusted_key` |
| A malicious archive (path traversal, symlinks, devices, multiple roots) | Explicit member pre-check, then `tarfile` `data` filter | `test_archive_extraction_refuses_unsafe_members` |
| A tampered evidence store on disk | Records are re-hashed on every load. Attachments are re-hashed before they are copied | `test_store.py` |
| HTML or script injection through evidence values (resource names, titles) | Jinja2 autoescaping for `.html` templates. Markdown cells escape `\|` | `test_html_is_escaped` |
| YAML deserialization attacks | `yaml.safe_load` only | n/a (by construction) |
| Token leakage and SSRF in API mode | The token comes from a named environment variable and is sent only to the configured `base_url`. Only `http(s)` URLs are allowed | `test_urllib_transport_rejects_other_schemes_and_reports_connection_errors` |
| The mock API exposed on a network | The mock server refuses any bind address other than loopback | `test_server_refuses_non_loopback_binding` |

## Out of scope (stated limits)

- **Lying or incomplete sources.** If an export is wrong, controlmap faithfully hashes a wrong
  export. Integrity is not truth.
- **A malicious operator with the signing key.** They can collect fabricated evidence and sign
  it. A signature identifies the signer. It does not vouch for the content.
- **Backdating.** `collected_at` and `generated_at` are self-asserted. There is no trusted
  timestamp authority (RFC 3161 is on the roadmap).
- **Key management.** `keygen` writes an unencrypted PKCS#8 key with mode 0600. Storing it in a
  KMS or HSM, rotating it, and distributing the public key out of band are the operator's
  responsibility.
- **Confidentiality of the package.** Packages contain e-mail addresses, device ids and
  configuration details. Encrypting or access-controlling them in transit and at rest is outside
  this tool.
- **Concurrent writers to the store.** Writes are atomic, but there is no locking.

## Data handling

The bundled fixtures are entirely synthetic (`*.example` domains, fake serials, AWS documentation
account id `111122223333`). Exception and document descriptors use roles ("CISO",
"VP Engineering") rather than names, and the sample library follows the same convention.
