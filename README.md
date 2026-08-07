# Repository Assurance Snapshot

Generate a read-only evidence dossier for one public GitHub repository revision.

[Buy a human-reviewed A$49 public-repository snapshot](https://msharlincreations.gumroad.com/l/public-repository-assurance-snapshot)

[Open the buyer-facing assurance page](https://harlin-consulting-pty-ltd.github.io/repository-assurance-snapshot/)

**See the proof before you buy:** [open a real snapshot of this repository](samples/repository_assurance_live/ASSURANCE.md), with [machine-readable findings](samples/repository_assurance_live/assurance.json) and a [SHA-256 evidence manifest](samples/repository_assurance_live/evidence_manifest.json).

An original, bounded prototype that inspects a **public GitHub repository** or an explicitly declared local public-repository fixture and produces:

- `ASSURANCE.md` — a human-readable, source-cited snapshot;
- `assurance.json` — the same observations in a machine-readable schema;
- `evidence_manifest.json` — SHA-256 hashes for the dossier and observed evidence.

The prototype is permanently read-only. It uses unauthenticated GitHub public APIs, requests no private-repository or write access, does not execute repository code, and does not certify security, compliance, licensing or release fitness.

## What the snapshot answers

In one bounded dossier, it records what was actually observed at one repository revision, including:

- whether workflow action references are pinned to immutable commit SHAs;
- whether workflows declare permissions;
- whether licence, security-policy, SBOM, test-result and release-provenance evidence is present;
- whether checked local Markdown links resolve; and
- which important questions were **not observed**, **not tested** or **cannot be certified**.

That last distinction is deliberate: the report separates evidence from assumptions instead of turning missing access into a reassuring score.

## Install and run

```bash
python -m pip install .
repository-assurance-snapshot owner/repository --output snapshot
```

Full GitHub URLs such as `https://github.com/owner/repository` are also accepted.
No token is read from the environment or sent in requests.

## Use as a GitHub Action

```yaml
- name: Build repository assurance snapshot
  uses: HarLin-Consulting-Pty-Ltd/repository-assurance-snapshot@v0.1.0
  with:
    repository: ${{ github.repository }}
    output: repository-assurance

- name: Upload evidence dossier
  uses: actions/upload-artifact@v4
  with:
    name: repository-assurance
    path: repository-assurance/
```

The action observes the public repository through unauthenticated public APIs. It
does not inspect private settings or execute repository code.

### Self-dogfood proof

The repository's [`self-assurance.yml`](.github/workflows/self-assurance.yml)
workflow is configured to run the local Action against this repository's public GitHub URL,
verifies the dossier hashes and non-certification boundary, and uploads the
three-file dossier as a 14-day Actions artifact. The job grants only
`contents: read`; checkout does not persist credentials; and the collector step
explicitly receives blank `GITHUB_TOKEN` and `GH_TOKEN` values. Checkout and
artifact upload still use GitHub's separate managed runner mechanisms—this is a
proof that the **collector's public API requests** need no credential, not a
claim that the entire Actions runner is token-free.

## Human-reviewed snapshot

The free CLI and Action are for self-service evidence collection. The paid
snapshot adds a bounded human review of the generated dossier and delivery of
the hashed evidence package within two business days after a valid public
repository URL and matching order number are received. It is not an audit,
certification, penetration test, legal licence opinion or security warranty.

[Order the A$49 human-reviewed public-repository snapshot](https://msharlincreations.gumroad.com/l/public-repository-assurance-snapshot)

## Tests

```bash
python -m unittest discover -s tests -v
```

## Safety boundary

- Public metadata and selected small text evidence only.
- No clone, checkout, dependency installation or code execution.
- No secrets, tokens, private repositories, comments, commits or repository writes.
- Remote fetches are bounded by file count and file size.
- Every report includes `not_observed`, `not_tested` and `cannot_certify` limitations.
