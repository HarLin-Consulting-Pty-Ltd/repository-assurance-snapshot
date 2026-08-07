# Repository Assurance Snapshot

> **Informational, bounded and read-only. This is not a security, compliance, legal or release certification.**

- **Source:** `https://github.com/HarLin-Consulting-Pty-Ltd/repository-assurance-snapshot`
- **Revision:** `c324ad4fd26a976aa086d648fd126a30aa14a4d8`
- **Observed at:** `2026-08-07T23:30:31+00:00`
- **Collector:** `repository-assurance-snapshot 0.1.2`

## Summary

| Status | Count |
|---|---:|
| pass | 3 |
| warn | 1 |
| info | 5 |
| not_observed | 2 |

## Findings

### PUBLIC_READ_ONLY_SOURCE — pass

**Public, read-only source boundary**

GitHub reported the repository public and the collector used no token.

Sources:
- `https://github.com/HarLin-Consulting-Pty-Ltd/repository-assurance-snapshot`

Limitation: A local fixture declaration does not prove that an equivalent remote repository is public.

### WORKFLOW_IMMUTABLE_REFS — pass

**Immutable workflow action references**

All 3 observed action reference(s) were pinned to full commit SHAs.

Sources:
- `.github/workflows/self-assurance.yml`

Limitation: Pinning reduces tag-mutation risk but does not prove an action or workflow safe.

### WORKFLOW_PERMISSIONS — pass

**Explicit workflow permissions**

A permissions declaration was observed in all 1 workflow file(s).

Sources:
- `.github/workflows/self-assurance.yml`

Limitation: Presence is not a semantic least-privilege proof; nested YAML and effective GitHub defaults were not evaluated.

### SBOM_EVIDENCE — info

**Software-bill-of-materials evidence**

Observed 1 path(s) that appear to contain SBOM evidence.

Sources:
- `fixtures/public_demo_repo/sbom.spdx.json`

Limitation: File naming/presence does not prove completeness, freshness or accuracy.

### TEST_EVIDENCE — info

**Test-result evidence**

Observed 1 test-result path(s).

Sources:
- `fixtures/public_demo_repo/test-results/junit.xml`

Limitation: Tests were not executed; result authenticity, coverage and revision association were not verified.

### LICENSE_DECLARATION — info

**Licence declaration**

Observed licence evidence: files=2, GitHub SPDX=MIT.

Sources:
- `LICENSE`
- `fixtures/public_demo_repo/LICENSE`
- `https://github.com/HarLin-Consulting-Pty-Ltd/repository-assurance-snapshot`

Limitation: No legal interpretation, dependency-licence compatibility assessment or ownership opinion was performed.

### RELEASE_PROVENANCE_EVIDENCE — info

**Release provenance or attestation evidence**

Observed 1 provenance/attestation path(s).

Sources:
- `fixtures/public_demo_repo/release/provenance.json`

Limitation: Presence was observed; signatures, issuer identity and subject-artifact binding were not cryptographically verified.

### SECURITY_POLICY — not_observed

**Security policy**

No root or .github SECURITY.md was observed.

Limitation: Policy presence does not prove response performance or vulnerability handling.

### DOCUMENT_LOCAL_LINKS — warn

**Documentation local-link integrity**

Checked 5 relative Markdown link(s); 1 unresolved target(s).

Sources:
- `PUBLISHING.md`
- `README.md`
- `fixtures/public_demo_repo/.github/SECURITY.md`
- `fixtures/public_demo_repo/README.md`
- `fixtures/public_demo_repo/docs/assurance.md`
- `samples/public_demo/ASSURANCE.md`
- `samples/repository_assurance_live/ASSURANCE.md`

Limitation: External URL availability, anchors, rendered-site routing and non-Markdown documentation were not tested.

### DEFAULT_BRANCH_PROTECTION — not_observed

**Default-branch protection**

Protection settings were not observable in the bounded public/read-only collection.

Sources:
- `https://github.com/HarLin-Consulting-Pty-Ltd/repository-assurance-snapshot`

### CONTRIBUTOR_CONCENTRATION — info

**Contributor concentration**

Public API returned 1 contributor record(s); the largest observed share was 100.0%.

Sources:
- `https://github.com/HarLin-Consulting-Pty-Ltd/repository-assurance-snapshot`

Limitation: The API page is capped, bot/anonymous identity may distort results, and concentration is not a continuity verdict.

## Limitations

### not_observed

- Default-branch protection was not observable without privileged repository access.
- Secrets, private branches, private issues, organisation rulesets and non-public repository settings were outside the public/no-token boundary.

### not_tested

- Repository code, builds, tests, dependencies and workflows were not executed.
- External links, runtime behaviour, exploitability, code quality and production deployment were not tested.
- Cryptographic attestation validity and artifact-to-source reproducibility were not verified.
- Legal licence compatibility, copyright ownership and regulatory compliance were not assessed.

### cannot_certify

- This snapshot cannot certify security, compliance, accessibility, legal fitness, release integrity or operational readiness.
- Observed evidence may be incomplete, stale, misleading or unrelated to the deployed product.
- A pass means only that the stated bounded observation was made; it is not an assurance opinion or warranty.

## Interpretation rule

Only the precise observations above are supported. Absence of a warning is not evidence of safety. The accompanying `evidence_manifest.json` hashes the dossier and observed evidence sources but does not make those sources true or complete.
