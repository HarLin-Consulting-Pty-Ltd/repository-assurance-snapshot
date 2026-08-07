from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

SCHEMA = "harlin.repository_assurance_snapshot/v0.1"
USER_AGENT = f"HarLin-Repository-Assurance-Snapshot/{__version__} (public-read-only)"
MAX_REMOTE_TEXT_FILES = 30
MAX_REMOTE_FILE_BYTES = 512_000
MAX_LOCAL_FILE_BYTES = 5_000_000


class SnapshotError(RuntimeError):
    pass


@dataclass
class Evidence:
    source_ref: str
    kind: str
    sha256: str
    size_bytes: int


@dataclass
class Observation:
    source_kind: str
    canonical_ref: str
    revision: str
    default_branch: str | None
    metadata: dict[str, Any]
    paths: list[str]
    text_files: dict[str, str]
    evidence: list[Evidence] = field(default_factory=list)
    branch_protection: dict[str, Any] | None = None
    contributors: list[dict[str, Any]] | None = None
    collection_gaps: list[str] = field(default_factory=list)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _get_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read(MAX_REMOTE_FILE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise SnapshotError(f"public GitHub request failed ({exc.code}) for {url}") from exc
    except urllib.error.URLError as exc:
        raise SnapshotError(f"public GitHub request failed for {url}: {exc.reason}") from exc


def _get_json(url: str) -> tuple[Any, bytes]:
    raw = _get_bytes(url)
    if len(raw) > MAX_REMOTE_FILE_BYTES:
        raise SnapshotError(f"public GitHub response exceeded {MAX_REMOTE_FILE_BYTES} bytes: {url}")
    try:
        return json.loads(raw.decode("utf-8")), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"invalid public GitHub JSON response: {url}") from exc


def _parse_github_ref(source: str) -> tuple[str, str] | None:
    value = source.strip()
    if value.startswith("https://github.com/"):
        parsed = urllib.parse.urlparse(value)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]
    elif re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        owner, repo = value.split("/", 1)
    else:
        return None
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def _is_text_candidate(path: str) -> bool:
    lower = path.lower()
    name = Path(lower).name
    return (
        lower.startswith(".github/workflows/")
        or name in {"readme.md", "security.md", "license", "license.md", "copying"}
        or "sbom" in lower
        or "spdx" in lower
        or "cyclonedx" in lower
        or "test-result" in lower
        or "junit" in lower
        or lower.endswith(".trx")
        or "attestation" in lower
        or "provenance" in lower
        or lower.endswith(".md")
    )


def _collect_remote(source: str) -> Observation:
    parsed = _parse_github_ref(source)
    if not parsed:
        raise SnapshotError("source is neither an existing local path nor a valid public GitHub reference")
    owner, repo = parsed
    api = f"https://api.github.com/repos/{owner}/{repo}"
    metadata, metadata_raw = _get_json(api)
    if metadata.get("private") is not False:
        raise SnapshotError("only repositories explicitly reported public by GitHub are accepted")

    branch = metadata.get("default_branch")
    if not branch:
        raise SnapshotError("public repository has no default branch")

    commit_url = f"{api}/commits/{urllib.parse.quote(branch, safe='')}"
    commit, commit_raw = _get_json(commit_url)
    revision = str(commit.get("sha") or "not-observed")

    tree_url = f"{api}/git/trees/{urllib.parse.quote(revision, safe='')}?recursive=1"
    tree, tree_raw = _get_json(tree_url)
    if tree.get("truncated"):
        raise SnapshotError("public repository tree was truncated; refusing an incomplete snapshot")
    blobs = [item for item in tree.get("tree", []) if item.get("type") == "blob"]
    paths = sorted(str(item.get("path")) for item in blobs if item.get("path"))

    evidence = [
        Evidence(api, "github_repository_metadata", _sha(metadata_raw), len(metadata_raw)),
        Evidence(commit_url, "github_commit_metadata", _sha(commit_raw), len(commit_raw)),
        Evidence(tree_url, "github_tree_metadata", _sha(tree_raw), len(tree_raw)),
    ]
    text_files: dict[str, str] = {}
    selected = [item for item in blobs if _is_text_candidate(str(item.get("path", "")))]
    selected = sorted(selected, key=lambda item: str(item.get("path")))[:MAX_REMOTE_TEXT_FILES]
    for item in selected:
        path = str(item["path"])
        size = int(item.get("size") or 0)
        if size > MAX_REMOTE_FILE_BYTES:
            continue
        encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{urllib.parse.quote(revision, safe='')}/{encoded_path}"
        try:
            raw = _get_bytes(raw_url)
        except SnapshotError:
            continue
        if len(raw) > MAX_REMOTE_FILE_BYTES:
            continue
        try:
            text_files[path] = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        evidence.append(Evidence(raw_url, "observed_repository_file", _sha(raw), len(raw)))

    contributors: list[dict[str, Any]] | None = None
    gaps: list[str] = []
    contributors_url = f"{api}/contributors?per_page=100&anon=1"
    try:
        value, raw = _get_json(contributors_url)
        if isinstance(value, list):
            contributors = value
            evidence.append(Evidence(contributors_url, "github_contributor_metadata", _sha(raw), len(raw)))
    except SnapshotError:
        gaps.append("Contributor concentration was not observed from the public API.")

    protection: dict[str, Any] | None = None
    protection_url = f"{api}/branches/{urllib.parse.quote(branch, safe='')}/protection"
    try:
        value, raw = _get_json(protection_url)
        if isinstance(value, dict):
            protection = value
            evidence.append(Evidence(protection_url, "github_branch_protection_metadata", _sha(raw), len(raw)))
    except SnapshotError:
        gaps.append("Default-branch protection was not observable without privileged repository access.")

    return Observation(
        source_kind="public_github",
        canonical_ref=f"https://github.com/{owner}/{repo}",
        revision=revision,
        default_branch=branch,
        metadata=metadata,
        paths=paths,
        text_files=text_files,
        evidence=evidence,
        branch_protection=protection,
        contributors=contributors,
        collection_gaps=gaps,
    )


def _collect_local(path: Path, output_dir: Path) -> Observation:
    root = path.resolve()
    output_resolved = output_dir.resolve()
    files: list[Path] = []
    for candidate in root.rglob("*"):
        if not candidate.is_file() or ".git" in candidate.parts:
            continue
        resolved = candidate.resolve()
        if resolved == output_resolved or output_resolved in resolved.parents:
            continue
        files.append(candidate)
    files.sort(key=lambda item: item.relative_to(root).as_posix())

    paths: list[str] = []
    text_files: dict[str, str] = {}
    evidence: list[Evidence] = []
    content_hashes: list[str] = []
    gaps: list[str] = []
    for candidate in files:
        rel = candidate.relative_to(root).as_posix()
        paths.append(rel)
        size = candidate.stat().st_size
        if size > MAX_LOCAL_FILE_BYTES:
            gaps.append(f"Local fixture file exceeded the evidence limit and was not read: {rel}")
            continue
        raw = candidate.read_bytes()
        digest = _sha(raw)
        content_hashes.append(f"{rel}\0{digest}")
        evidence.append(Evidence(rel, "local_public_fixture_file", digest, len(raw)))
        if _is_text_candidate(rel):
            try:
                text_files[rel] = raw.decode("utf-8")
            except UnicodeDecodeError:
                pass

    tree_digest = _sha("\n".join(content_hashes).encode("utf-8"))
    return Observation(
        source_kind="local_public_fixture",
        canonical_ref=str(root),
        revision=f"local-content-sha256:{tree_digest}",
        default_branch=None,
        metadata={
            "name": root.name,
            "private": False,
            "visibility_basis": "caller-declared local public fixture",
            "license": None,
        },
        paths=paths,
        text_files=text_files,
        evidence=evidence,
        collection_gaps=gaps,
    )


def _finding(code: str, status: str, title: str, evidence: str, source_refs: list[str], limitation: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "code": code,
        "status": status,
        "title": title,
        "evidence": evidence,
        "source_refs": source_refs,
    }
    if limitation:
        result["limitation"] = limitation
    return result


def _analyse(observation: Observation) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    paths_lower = {path.lower(): path for path in observation.paths}
    findings: list[dict[str, Any]] = []

    findings.append(
        _finding(
            "PUBLIC_READ_ONLY_SOURCE",
            "pass",
            "Public, read-only source boundary",
            (
                "GitHub reported the repository public and the collector used no token."
                if observation.source_kind == "public_github"
                else "The caller explicitly declared this local directory a public-repository fixture."
            ),
            [observation.canonical_ref],
            "A local fixture declaration does not prove that an equivalent remote repository is public.",
        )
    )

    workflow_paths = sorted(path for path in observation.paths if path.lower().startswith(".github/workflows/") and path.lower().endswith((".yml", ".yaml")))
    uses: list[tuple[str, str, str]] = []
    missing_permissions: list[str] = []
    for path in workflow_paths:
        text = observation.text_files.get(path, "")
        if not re.search(r"(?m)^\s*permissions\s*:", text):
            missing_permissions.append(path)
        for match in re.finditer(r"(?m)^\s*-?\s*uses\s*:\s*([^\s#]+)@([^\s#]+)", text):
            uses.append((path, match.group(1), match.group(2)))
    unpinned = [(path, action, ref) for path, action, ref in uses if not re.fullmatch(r"[0-9a-fA-F]{40}", ref)]
    if not workflow_paths:
        findings.append(_finding("WORKFLOW_IMMUTABLE_REFS", "not_observed", "Immutable workflow action references", "No GitHub workflow file was observed.", []))
        findings.append(_finding("WORKFLOW_PERMISSIONS", "not_observed", "Explicit workflow permissions", "No GitHub workflow file was observed.", []))
    else:
        findings.append(
            _finding(
                "WORKFLOW_IMMUTABLE_REFS",
                "warn" if unpinned else "pass",
                "Immutable workflow action references",
                (
                    f"Observed {len(unpinned)} of {len(uses)} action reference(s) not pinned to a full 40-character commit SHA."
                    if unpinned
                    else f"All {len(uses)} observed action reference(s) were pinned to full commit SHAs."
                ),
                sorted({item[0] for item in uses}),
                "Pinning reduces tag-mutation risk but does not prove an action or workflow safe.",
            )
        )
        findings.append(
            _finding(
                "WORKFLOW_PERMISSIONS",
                "warn" if missing_permissions else "pass",
                "Explicit workflow permissions",
                (
                    f"{len(missing_permissions)} of {len(workflow_paths)} workflow file(s) lacked a top-level or job-level permissions declaration detectable by this bounded parser."
                    if missing_permissions
                    else f"A permissions declaration was observed in all {len(workflow_paths)} workflow file(s)."
                ),
                workflow_paths,
                "Presence is not a semantic least-privilege proof; nested YAML and effective GitHub defaults were not evaluated.",
            )
        )

    sbom_paths = sorted(path for path in observation.paths if any(token in path.lower() for token in ("sbom", "spdx", "cyclonedx")))
    findings.append(
        _finding(
            "SBOM_EVIDENCE",
            "info" if sbom_paths else "not_observed",
            "Software-bill-of-materials evidence",
            f"Observed {len(sbom_paths)} path(s) that appear to contain SBOM evidence." if sbom_paths else "No SBOM-named path was observed.",
            sbom_paths,
            "File naming/presence does not prove completeness, freshness or accuracy.",
        )
    )

    test_paths = sorted(path for path in observation.paths if any(token in path.lower() for token in ("test-results", "junit", "pytest")) or path.lower().endswith(".trx"))
    findings.append(
        _finding(
            "TEST_EVIDENCE",
            "info" if test_paths else "not_observed",
            "Test-result evidence",
            f"Observed {len(test_paths)} test-result path(s)." if test_paths else "No persisted test-result path was observed.",
            test_paths,
            "Tests were not executed; result authenticity, coverage and revision association were not verified.",
        )
    )

    licence_paths = sorted(path for path in observation.paths if Path(path).name.lower() in {"license", "license.md", "copying"})
    api_licence = (observation.metadata.get("license") or {}).get("spdx_id") if isinstance(observation.metadata.get("license"), dict) else None
    findings.append(
        _finding(
            "LICENSE_DECLARATION",
            "info" if licence_paths or api_licence else "not_observed",
            "Licence declaration",
            f"Observed licence evidence: files={len(licence_paths)}, GitHub SPDX={api_licence or 'not observed'}.",
            licence_paths + ([observation.canonical_ref] if api_licence else []),
            "No legal interpretation, dependency-licence compatibility assessment or ownership opinion was performed.",
        )
    )

    provenance_paths = sorted(path for path in observation.paths if any(token in path.lower() for token in ("attestation", "provenance", "slsa")))
    findings.append(
        _finding(
            "RELEASE_PROVENANCE_EVIDENCE",
            "info" if provenance_paths else "not_observed",
            "Release provenance or attestation evidence",
            f"Observed {len(provenance_paths)} provenance/attestation path(s)." if provenance_paths else "No provenance/attestation-named path was observed.",
            provenance_paths,
            "Presence was observed; signatures, issuer identity and subject-artifact binding were not cryptographically verified.",
        )
    )

    security_paths = [paths_lower[key] for key in ("security.md", ".github/security.md") if key in paths_lower]
    findings.append(
        _finding(
            "SECURITY_POLICY",
            "pass" if security_paths else "not_observed",
            "Security policy",
            "A SECURITY.md policy was observed." if security_paths else "No root or .github SECURITY.md was observed.",
            security_paths,
            "Policy presence does not prove response performance or vulnerability handling.",
        )
    )

    markdown_paths = [path for path in observation.text_files if path.lower().endswith(".md")]
    broken_links: list[str] = []
    checked_links = 0
    path_set = set(observation.paths)
    for md_path in markdown_paths:
        base = Path(md_path).parent
        for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", observation.text_files[md_path]):
            target = match.group(1).strip().split("#", 1)[0]
            if not target or re.match(r"^(?:https?://|mailto:|#)", target):
                continue
            checked_links += 1
            candidate = (base / urllib.parse.unquote(target)).as_posix().lstrip("./")
            if candidate not in path_set:
                broken_links.append(f"{md_path} -> {target}")
    findings.append(
        _finding(
            "DOCUMENT_LOCAL_LINKS",
            "warn" if broken_links else ("pass" if markdown_paths else "not_observed"),
            "Documentation local-link integrity",
            f"Checked {checked_links} relative Markdown link(s); {len(broken_links)} unresolved target(s).",
            sorted(markdown_paths),
            "External URL availability, anchors, rendered-site routing and non-Markdown documentation were not tested.",
        )
    )

    if observation.branch_protection is None:
        findings.append(_finding("DEFAULT_BRANCH_PROTECTION", "not_observed", "Default-branch protection", "Protection settings were not observable in the bounded public/read-only collection.", [observation.canonical_ref]))
    else:
        findings.append(_finding("DEFAULT_BRANCH_PROTECTION", "info", "Default-branch protection", "GitHub returned a branch-protection configuration for the default branch.", [observation.canonical_ref], "Configuration presence was observed; organisational rulesets and effective bypasses were not fully evaluated."))

    if observation.contributors:
        contributions = [int(item.get("contributions") or 0) for item in observation.contributors]
        total = sum(contributions)
        top_share = (max(contributions) / total) if total else 0.0
        findings.append(_finding("CONTRIBUTOR_CONCENTRATION", "info", "Contributor concentration", f"Public API returned {len(contributions)} contributor record(s); the largest observed share was {top_share:.1%}.", [observation.canonical_ref], "The API page is capped, bot/anonymous identity may distort results, and concentration is not a continuity verdict."))
    else:
        findings.append(_finding("CONTRIBUTOR_CONCENTRATION", "not_observed", "Contributor concentration", "Contributor concentration was not observed.", [observation.canonical_ref]))

    limitations = {
        "not_observed": sorted(set(observation.collection_gaps + [
            "Secrets, private branches, private issues, organisation rulesets and non-public repository settings were outside the public/no-token boundary.",
        ])),
        "not_tested": [
            "Repository code, builds, tests, dependencies and workflows were not executed.",
            "External links, runtime behaviour, exploitability, code quality and production deployment were not tested.",
            "Cryptographic attestation validity and artifact-to-source reproducibility were not verified.",
            "Legal licence compatibility, copyright ownership and regulatory compliance were not assessed.",
        ],
        "cannot_certify": [
            "This snapshot cannot certify security, compliance, accessibility, legal fitness, release integrity or operational readiness.",
            "Observed evidence may be incomplete, stale, misleading or unrelated to the deployed product.",
            "A pass means only that the stated bounded observation was made; it is not an assurance opinion or warranty.",
        ],
    }
    return findings, limitations


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Repository Assurance Snapshot",
        "",
        "> **Informational, bounded and read-only. This is not a security, compliance, legal or release certification.**",
        "",
        f"- **Source:** `{report['source']['canonical_ref']}`",
        f"- **Revision:** `{report['source']['revision']}`",
        f"- **Observed at:** `{report['observed_at']}`",
        f"- **Collector:** `{report['collector']['name']} {report['collector']['version']}`",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    for status in ("pass", "warn", "info", "not_observed"):
        lines.append(f"| {status} | {report['summary'].get(status, 0)} |")
    lines.extend(["", "## Findings", ""])
    for item in report["findings"]:
        lines.extend(
            [
                f"### {item['code']} — {item['status']}",
                "",
                f"**{item['title']}**",
                "",
                item["evidence"],
            ]
        )
        if item.get("source_refs"):
            lines.append("")
            lines.append("Sources:")
            lines.extend(f"- `{source}`" for source in item["source_refs"])
        if item.get("limitation"):
            lines.extend(["", f"Limitation: {item['limitation']}"])
        lines.append("")
    lines.extend(["## Limitations", ""])
    for key in ("not_observed", "not_tested", "cannot_certify"):
        lines.extend([f"### {key}", ""])
        lines.extend(f"- {value}" for value in report["limitations"][key])
        lines.append("")
    lines.extend(
        [
            "## Interpretation rule",
            "",
            "Only the precise observations above are supported. Absence of a warning is not evidence of safety. The accompanying `evidence_manifest.json` hashes the dossier and observed evidence sources but does not make those sources true or complete.",
            "",
        ]
    )
    return "\n".join(lines)


def generate_snapshot(source: str, output_dir: Path, local_public_fixture: bool = False) -> dict[str, Path]:
    source_path = Path(source)
    if source_path.exists():
        if not source_path.is_dir():
            raise SnapshotError("local source must be a directory")
        if not local_public_fixture:
            raise SnapshotError("local paths require --local-public-fixture; private/local estates are not implicitly authorised")
        observation = _collect_local(source_path, output_dir)
    else:
        if local_public_fixture:
            raise SnapshotError("--local-public-fixture was supplied but the local source does not exist")
        observation = _collect_remote(source)

    observed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    findings, limitations = _analyse(observation)
    counts: dict[str, int] = {}
    for item in findings:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    report = {
        "schema": SCHEMA,
        "observed_at": observed_at,
        "disposition": "informational_only_cannot_certify",
        "collector": {
            "name": "repository-assurance-snapshot",
            "version": __version__,
            "access": "public_read_only_no_token_no_code_execution",
        },
        "source": {
            "kind": observation.source_kind,
            "canonical_ref": observation.canonical_ref,
            "revision": observation.revision,
            "default_branch": observation.default_branch,
        },
        "summary": counts,
        "findings": findings,
        "limitations": limitations,
    }

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "assurance.json"
    markdown_path = output_dir / "ASSURANCE.md"
    manifest_path = output_dir / "evidence_manifest.json"
    json_path.write_bytes(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8", newline="\n")

    dossier_entries = []
    for path in (markdown_path, json_path):
        raw = path.read_bytes()
        dossier_entries.append({"path": path.name, "sha256": _sha(raw), "size_bytes": len(raw)})
    manifest = {
        "schema": "harlin.repository_assurance_evidence_manifest/v0.1",
        "generated_at": observed_at,
        "hash_algorithm": "sha256",
        "source": report["source"],
        "dossier_files": dossier_entries,
        "observed_evidence": [
            {
                "source_ref": item.source_ref,
                "kind": item.kind,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
            }
            for item in sorted(observation.evidence, key=lambda value: (value.kind, value.source_ref))
        ],
        "limitations": {
            "manifest_self_hash": "The manifest does not hash itself, avoiding a recursive hash claim.",
            "meaning": "A matching hash proves byte identity only; it does not prove truth, completeness, safety, ownership or certification.",
        },
    }
    manifest_path.write_bytes(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return {"markdown": markdown_path, "json": json_path, "manifest": manifest_path}
