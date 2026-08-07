from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from repository_assurance_snapshot import __version__
from repository_assurance_snapshot.scanner import SnapshotError, generate_snapshot


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "fixtures" / "public_demo_repo"


class SnapshotTests(unittest.TestCase):
    def test_local_source_requires_explicit_public_fixture_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(SnapshotError):
                generate_snapshot(str(FIXTURE), Path(temp))

    def test_generates_required_outputs_and_limitations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            paths = generate_snapshot(str(FIXTURE), output, local_public_fixture=True)
            self.assertEqual({"markdown", "json", "manifest"}, set(paths))
            for path in paths.values():
                self.assertTrue(path.is_file())
            report = json.loads((output / "assurance.json").read_text(encoding="utf-8"))
            self.assertEqual(__version__, report["collector"]["version"])
            self.assertEqual("informational_only_cannot_certify", report["disposition"])
            self.assertTrue(report["limitations"]["not_observed"])
            self.assertTrue(report["limitations"]["not_tested"])
            self.assertTrue(report["limitations"]["cannot_certify"])

    def test_fixture_exposes_pinning_warning_and_observed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            generate_snapshot(str(FIXTURE), Path(temp), local_public_fixture=True)
            report = json.loads((Path(temp) / "assurance.json").read_text(encoding="utf-8"))
            by_code = {item["code"]: item for item in report["findings"]}
            self.assertEqual("warn", by_code["WORKFLOW_IMMUTABLE_REFS"]["status"])
            self.assertEqual("info", by_code["SBOM_EVIDENCE"]["status"])
            self.assertEqual("info", by_code["TEST_EVIDENCE"]["status"])
            self.assertEqual("info", by_code["RELEASE_PROVENANCE_EVIDENCE"]["status"])
            self.assertEqual("pass", by_code["SECURITY_POLICY"]["status"])

    def test_manifest_hashes_match_dossier_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            generate_snapshot(str(FIXTURE), output, local_public_fixture=True)
            manifest = json.loads((output / "evidence_manifest.json").read_text(encoding="utf-8"))
            for item in manifest["dossier_files"]:
                raw = (output / item["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
                self.assertEqual(len(raw), item["size_bytes"])
            self.assertGreater(len(manifest["observed_evidence"]), 0)


if __name__ == "__main__":
    unittest.main()
