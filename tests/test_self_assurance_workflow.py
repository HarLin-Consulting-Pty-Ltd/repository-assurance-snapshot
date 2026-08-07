from __future__ import annotations

import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "self-assurance.yml"


class SelfAssuranceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_third_party_actions_are_immutable(self) -> None:
        refs = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", self.text)
        third_party = [ref for ref in refs if ref != "./"]
        self.assertGreaterEqual(len(third_party), 3)
        for ref in third_party:
            self.assertRegex(ref, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_least_privilege_and_no_collector_token(self) -> None:
        self.assertIn("permissions:\n  contents: read", self.text)
        self.assertNotRegex(self.text, r"(?m)^\s+[A-Za-z-]+:\s*write\s*$")
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn('GITHUB_TOKEN: ""', self.text)
        self.assertIn('GH_TOKEN: ""', self.text)

    def test_dogfood_and_artifact_contract(self) -> None:
        self.assertIn("uses: ./", self.text)
        self.assertIn("repository: ${{ github.repository }}", self.text)
        self.assertIn("output: repository-assurance", self.text)
        self.assertIn("if-no-files-found: error", self.text)
        self.assertIn("retention-days: 14", self.text)


if __name__ == "__main__":
    unittest.main()

