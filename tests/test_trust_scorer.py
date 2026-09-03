import json
import subprocess
import sys
import unittest
from pathlib import Path

from trust_scorer import Finding, ScoringConfig, TrustEngine, VulnType


class TrustEngineTests(unittest.TestCase):
    def test_high_context_finding_scores_above_basic_finding(self):
        engine = TrustEngine()
        urgent = Finding(VulnType.SQLI, "https://example.test/login", handles_pii_or_payment=True, is_authentication_endpoint=True, asset_criticality=5)
        basic = Finding(VulnType.MISSING_SECURITY_HEADER, "https://example.test/about")
        self.assertGreater(engine.score(urgent).trust_score, engine.score(basic).trust_score)

    def test_cvss_and_epss_are_used(self):
        result = TrustEngine().score(Finding(VulnType.OPEN_REDIRECT, "https://example.test/redirect", cvss_base_score=9.0, epss_score=0.95))
        self.assertEqual(result.score_components["base_severity"], 9.0)
        self.assertGreater(result.exploit_likelihood, 0.5)

    def test_explanation_contains_mitigating_factors(self):
        result = TrustEngine().score(Finding(VulnType.SQLI, "https://internal.test/query", internet_facing=False, requires_authentication=True, requires_user_interaction=True))
        self.assertIn("mitigating factors", result.explanation)
        self.assertIn("authentication required", result.explanation)

    def test_validation_rejects_bad_values(self):
        with self.assertRaises(ValueError):
            Finding(VulnType.SQLI, "not-a-url")
        with self.assertRaises(ValueError):
            Finding(VulnType.SQLI, "https://example.test", asset_criticality=6)
        with self.assertRaises(ValueError):
            Finding(VulnType.SQLI, "https://example.test", epss_score=2)

    def test_deduplication(self):
        finding = Finding(VulnType.SQLI, "https://example.test", parameter="q")
        self.assertEqual(len(TrustEngine().score_all([finding, finding])), 1)

    def test_configurable_tiers(self):
        config = ScoringConfig(critical_threshold=60, high_threshold=40, medium_threshold=20)
        result = TrustEngine(config).score(Finding(VulnType.SQLI, "https://example.test"))
        self.assertIn(result.tier, {"Critical", "High", "Medium", "Low"})

    def test_serialization_has_json_safe_enum(self):
        result = TrustEngine().score(Finding(VulnType.SQLI, "https://example.test"))
        self.assertIn('"vuln_type": "sql_injection"', json.dumps(result.to_dict()))


class CliTests(unittest.TestCase):
    def test_demo_cli_and_json_cli(self):
        root = Path(__file__).parents[1]
        demo = subprocess.run([sys.executable, str(root / "trust_scorer.py")], capture_output=True, text=True, check=True)
        self.assertIn("Critical", demo.stdout)
        output = subprocess.run([sys.executable, str(root / "trust_scorer.py"), str(root / "examples/findings.json"), "--output", "json"], capture_output=True, text=True, check=True)
        self.assertEqual(len(json.loads(output.stdout)), 2)


if __name__ == "__main__":
    unittest.main()
