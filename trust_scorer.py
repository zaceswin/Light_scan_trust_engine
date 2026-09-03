"""Explainable vulnerability prioritisation.

The engine accepts scanner findings and returns a ranked, human-readable
priority score. It is small enough to embed in a scanner and also provides a
JSON CLI for pipelines and demonstrations.

The bundled model is a proof of concept trained on synthetic labels. Replace
it with organisation-specific outcomes before using the score for automated
security decisions.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

import numpy as np
from sklearn.linear_model import LogisticRegression

LOGGER = logging.getLogger(__name__)


class VulnType(str, Enum):
    SQLI = "sql_injection"
    XSS_STORED = "xss_stored"
    XSS_REFLECTED = "xss_reflected"
    OPEN_REDIRECT = "open_redirect"
    MISSING_SECURITY_HEADER = "missing_security_header"


BASE_SEVERITY = {
    VulnType.SQLI: 9.1,
    VulnType.XSS_STORED: 8.2,
    VulnType.XSS_REFLECTED: 6.1,
    VulnType.OPEN_REDIRECT: 4.7,
    VulnType.MISSING_SECURITY_HEADER: 3.1,
}

OWASP_MAPPING = {
    VulnType.SQLI: "A03:2021 - Injection",
    VulnType.XSS_STORED: "A03:2021 - Injection",
    VulnType.XSS_REFLECTED: "A03:2021 - Injection",
    VulnType.OPEN_REDIRECT: "A01:2021 - Broken Access Control",
    VulnType.MISSING_SECURITY_HEADER: "A05:2021 - Security Misconfiguration",
}

CWE_MAPPING = {
    VulnType.SQLI: "CWE-89",
    VulnType.XSS_STORED: "CWE-79",
    VulnType.XSS_REFLECTED: "CWE-79",
    VulnType.OPEN_REDIRECT: "CWE-601",
    VulnType.MISSING_SECURITY_HEADER: "CWE-693",
}

REMEDIATION = {
    VulnType.SQLI: "Use parameterized queries and validate input at the server boundary.",
    VulnType.XSS_STORED: "Apply context-aware output encoding and sanitize stored content.",
    VulnType.XSS_REFLECTED: "Apply context-aware output encoding and validate reflected input.",
    VulnType.OPEN_REDIRECT: "Allow-list redirect destinations and reject untrusted absolute URLs.",
    VulnType.MISSING_SECURITY_HEADER: "Set the appropriate security response header and verify it in CI.",
}


@dataclass
class Finding:
    """A scanner finding with exploitability and business-context signals."""

    vuln_type: VulnType
    url: str
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    internet_facing: bool = True
    requires_authentication: bool = False
    requires_user_interaction: bool = False
    handles_pii_or_payment: bool = False
    is_authentication_endpoint: bool = False
    asset_criticality: int = 3
    cvss_base_score: Optional[float] = None
    epss_score: Optional[float] = None
    confidence: float = 1.0
    remediation: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.vuln_type, VulnType):
            try:
                self.vuln_type = VulnType(self.vuln_type)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Unsupported vulnerability type: {self.vuln_type!r}") from exc
        parsed = urlparse(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("url must be an absolute HTTP(S) URL")
        if not isinstance(self.asset_criticality, int) or not 1 <= self.asset_criticality <= 5:
            raise ValueError("asset_criticality must be an integer from 1 to 5")
        if self.cvss_base_score is not None:
            self.cvss_base_score = _bounded(self.cvss_base_score, "cvss_base_score", 0, 10)
        if self.epss_score is not None:
            self.epss_score = _bounded(self.epss_score, "epss_score", 0, 1)
        self.confidence = _bounded(self.confidence, "confidence", 0, 1)

    @property
    def base_severity(self) -> float:
        return self.cvss_base_score if self.cvss_base_score is not None else BASE_SEVERITY[self.vuln_type]

    @property
    def fingerprint(self) -> str:
        """Stable identity used to remove repeated scanner observations."""
        return "|".join((self.vuln_type.value, self.url, self.parameter or ""))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(**data)


def _bounded(value: float, name: str, low: float, high: float) -> float:
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return float(value)


@dataclass
class ScoredFinding:
    finding: Finding
    trust_score: float
    exploit_likelihood: float
    tier: str
    explanation: str
    owasp: str
    cwe: str
    remediation: str
    score_components: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["finding"]["vuln_type"] = self.finding.vuln_type.value
        return result


@dataclass(frozen=True)
class ScoringConfig:
    """Tune prioritisation without changing the domain model."""

    critical_threshold: float = 75.0
    high_threshold: float = 50.0
    medium_threshold: float = 25.0
    max_impact_weight: float = 1.7

    def __post_init__(self) -> None:
        if not self.medium_threshold < self.high_threshold < self.critical_threshold <= 100:
            raise ValueError("thresholds must be ordered and no greater than 100")
        if self.max_impact_weight <= 0:
            raise ValueError("max_impact_weight must be positive")


def _features_from_finding(finding: Finding) -> np.ndarray:
    return np.array([
        float(finding.internet_facing),
        float(not finding.requires_authentication),
        float(not finding.requires_user_interaction),
        float(finding.base_severity >= 7.0),
    ])


def _build_synthetic_training_set() -> tuple[np.ndarray, np.ndarray]:
    X = np.array([
        [1, 1, 1, 1], [1, 1, 1, 1], [1, 1, 0, 1], [1, 0, 1, 1],
        [0, 1, 1, 1], [1, 1, 1, 0], [1, 1, 1, 0], [1, 0, 0, 0],
        [0, 0, 0, 0], [0, 1, 0, 1],
    ])
    return X, np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0])


class TrustEngine:
    """Score and rank findings with deterministic, explainable output."""

    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or ScoringConfig()
        X, y = _build_synthetic_training_set()
        self._model = LogisticRegression(random_state=42, max_iter=1000)
        self._model.fit(X, y)

    def _exploit_likelihood(self, finding: Finding) -> float:
        model_likelihood = float(self._model.predict_proba(_features_from_finding(finding).reshape(1, -1))[0, 1])
        if finding.epss_score is not None:
            return 0.4 * model_likelihood + 0.6 * finding.epss_score
        return model_likelihood

    @staticmethod
    def _business_impact_weight(finding: Finding) -> float:
        weight = 1.0 + (0.4 if finding.handles_pii_or_payment else 0)
        weight += 0.3 if finding.is_authentication_endpoint else 0
        return max(0.5, weight + (finding.asset_criticality - 3) * 0.1)

    @staticmethod
    def _tier(score: float, config: ScoringConfig) -> str:
        if score >= config.critical_threshold:
            return "Critical"
        if score >= config.high_threshold:
            return "High"
        if score >= config.medium_threshold:
            return "Medium"
        return "Low"

    @staticmethod
    def _explain(finding: Finding, likelihood: float) -> str:
        positive, mitigating = [], []
        if finding.internet_facing:
            positive.append("internet-facing")
        else:
            mitigating.append("internal-only asset")
        if not finding.requires_authentication:
            positive.append("no authentication required")
        else:
            mitigating.append("authentication required")
        if not finding.requires_user_interaction:
            positive.append("no user interaction required")
        else:
            mitigating.append("requires user interaction")
        if finding.handles_pii_or_payment:
            positive.append("touches PII or payment data")
        if finding.is_authentication_endpoint:
            positive.append("authentication endpoint")
        positive.append(f"base severity {finding.base_severity:.1f}/10")
        positive.append(f"estimated exploit likelihood {likelihood:.0%}")
        text = "; ".join(positive)
        if mitigating:
            text += "; mitigating factors: " + ", ".join(mitigating)
        return text

    def score(self, finding: Finding) -> ScoredFinding:
        likelihood = self._exploit_likelihood(finding)
        impact = self._business_impact_weight(finding)
        raw = finding.base_severity * (0.4 + 0.6 * likelihood) * impact * finding.confidence
        score = min(100.0, round(raw * 100 / (10 * self.config.max_impact_weight), 1))
        components = {
            "base_severity": round(finding.base_severity, 3),
            "exploit_likelihood": round(likelihood, 3),
            "business_impact_weight": round(impact, 3),
            "confidence": round(finding.confidence, 3),
        }
        return ScoredFinding(
            finding=finding, trust_score=score, exploit_likelihood=round(likelihood, 3),
            tier=self._tier(score, self.config), explanation=self._explain(finding, likelihood),
            owasp=OWASP_MAPPING[finding.vuln_type], cwe=CWE_MAPPING[finding.vuln_type],
            remediation=finding.remediation or REMEDIATION[finding.vuln_type], score_components=components,
        )

    def score_all(self, findings: Iterable[Finding], *, deduplicate: bool = True) -> list[ScoredFinding]:
        items = list(findings)
        if deduplicate:
            unique: dict[str, Finding] = {}
            for finding in items:
                unique.setdefault(finding.fingerprint, finding)
            if len(unique) != len(items):
                LOGGER.info("Removed %d duplicate findings", len(items) - len(unique))
            items = list(unique.values())
        return sorted((self.score(finding) for finding in items), key=lambda item: (-item.trust_score, item.finding.fingerprint))


def demo_findings() -> list[Finding]:
    return [
        Finding(VulnType.SQLI, "https://example-sacco.co.ke/login", parameter="username", handles_pii_or_payment=True, is_authentication_endpoint=True, asset_criticality=5),
        Finding(VulnType.MISSING_SECURITY_HEADER, "https://example-sacco.co.ke/about", asset_criticality=2),
        Finding(VulnType.XSS_REFLECTED, "https://example-sacco.co.ke/search", parameter="q", requires_user_interaction=True),
    ]


def _load_findings(path: str) -> list[Finding]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("findings", [])
    if not isinstance(payload, list):
        raise ValueError("input JSON must be a list or an object with a 'findings' list")
    return [Finding.from_dict(item) for item in payload]


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Rank vulnerability findings by explainable trust score")
    parser.add_argument("input", nargs="?", help="JSON file containing findings; omit to run the demo")
    parser.add_argument("--output", choices=("text", "json"), default="text")
    parser.add_argument("--keep-duplicates", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        findings = _load_findings(args.input) if args.input else demo_findings()
        scored = TrustEngine().score_all(findings, deduplicate=not args.keep_duplicates)
        if args.output == "json":
            print(json.dumps([item.to_dict() for item in scored], indent=2))
        else:
            for item in scored:
                print(f"[{item.tier:8}] {item.trust_score:5.1f}  {item.finding.vuln_type.value:25} {item.finding.url}")
                print(f"           why: {item.explanation}")
                print(f"           fix: {item.remediation}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
