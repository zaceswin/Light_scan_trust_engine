LightScan Trust Engine (trust-scorer-py) project:

  ---

  Project Overview
  The LightScan Trust Engine is an explainable vulnerability prioritization
  layer designed to be embedded directly into security scanners or run as a
  standalone CLI in automation pipelines. 

  Instead of relying solely on generic CVSS severity scores, it combines
  technical severity, environmental exploitability factors, and business impact
  context to calculate a personalized Trust Score (0–100) for each finding. This
  score is mapped to actionable risk tiers (Critical, High, Medium, Low)
  accompanied by clear, human-readable explanations of why the finding received
  that score.

  ---

  Key Architectural Components

  1. The Domain Model (Finding & ScoredFinding)
   * Vulnerability Types: Focuses on common web vulnerabilities: SQL Injection
     (sql_injection), Stored XSS (xss_stored), Reflected XSS (xss_reflected),
     Open Redirect (open_redirect), and Missing Security Headers
     (missing_security_header).
   * Enriched Attributes: Captures essential security signals such as:
       * Exploitability: internet_facing, requires_authentication,
         requires_user_interaction.
       * Business Context: handles_pii_or_payment, is_authentication_endpoint,
         asset_criticality (1 to 5).
       * External Intelligence: Integrated CVSS base scores and EPSS (Exploit
         Prediction Scoring System) percentiles.
   * Metadata Integration: Automatically maps findings to their respective OWASP
     Top 10 categories, CWE IDs, and standard remediation steps.

  2. The Prioritization & Scoring Engine (TrustEngine)
  The scoring pipeline executes a multi-stage deterministic calculation to
  compute the final score:
   * Exploit Likelihood: Powered by a local scikit-learn Logistic Regression
     model (currently trained on a synthetic dataset for POC demonstration) that
     predicts likelihood based on exposure controls. If an external EPSS score
     is supplied, it is combined as a weighted average (60% EPSS / 40% model).
   * Business Impact Weight: Computes an impact multiplier based on asset
     criticality and data sensitivity (e.g., handling PII/payment data or
     protecting auth endpoints).
   * Trust Score Formula:
      Raw Score = Base Severity × (0.4 + 0.6 × Exploit Likelihood) × Business
  Impact × Confidence
      The score is then normalized to a 0–100 scale.
   * Explainability Generator: Formulates structured, natural language reasoning
     detailing the precise positive signals and mitigating factors (e.g.,
     internal-only asset, requires authentication) that influenced the score.
   * Deduplication: Features an automated deduplication layer that groups and
     discards repeated scanner observations using a unique signature of
     vuln_type | url | parameter.
  3. Configuration & Tuning (ScoringConfig)
  Enables security teams to tune tier classification thresholds (Critical, High,
  Medium) and weight parameters without altering the core code, allowing
  alignment with the organization's specific risk appetite.

  ---

  Interfaces & Usage

   * Python API: Easily integrated programmatically into other Python tools:

   1     from trust_scorer import Finding, TrustEngine, VulnType
   2     
   3     engine = TrustEngine()
   4     result = engine.score(Finding(VulnType.SQLI,
     "https://example.test/login"))
   5     print(result.trust_score, result.tier, result.explanation)
   * Command Line Interface (CLI): Accepts JSON files containing scanner
     findings and outputs either structured JSON or formatted console tables:

   1     # Run built-in demo
   2     python trust_scorer.py
   3     
   4     # Process findings and output JSON
   5     python trust_scorer.py examples/findings.json --output json
