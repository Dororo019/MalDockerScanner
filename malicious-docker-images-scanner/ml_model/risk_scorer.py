"""
ml_model/risk_scorer.py
========================
Context-aware vulnerability risk scoring.

This is the CORE NOVELTY of the project (thesis contribution):
    Standard scanners report raw CVE counts → alert fatigue.
    This model adjusts scores using context:
        • Is the vulnerable package actually in use?
        • Is it a dev-only dependency?
        • Does a public exploit exist?
        • How old is the vulnerability?
        • Is a patch available?

The result is a per-vulnerability score that is LOWER than naive CVSS
for false-positive-prone findings, and HIGHER for genuinely dangerous ones.
This directly implements the "false positive reduction" claim in the thesis.

VulnerabilityContext is populated by scan_orchestrator._build_vuln_contexts()
from Trivy JSON output.
"""

from dataclasses import dataclass, field
from typing import Optional
import math


@dataclass
class VulnerabilityContext:
    """All available context for a single CVE in a scanned image."""
    cve_id:          str
    cvss_score:      float    # 0.0 – 10.0
    cvss_vector:     str      # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/..."
    package_name:    str
    package_type:    str      # "os", "pip", "npm", "gem", etc.
    layer_index:     int      # which layer the package is in
    total_layers:    int      # total layers in the image
    in_use:          bool     # is this package actually called at runtime?
    is_dev_dependency: bool   # dev/test only?
    environment:     str      # "production", "staging", "development"
    patch_available: bool     # does FixedVersion exist?
    public_exploit:  bool     # is there a known public exploit?
    age_days:        int      # how many days since the CVE was published


class RiskScorer:
    """
    Here, it is different from aggregation and this is for computing a context-aware risk score for a single vulnerability.

    IMP Score formula:
        base       = normalise(cvss_score)          # 0–1
        exploitability = AV + AC + PR + UI factors  # from CVSS vector , AV:Attack Vector,AC:Attack Complexity, PR: Priviledges Required , UI: User Interaction
        impact     = C + I + A factors              # from CVSS vector , Confidentiality, Integrty , Availability Impact
        temporal   = age + patch_available + public_exploit
        context    = in_use + dev_dep + environment + layer_depth ,
        
        #1 dependencies/packages: exec during runtime;to boot uo and serve users 
        #2 development dependencies: for local dev ,testing& Building
        #3 env: local/dev/staging/production
        #4 layer/_depth: based on the order and position of code stacks

        raw = (base×0.40) + (exploitability×0.25) + (impact×0.20)
            + (temporal×0.10) + (context×0.05)

        final = raw × 100  -->  clamped to [0, 100]

    The Final weights for tagging the scores w.r.t to score formula given above :
        FinalRiskScore = (BaseNorm×0.40) + (Exploit×0.25) + (Impact×0.20)
                       + (Temporal×0.10) + (Context×0.05)
    """

    # CVSS vector parsing 
    _AV  = {"N": 1.0, "A": 0.6, "L": 0.4, "P": 0.2}
    _AC  = {"L": 1.0, "H": 0.5}
    _PR  = {"N": 1.0, "L": 0.7, "H": 0.3}
    _UI  = {"N": 1.0, "R": 0.5}
    _C   = {"H": 1.0, "L": 0.5, "N": 0.0}  # Confidentiality
    _I   = {"H": 1.0, "L": 0.5, "N": 0.0}  # Integrity
    _A   = {"H": 1.0, "L": 0.5, "N": 0.0}  # Availability

    def _parse_vector(self, vector: str) -> dict:
        """Parse a CVSS v3 vector string into component values."""
        parts = {}
        for segment in vector.split("/"):
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k] = v
        return parts

    def _exploitability(self, ctx: VulnerabilityContext) -> float:
        """Score 0–1 based on how easily exploitable the vulnerability is."""
        v = self._parse_vector(ctx.cvss_vector)
        av = self._AV.get(v.get("AV", "N"), 0.5)
        ac = self._AC.get(v.get("AC", "L"), 0.5)
        pr = self._PR.get(v.get("PR", "N"), 0.5)
        ui = self._UI.get(v.get("UI", "N"), 0.5)
        # Public exploit available--> additional boost
        exploit_boost = 0.2 if ctx.public_exploit else 0.0
        return min(1.0, (av * ac * pr * ui) + exploit_boost)

    def _impact(self, ctx: VulnerabilityContext) -> float:
        """Score 0–1 based on CIA impact from CVSS vector."""
        v = self._parse_vector(ctx.cvss_vector)
        c = self._C.get(v.get("C", "N"), 0.0)
        i = self._I.get(v.get("I", "N"), 0.0)
        a = self._A.get(v.get("A", "N"), 0.0)
        return (c + i + a) / 3.0

    def _temporal(self, ctx: VulnerabilityContext) -> float:
        """Score 0–1 based on how urgent the vulnerability is over time."""
        # Older unpatched = more dangerous (exploits mature over time)
        age_factor = min(1.0, ctx.age_days / 365.0)
        # Patch available = slightly less urgent (upgrading is an option)
        patch_factor = 0.0 if ctx.patch_available else 0.3
        # Public exploit = very urgent
        exploit_factor = 0.5 if ctx.public_exploit else 0.0
        return min(1.0, age_factor * 0.4 + patch_factor + exploit_factor)

    def _context(self, ctx: VulnerabilityContext) -> float:
        """
        Score 0–1 based on deployment context.
        THIS IS WHERE FALSE POSITIVE REDUCTION HAPPENS:
            Dev-only packages in production images 
            Packages not in use at runtime       
            Non-production environments          
        """
        score = 0.5  # neutral baseline

        # If the package is not actually used at runtime, it is lower risk
        if not ctx.in_use:
            score -= 0.3

        # Dev dependencies in production are concerning (should be stripped) but the vuln itself is less likely to be exploited
        if ctx.is_dev_dependency:
            score -= 0.2

        # Layer depth: vulnerabilities introduced in earlier (base) layer are harder to fix (can't change the base image easily)
        if ctx.total_layers > 0:
            layer_depth_factor = (ctx.total_layers - ctx.layer_index) / ctx.total_layers
            score += layer_depth_factor * 0.1

        # Environment adjustment
        env_factors = {"production": 0.3, "staging": 0.1, "development": -0.1}
        score += env_factors.get(ctx.environment, 0.0)

        return max(0.0, min(1.0, score))

    def score(self, ctx: VulnerabilityContext) -> float:
        """
        Compute the final context-aware score for one vulnerability.
        Returns a value in [0, 100].
        """
        base           = ctx.cvss_score / 10.0    # normalise CVSS to 0–1
        exploitability = self._exploitability(ctx)
        impact         = self._impact(ctx)
        temporal       = self._temporal(ctx)
        context        = self._context(ctx)

        # Weighted combination (Week 7 formula)
        raw = (
            base           * 0.40 +
            exploitability * 0.25 +
            impact         * 0.20 +
            temporal       * 0.10 +
            context        * 0.05
        )
        return max(0.0, min(raw * 100.0, 100.0))
