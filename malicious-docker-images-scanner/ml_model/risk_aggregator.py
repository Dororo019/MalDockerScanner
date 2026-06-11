"""
This program is for aggregating  per-vulnerability scores into a single image-level risk score.

The aggregator takes the list of VulnerabilityContext objects scored by
RiskScorer and produces an ImageRisk object that scan_orchestrator uses
to compute the final risk score.

Key design decisions (documented for thesis):

1. Weighted max + mean blend: Pure mean underweights single critical CVEs (one 10.0 buried in 40 lows).
    Pure max ignores breadth (40 lows is worse than 1 low).
    Blend: 60% weighted max, 40% weighted mean.

2. Volume penalty: more vulnerabilities means higher aggregate risk, even if each individual score is moderate. Capped at +20 points.

3. Critical floor: if  ANY vulnerability is CRITICAL severity with a public exploit, the image cannot score below 60 (HIGH).
"""

from dataclasses import dataclass
from typing import List, Optional

from ml_model.risk_scorer import RiskScorer, VulnerabilityContext


@dataclass
class ImageRisk:
    """creating the result of aggregating all vulnerability scores for one image."""
    image_name:      str
    aggregated_risk: float   # 0–100, used by scan_orchestrator
    risk_category:   str     # LOW / MEDIUM / HIGH / CRITICAL
    vuln_count:      int
    max_single:      float   # highest individual score
    mean_score:      float   # mean of all individual scores


def _category(score: float) -> str:
    if score < 20:  return "LOW"
    if score < 50:  return "MEDIUM"
    if score < 80:  return "HIGH"
    return "CRITICAL"


class RiskAggregator:
    """
    to aggregate per-vulnerability scores into an image-level risk. it will be used directly by a scan_orchestrator.run_full_scan().
    """

    def __init__(self):
        self._scorer = RiskScorer()

    def aggregate_image_risk(
        self,
        image_name: str,
        contexts: List[VulnerabilityContext],
    ) -> ImageRisk:
        """
        Score all vulnerabilities and aggregate into a single ImageRisk.If contexts is empty (no CVEs found), it will return a near-zero score .
        """
        if not contexts:
            return ImageRisk(
                image_name      = image_name,
                aggregated_risk = 0.0,
                risk_category   = "LOW",
                vuln_count      = 0,
                max_single      = 0.0,
                mean_score      = 0.0,
            )

        # Score each vulnerability
        scores = [self._scorer.score(ctx) for ctx in contexts]

        max_score  = max(scores)
        mean_score = sum(scores) / len(scores)

        # Blend: 60% highest single score + 40% mean
        blended = (max_score * 0.60) + (mean_score * 0.40)

        # Volume penalty: more CVEs = more attack surface
        # +0.5 per vuln up to a maximum of +20
        volume_penalty = min(20.0, len(scores) * 0.5)

        raw = blended + volume_penalty

        # Critical floor: if any CVE is critical + public exploit -> floor of 60
        has_critical_exploit = any(
            ctx.cvss_score >= 9.0 and ctx.public_exploit
            for ctx in contexts
        )
        if has_critical_exploit:
            raw = max(raw, 60.0)

        aggregated = max(0.0, min(raw, 100.0))

        return ImageRisk(
            image_name      = image_name,
            aggregated_risk = round(aggregated, 2),
            risk_category   = _category(aggregated),
            vuln_count      = len(contexts),
            max_single      = round(max_score, 2),
            mean_score      = round(mean_score, 2),
        )
