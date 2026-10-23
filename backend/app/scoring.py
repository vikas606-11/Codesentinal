"""Deterministic scoring. Change the numbers below to tune the score; nothing else needs editing."""
from app.models.schemas import Finding

START_SCORE = 100

# Points removed per finding, by severity
PENALTIES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3}

# Findings in the Secret category use this instead of their severity penalty
SECRET_PENALTY = 20

# (minimum score, rating), checked from the top
RATING_BANDS = [
    (90, "Excellent"),
    (75, "Good"),
    (60, "Needs Improvement"),
    (0, "Critical"),
]


def penalty_for(finding: Finding) -> int:
    return SECRET_PENALTY if finding.category == "Secret" else PENALTIES[finding.severity]


def calculate_score(findings: list[Finding]) -> int:
    score = START_SCORE - sum(penalty_for(f) for f in findings)
    return max(0, min(100, score))


def rating_for(score: int) -> str:
    for minimum, name in RATING_BANDS:
        if score >= minimum:
            return name
    return RATING_BANDS[-1][1]


def gate_for(score: int, threshold: int) -> str:
    return "PASS" if score >= threshold else "FAIL"
