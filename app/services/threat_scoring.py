"""Transparent, non-probabilistic score calculation from rule-based alerts."""
from collections import Counter


def score_alerts(alerts: list[dict]) -> tuple[int, str, list[str]]:
    """Combine alert contributions, cap at 100, and return viva-friendly reasons."""
    score = min(100, sum(alert["score"] for alert in alerts))
    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    elif score >= 30:
        severity = "Medium"
    else:
        severity = "Low"
    reasons = list(Counter(alert["alert_type"] for alert in alerts).keys())
    return score, severity, reasons
