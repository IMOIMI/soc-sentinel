"""Evaluate the phishing engine against the Day 1 sample dataset."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engines.phishing_engine import PHISHING_THRESHOLD, analyze_email

PHISHING_DIR = ROOT / "data" / "samples" / "phishing"
LEGITIMATE_DIR = ROOT / "data" / "samples" / "legitimate"


def main() -> None:
    rows = []
    correct = 0

    for expected, sample_dir in (("PHISHING", PHISHING_DIR), ("SAFE", LEGITIMATE_DIR)):
        for sample in sorted(sample_dir.glob("*.eml")):
            alert = analyze_email(sample)
            actual = alert.raw_event["classification"]
            passed = actual == expected
            correct += int(passed)
            rows.append((sample.name, expected, actual, alert.score, passed))

    for sample_name, expected, actual, score, passed in rows:
        marker = "PASS" if passed else "MISS"
        print(f"{marker:4} {sample_name:36} expected={expected:8} actual={actual:8} score={score:3}")

    total = len(rows)
    accuracy = correct / total if total else 0
    false_positives = sum(
        1 for _, expected, actual, _, _ in rows if expected == "SAFE" and actual != "SAFE"
    )

    print()
    print(f"threshold: {PHISHING_THRESHOLD}")
    print(f"accuracy: {correct}/{total} = {accuracy:.1%}")
    print(f"false_positives_on_legitimate: {false_positives}")


if __name__ == "__main__":
    main()
