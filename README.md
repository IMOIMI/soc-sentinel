# SOC-Sentinel

Mini SOC Analyst Platform -- phishing detection, log analysis, and automated incident response.

## Planned Modules

- `apps/api` - backend API for scans, log ingestion, incidents, and response actions
- `apps/web` - analyst dashboard frontend
- `apps/worker` - background jobs for enrichment, rule runs, and notifications
- `packages/detectors` - phishing and IOC detection logic
- `packages/log-parser` - reusable log parsing utilities
- `packages/playbooks` - automated incident response playbooks
- `data` - local sample logs, rules, and generated reports
- `infra` - Docker and deployment configuration
- `docs` - architecture notes and project documentation

## Day 2: Phishing Engine Baseline

The phishing engine analyzes `.eml` files and emits the shared `Alert` dataclass
used by the rest of the platform. Each heuristic follows the same shape:

`triggered`, `weight`, `reason`, and optional `indicator`.

This keeps the detector explainable: the final score is useful, but the evidence
trail is what makes the output analyst-ready.

Current heuristic coverage:

- Authentication-Results failure or weak-result detection for SPF, DKIM, DMARC, and compauth
- Display-name brand impersonation versus sending domain
- Return-Path domain mismatch
- Reply-To domain mismatch
- Risky attachment extension detection
- Urgency and social-engineering language in subject/body
- Suspicious link patterns, including raw IP hosts, link volume, and external domain spread
- Free-provider brand impersonation, subject brand mismatch, relay obfuscation, and risky marketplace/crypto lure language

Evaluation dataset:

- 8 real phishing emails from `rf-peixoto/phishing_pot`
- 5 synthetic legitimate emails
- 13 total `.eml` test cases

Measured result:

- Accuracy: 12/13 = 92.3%
- False positives on legitimate samples: 0
- Threshold: 20/100

Known limitation:

- `sample-1000.eml` is a Portuguese-language tax-refund lure sent through a
  genuine, SPF/DKIM/DMARC-passing Gmail account. The current heuristic engine
  intentionally avoids broad language-specific content classification, so this
  remains a documented miss rather than a hand-tuned score.

Run the evaluation:

```bash
python scripts/evaluate_phishing_engine.py
```

