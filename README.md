# AI-Powered-Multi-Modal-Scam-Intelligence-System

This project implements a practical **multi-modal scam detection pipeline** that combines:

- **Rule-based NLP signals** from message text.
- **Machine-learning text classification** for scam probability.
- **Metadata intelligence** from URLs, emails, and phone numbers.
- **Risk fusion** into one final explainable risk score.

## Architecture

1. `TextRiskDetector`: detects urgency, credential theft language, investment scam phrasing, and social-engineering cues.
2. `MLTextClassifier`: lightweight multinomial Naive Bayes baseline model trained on starter scam/legit samples.
3. `MetadataRiskDetector`: checks suspicious TLDs, URL obfuscation/IP patterns, numeric-heavy emails, and irregular phone formats.
4. `fuse_scores`: weighted fusion across modalities.
5. `ScamIntelligenceSystem`: orchestrates full scoring and returns decision + rationale.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py \
  --text "Urgent! Your account is suspended. Share OTP and send gift cards now" \
  --urls "http://verify-security-alert.xyz/login"
```

Sample output:

```json
{
  "verdict": "likely_scam",
  "risk_level": "high",
  "final_score": 0.782,
  "signals": {
    "text_rule_score": 0.71,
    "ml_score": 0.84,
    "metadata_score": 0.25
  },
  "rationale": ["..."]
}
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Extending to full multi-modal intelligence

To make this production-grade, extend with:

- OCR and visual phishing logo detection for screenshots.
- Audio transcription + voice scam cue extraction.
- Domain reputation APIs and threat-intel feeds.
- Feedback loop for analyst-confirmed labels and periodic re-training.
- Serving layer (FastAPI) and case-management dashboard.
