from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass
class DetectorSignal:
    label: str
    score: float
    rationale: list[str]


class TextRiskDetector:
    """Rule-based detector for scam language in text transcripts/messages."""

    _HIGH_RISK_PATTERNS = {
        r"\b(urgent|immediately|act now|last chance)\b": 0.18,
        r"\b(wire transfer|gift card|crypto|bitcoin|voucher)\b": 0.22,
        r"\b(password|otp|verification code|bank details|ssn)\b": 0.24,
        r"\b(guaranteed return|double your money|risk-free)\b": 0.2,
        r"\b(congratulations you won|lottery|prize claim)\b": 0.18,
    }

    _SOCIAL_ENGINEERING = {
        r"\b(police|tax authority|irs|court notice)\b": 0.15,
        r"\b(account suspended|security alert|confirm identity)\b": 0.15,
        r"\b(do not tell anyone|keep this confidential)\b": 0.12,
    }

    def analyze(self, text: str) -> DetectorSignal:
        normalized = text.lower().strip()
        if not normalized:
            return DetectorSignal("text", 0.0, ["No text provided."])

        score = 0.0
        rationale: list[str] = []

        for pattern, weight in self._HIGH_RISK_PATTERNS.items():
            if re.search(pattern, normalized):
                score += weight
                rationale.append(f"Matched high-risk phrase pattern: {pattern}")

        for pattern, weight in self._SOCIAL_ENGINEERING.items():
            if re.search(pattern, normalized):
                score += weight
                rationale.append(f"Matched social-engineering phrase pattern: {pattern}")

        punctuation_pressure = normalized.count("!") + normalized.count("$")
        if punctuation_pressure >= 3:
            pressure_score = min(0.12, punctuation_pressure * 0.02)
            score += pressure_score
            rationale.append("Message uses pressure punctuation typical in scams.")

        uppercase_words = [w for w in re.findall(r"\b[A-Z]{3,}\b", text) if len(w) > 3]
        if uppercase_words:
            score += 0.05
            rationale.append("Contains uppercase pressure wording.")

        final_score = min(score, 1.0)
        if not rationale:
            rationale.append("No obvious high-risk text patterns were detected.")
        return DetectorSignal("text", final_score, rationale)


class MetadataRiskDetector:
    """Heuristics for URL/domain/phone/email metadata risk."""

    _SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".gq", ".tk", ".work"}

    def analyze(
        self,
        urls: Iterable[str] | None = None,
        emails: Iterable[str] | None = None,
        phones: Iterable[str] | None = None,
    ) -> DetectorSignal:
        urls = list(urls or [])
        emails = list(emails or [])
        phones = list(phones or [])

        score = 0.0
        rationale: list[str] = []

        for url in urls:
            lowered = url.lower()
            if "@" in lowered or re.search(r"\d{1,3}(?:\.\d{1,3}){3}", lowered):
                score += 0.2
                rationale.append(f"URL looks obfuscated or IP-based: {url}")
            if any(tld in lowered for tld in self._SUSPICIOUS_TLDS):
                score += 0.15
                rationale.append(f"URL uses suspicious top-level domain: {url}")
            if lowered.count("-") >= 3:
                score += 0.08
                rationale.append(f"URL has excessive hyphenation: {url}")

        for email in emails:
            lowered = email.lower()
            if re.search(r"\d{4,}", lowered):
                score += 0.08
                rationale.append(f"Email contains unusual numeric pattern: {email}")
            if any(tld in lowered for tld in self._SUSPICIOUS_TLDS):
                score += 0.1
                rationale.append(f"Email domain has suspicious top-level domain: {email}")

        for phone in phones:
            digits = re.sub(r"\D", "", phone)
            if len(digits) < 10 or len(digits) > 15:
                score += 0.05
                rationale.append(f"Phone format is irregular: {phone}")

        final_score = min(score, 1.0)
        if not rationale:
            rationale.append("Metadata did not include common scam risk indicators.")
        return DetectorSignal("metadata", final_score, rationale)
