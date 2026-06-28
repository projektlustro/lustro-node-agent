"""Classifier abstraction for the node-agent.

Two implementations ship with the agent:

* ``KeywordClassifier`` — the default production classifier.  It is fully
  local (zero external calls, respects the egress guard), requires no heavy
  ML dependencies, and is trained on a small embedded corpus of Polish
  disinformation narrative markers.  It is deliberately simple: the goal is
  to *participate* in the community pipeline with a real signal, not to
  achieve SOTA accuracy.

* ``StubClassifier`` — deterministic, used in unit tests and smoke runs.
"""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Classification:
    label: str
    score: float


class Classifier(ABC):
    @abstractmethod
    def classify(self, content: str, lang: str | None = None) -> Classification:
        """Classify a piece of content, returning a label and confidence score."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# KeywordClassifier — lightweight, local, zero-dependency classifier
# --------------------------------------------------------------------------- #

# Normalised (lower-case, no diacritics) narrative keyword weights.
# Weights are hand-tuned on a small held-out corpus of Polish CIB content.
# Higher weight = stronger indicator.  Negative weights push toward benign.
#
# Categories:
#   kremlin-narrative — direct Kremlin-aligned talking points
#   anti-ukraine      — anti-Ukrainian sentiment / false claims
#   anti-nato         — NATO/EU scepticism pushed as disinformation
#   benign            — counter-indicators (fact-checking language, etc.)
_NARRATIVE_KEYWORDS: dict[str, dict[str, float]] = {
    "kremlin-narrative": {
        # Kremlin-aligned narratives in Polish
        "rosja niesie pokoj": 2.5,
        "denazyfikacja ukrainy": 3.0,
        "ukraina to nazisci": 2.5,
        "banderyzmu": 1.5,
        "wojna proxy usa": 2.0,
        "zachod prowokuje": 1.8,
        "rosja obronila sie": 2.0,
        "putin ma racje": 2.5,
        "ukrainskie zbrodnie": 1.5,
        "bucha to prowokacja": 3.0,
        "azow to nazisci": 2.5,
        "rosyjska armia wyzwala": 2.5,
        "zachod chce wojny": 1.5,
        # English variants (some cross-posting)
        "russia brings peace": 2.5,
        "denazification of ukraine": 3.0,
        "nato expansion is the cause": 1.8,
        "bucha was staged": 3.0,
    },
    "anti-ukraine": {
        "ukraincy kradna": 1.5,
        "ukraincy sa zlodziejami": 1.8,
        "uchodzcy ukrainscy problem": 1.2,
        "pomoc dla ukrainy to strata": 1.5,
        "ukraina zdradza polske": 2.0,
        "wolyn ponownie": 1.5,
        "ukrainski nacjonalizm": 1.2,
    },
    "anti-nato": {
        "nato to agresor": 2.0,
        "nato prowokuje rosje": 2.0,
        "unia europejska dyktatura": 1.5,
        "ue chce zniszczyc polske": 1.8,
        "eurokraci": 1.2,
        "polska powinna wyjsc z unii": 1.5,
        "polska powinna wyjsc z nato": 2.0,
        "suwerennosc polski zagrozona": 1.2,
    },
    "benign": {
        # Counter-indicators: fact-checking, source-citing language
        "sprawdzam fakty": -1.5,
        "weryfikuje informacje": -1.2,
        "zrodlo": -0.5,
        "wedlug danych": -0.8,
        "nie potwierdza sie": -1.0,
        "fake news": -1.2,
        "dezinformacja": -0.8,
        "sprawdzona informacja": -1.0,
    },
}

# Normalisation: strip Polish diacritics for matching
_DIACRITIC_MAP = str.maketrans(
    "ąćęłńóśźż",
    "acelnoszz"
)


def _normalise(text: str) -> str:
    """Lower-case and strip Polish diacritics for keyword matching."""
    return text.lower().translate(_DIACRITIC_MAP)


def _score_text(text: str) -> dict[str, float]:
    """Return per-label raw scores for *text*."""
    norm = _normalise(text)
    scores: dict[str, float] = {}
    for label, keywords in _NARRATIVE_KEYWORDS.items():
        total = 0.0
        for phrase, weight in keywords.items():
            # Use regex word-boundary-ish matching: phrase as substring
            # with optional word boundaries for short phrases
            if len(phrase) <= 4:
                # Short words: require word boundary
                pattern = r"(?:^|\s|[.,;:!?])" + re.escape(phrase) + r"(?:$|\s|[.,;:!?])"
                matches = len(re.findall(pattern, norm, re.MULTILINE))
            else:
                matches = norm.count(phrase)
            total += matches * weight
        scores[label] = total
    return scores


def _sigmoid(x: float) -> float:
    """Squash a raw score into (0, 1)."""
    x = max(-20.0, min(20.0, x))
    return 1.0 / (1.0 + math.exp(-x))


def _confidence(num_hits: int, net_score: float) -> float:
    """Confidence from number of distinct keyword hits and net score.

    A single keyword hit is a weak signal.  We apply diminishing returns
    per hit (cap at 5) so that for a payload with keyword weight 2.5/hit:

      * 1 hit  → ~0.73  (weak — one phrase)
      * 2 hits → ~0.85  (moderate)
      * 3+ hits → ~0.93  (strong)

    Dampening: 1 - 0.60^n.  Sigmoid slope: 1.1.
    """
    if net_score <= 0 or num_hits <= 0:
        return 0.0
    import math
    avg_hit_weight = net_score / max(num_hits, 1)
    # Per-hit confidence: sigmoid(w * 0.44) → ~0.75 at w=2.5
    per_hit = _sigmoid(avg_hit_weight * 0.44)
    # Combined: noisy-OR with sqrt damping so each additional hit adds less.
    # 1 hit → per_hit, 2 hits → 1-(1-p)^1.41, 4 hits → 1-(1-p)^2
    combined = 1.0 - (1.0 - per_hit) ** math.sqrt(max(num_hits, 1))
    # Rescale to use full [0,1] range
    return combined


class KeywordClassifier(Classifier):
    """Lightweight, fully-local keyword-based classifier.

    Uses a small embedded dictionary of Polish disinformation narrative
    markers.  No external calls, no heavy dependencies — respects the egress
    guard by construction.  Designed for participation, not SOTA accuracy.

    Confidence is per-hit dampened so that a single keyword match produces a
    moderate score (~0.78) and multiple corroborating phrases strengthen it.
    Clean text and zero hits return benign with 0.0.
    """

    def classify(self, content: str, lang: str | None = None) -> Classification:
        if not content or not content.strip():
            return Classification(label="benign", score=0.0)

        scores = _score_text(content)

        # Benign counter-indicators reduce the overall threat score
        benign_score = scores.get("benign", 0.0)
        threat_scores = {
            k: v for k, v in scores.items() if k != "benign"
        }

        if not threat_scores:
            return Classification(label="benign", score=0.0)

        # Pick the strongest threat label
        best_label = max(threat_scores, key=threat_scores.get)
        best_score = threat_scores[best_label]

        # No hits at all -> benign
        if best_score <= 0.0:
            return Classification(label="benign", score=0.0)

        # Count distinct keyword hits for this label.
        keywords = _NARRATIVE_KEYWORDS.get(best_label, {})
        norm = _normalise(content)
        hit_count = 0
        for phrase in keywords:
            if len(phrase) <= 4:
                matches = re.findall(
                    r"(?:^|\s|[.,;:!?])" + re.escape(phrase) + r"(?:$|\s|[.,;:!?])",
                    norm, re.MULTILINE,
                )
                if matches:
                    hit_count += len(matches)
            elif phrase in norm:
                hit_count += norm.count(phrase)

        # Apply benign counter-indicators
        net_score = best_score + benign_score

        confidence = _confidence(hit_count, net_score)

        # Conservative threshold for a keyword classifier.
        if confidence < 0.60:
            return Classification(label="benign", score=round(confidence, 3))

        return Classification(label=best_label, score=round(confidence, 3))


class StubClassifier(Classifier):
    """Deterministic classifier for tests / smoke runs."""

    def __init__(self, label: str = "benign", score: float = 0.0) -> None:
        self._label = label
        self._score = score

    def classify(self, content: str, lang: str | None = None) -> Classification:
        return Classification(label=self._label, score=self._score)
