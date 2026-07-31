"""Local, artifact-backed classifiers for the node-agent.

Production inference is deliberately model-only.  A missing, malformed, or
checksum-mismatched artifact is an error; the agent never silently degrades to
keywords or a stub.  ``StubClassifier`` remains available exclusively for the
offline protocol tests.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Classification:
    label: str
    score: float


class Classifier(ABC):
    @abstractmethod
    def classify(self, content: str, lang: str | None = None) -> Classification:
        raise NotImplementedError


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lexical_features(text: str, source_name: str = "") -> list[float]:
    """Keep the eight auxiliary features identical to the training pipeline."""
    words = re.findall(r"\w+", text, re.UNICODE)
    word_count = max(len(words), 1)
    upper_count = sum(1 for char in text if char.isupper())
    alpha_count = max(sum(1 for char in text if char.isalpha()), 1)
    source = source_name.lower()
    lowered = text.lower()
    return [
        min(len(text), 5000) / 5000,
        min(word_count, 1000) / 1000,
        min(text.count("!"), 10) / 10,
        min(text.count("?"), 10) / 10,
        upper_count / alpha_count,
        min(len(re.findall(r"https?://\S+", text, re.IGNORECASE)), 10) / 10,
        1.0 if any(token in source for token in ("wrealu", "newsfront", "zmianynaziemi", "wolnemedia")) else 0.0,
        1.0 if any(token in lowered for token in ("ukraina", "nato", "bruksela", "gaz", "prad", "prąd")) else 0.0,
    ]


class ModelClassifier(Classifier):
    """Run the signed multilingual E5 + classifier artifact locally."""

    def __init__(self, model_root: str | Path | None = None) -> None:
        raw_root = model_root or os.environ.get("LUSTRO_NODE_MODEL_ROOT")
        if not raw_root:
            raise RuntimeError("LUSTRO_NODE_MODEL_ROOT is required; model-only mode has no fallback")
        self.model_root = Path(raw_root)

        self.card = self._read_json("model_card.json")
        self.embedding_model = self._read_json("embedder_config.json").get("embedding_model")
        if not self.embedding_model:
            raise RuntimeError("model artifact has no embedding_model")
        self.feature_config = self._read_json("feature_config.json") if (self.model_root / "feature_config.json").exists() else {}
        self.calibration = self._read_json("calibration.json") if (self.model_root / "calibration.json").exists() else {}

        classifier_path = self.model_root / "disinfo_classifier.joblib"
        expected = (self.card.get("checksums") or {}).get(classifier_path.name)
        if not expected:
            raise RuntimeError("model card has no classifier checksum")
        if _sha256(classifier_path) != expected:
            raise RuntimeError("model classifier checksum mismatch")

        try:
            import joblib
            from fastembed import TextEmbedding
        except ImportError as exc:
            raise RuntimeError(f"model runtime dependency missing: {exc}") from exc

        cache_dir = os.environ.get("LUSTRO_NODE_EMBED_CACHE")
        if not cache_dir:
            raise RuntimeError("LUSTRO_NODE_EMBED_CACHE is required; model weights must be preloaded")
        if not Path(cache_dir).exists():
            raise RuntimeError(f"embedding cache is missing: {cache_dir}")
        self._embedder = TextEmbedding(
            model_name=self.embedding_model,
            cache_dir=cache_dir,
            local_files_only=True,
        )
        self._classifier = joblib.load(classifier_path)
        self.model_version = str(self.card.get("model_version") or "unknown")
        thresholds = self.calibration.get("thresholds_by_language") or {}
        self._thresholds = {
            key: float(value["threshold"])
            for key, value in thresholds.items()
            if isinstance(value, dict) and "threshold" in value
        }
        self._threshold = float(self.calibration.get("is_disinformation_threshold", 0.6))

    def _read_json(self, name: str) -> dict[str, Any]:
        path = self.model_root / name
        if not path.exists():
            raise RuntimeError(f"model artifact missing: {path}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid model artifact metadata: {path}") from exc
        if not isinstance(value, dict):
            raise RuntimeError(f"model artifact metadata must be an object: {path}")
        return value

    def classify(self, content: str, lang: str | None = None) -> Classification:
        if not content or not content.strip():
            return Classification(label="unverified", score=0.5)

        vector = next(self._embedder.embed([f"query: {content}" ]))
        try:
            import numpy as np
            embedding = np.asarray([list(vector)], dtype="float32")
            if self.feature_config.get("include_lexical_features", True):
                lexical = np.asarray([_lexical_features(content)], dtype="float32")
                matrix = np.hstack([embedding, lexical])
            else:
                matrix = embedding
            if hasattr(self._classifier, "predict_proba"):
                probability = float(self._classifier.predict_proba(matrix)[0, -1])
            elif hasattr(self._classifier, "decision_function"):
                score = float(self._classifier.decision_function(matrix)[0])
                probability = 1.0 / (1.0 + math.exp(-score))
            else:
                probability = float(self._classifier.predict(matrix)[0])
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"model inference failed: {type(exc).__name__}") from exc

        threshold = self._thresholds.get((lang or "").split("-", 1)[0], self._threshold)
        label = "misinformation" if probability >= threshold else "factual"
        return Classification(label=label, score=round(max(0.0, min(1.0, probability)), 3))


class StubClassifier(Classifier):
    """Deterministic classifier used only by offline protocol tests."""

    def __init__(self, label: str = "factual", score: float = 0.0) -> None:
        self._label = label
        self._score = score

    def classify(self, content: str, lang: str | None = None) -> Classification:
        return Classification(label=self._label, score=self._score)
