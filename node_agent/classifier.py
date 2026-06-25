"""Classifier abstraction for the node-agent.

The volunteer runs a `Classifier`. The stub returns a fixed label/score so the
plumbing (pull WU -> verify -> classify -> sign -> POST result) can be exercised
end-to-end without any model weights.
"""

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


class StubClassifier(Classifier):
    """Deterministic classifier for tests / smoke runs."""

    def __init__(self, label: str = "benign", score: float = 0.0) -> None:
        self._label = label
        self._score = score

    def classify(self, content: str, lang: str | None = None) -> Classification:
        return Classification(label=self._label, score=self._score)
