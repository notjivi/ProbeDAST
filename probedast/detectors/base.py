"""Detector plugin contract. One module per vulnerability class (design doc
Section 1.1 / 4.5). Each detector takes an endpoint + parameter, sends probes,
and returns zero or more Candidates — not findings. Only the Verification
Engine (verify.py) promotes a candidate to a finding.
"""
from __future__ import annotations
from abc import ABC, abstractmethod

REGISTRY: dict = {}


def register(name: str):
    def deco(cls):
        REGISTRY[name] = cls
        return cls
    return deco


class Detector(ABC):
    name: str = "base"
    applies_to_types: tuple = ()     # Param.type values this detector bothers probing; empty = all

    def applies(self, param) -> bool:
        return not self.applies_to_types or param.type in self.applies_to_types

    @abstractmethod
    async def run(self, client, endpoint, param, context) -> list:
        """Return a list of Candidate objects. `context` carries cookies,
        config and the baseline-building helper (see detectors/__init__.py)."""
        raise NotImplementedError
