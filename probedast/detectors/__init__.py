from .base import REGISTRY, Detector, register
from . import xss, sqli, traversal, idor, passive  # noqa: F401  (populate REGISTRY)

ALL_DETECTORS = list(REGISTRY.keys())
ENDPOINT_LEVEL = [name for name, cls in REGISTRY.items() if getattr(cls, "endpoint_level", False)]
PARAM_LEVEL = [name for name in ALL_DETECTORS if name not in ENDPOINT_LEVEL]


def instantiate(name: str, config=None):
    cls = REGISTRY[name]
    if name == "sqli_time" and config is not None:
        return cls(delay=config.time_delay, samples=config.time_samples)
    return cls()
