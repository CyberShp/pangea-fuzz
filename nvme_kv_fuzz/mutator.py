from __future__ import annotations

from .catalog import FieldCatalog
from .case_generator import CaseGenerator, FuzzCase


class MutationEngine:
    """Small facade kept separate so deeper mutators can replace generation later."""

    def __init__(self, catalog: FieldCatalog, *, key_prefix: str = "kvfuzz-", nsid: int = 1):
        self.generator = CaseGenerator(catalog, key_prefix=key_prefix, nsid=nsid)

    def mutate(self, *, seed: int, operation: str | None = None, strategy: str | None = None) -> FuzzCase:
        return self.generator.generate(seed=seed, operation=operation, strategy=strategy)
