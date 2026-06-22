from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Iterator

from .case_generator import CaseGenerator, FuzzCase, KV_OPCODES
from .catalog import FieldCatalog


DEFAULT_CASE_COUNT = 1_500_000
DEFAULT_RANDOM_RATIO = 0.10


@dataclass(frozen=True)
class CampaignConfig:
    seed: int
    count: int = DEFAULT_CASE_COUNT
    random_ratio: float = DEFAULT_RANDOM_RATIO
    operations: tuple[str, ...] = tuple(KV_OPCODES.keys())

    def validate(self) -> None:
        if self.count <= 0:
            raise ValueError("campaign count must be positive")
        if not 0.0 <= self.random_ratio <= 1.0:
            raise ValueError("random_ratio must be between 0.0 and 1.0")
        if not self.operations:
            raise ValueError("operations must not be empty")


@dataclass(frozen=True)
class CampaignCase:
    campaign_index: int
    case: FuzzCase
    random_mutation: bool

    def to_dict(self) -> dict:
        data = self.case.to_dict()
        data["campaign_index"] = self.campaign_index
        data["random_mutation"] = self.random_mutation
        return data


class CampaignGenerator:
    def __init__(self, catalog: FieldCatalog, *, key_prefix: str = "kvfuzz-", nsid: int = 1):
        self.catalog = catalog
        self.case_generator = CaseGenerator(catalog, key_prefix=key_prefix, nsid=nsid)

    def iter_cases(self, config: CampaignConfig) -> Iterator[CampaignCase]:
        config.validate()
        rng = random.Random(config.seed)
        random_budget = int(round(config.count * config.random_ratio))
        random_indexes = set(rng.sample(range(config.count), random_budget)) if random_budget else set()
        strategies = self.catalog.strategies()
        for index in range(config.count):
            random_mutation = index in random_indexes
            case_seed = rng.randrange(0, 2**63)
            operation = rng.choice(config.operations)
            strategy = "random_value" if random_mutation else rng.choice(strategies)
            yield CampaignCase(
                campaign_index=index,
                case=self.case_generator.generate(seed=case_seed, operation=operation, strategy=strategy),
                random_mutation=random_mutation,
            )

    def summary(self, config: CampaignConfig) -> dict:
        config.validate()
        random_count = int(round(config.count * config.random_ratio))
        return {
            "seed": config.seed,
            "count": config.count,
            "random_ratio": config.random_ratio,
            "random_mutation_count": random_count,
            "grammar_mutation_count": config.count - random_count,
            "operations": list(config.operations),
            "fields": self.catalog.field_paths(),
            "strategies": self.catalog.strategies(),
        }
