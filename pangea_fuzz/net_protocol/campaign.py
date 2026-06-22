from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Iterator

from .catalog import NetFieldCatalog
from .case_generator import NetCaseGenerator, NetFuzzCase


DEFAULT_CASE_COUNT = 1_000
DEFAULT_RANDOM_RATIO = 0.10


@dataclass(frozen=True)
class NetCampaignConfig:
    seed: int
    count: int = DEFAULT_CASE_COUNT
    random_ratio: float = DEFAULT_RANDOM_RATIO


@dataclass(frozen=True)
class NetCampaignCase:
    campaign_index: int
    case: NetFuzzCase
    random_mutation: bool

    def to_dict(self) -> dict:
        data = self.case.to_dict()
        data["campaign_index"] = self.campaign_index
        data["random_mutation"] = self.random_mutation
        return data


class NetCampaignGenerator:
    def __init__(self, catalog: NetFieldCatalog):
        self.catalog = catalog
        self.case_generator = NetCaseGenerator(catalog)

    def iter_cases(self, config: NetCampaignConfig) -> Iterator[NetCampaignCase]:
        rng = random.Random(config.seed)
        random_count = int(round(config.count * config.random_ratio))
        random_indexes = set(rng.sample(range(config.count), random_count)) if random_count else set()
        protocols = self.catalog.protocols()
        for index in range(config.count):
            seed = rng.randrange(0, 2**63)
            random_mutation = index in random_indexes
            case = self.case_generator.generate(
                seed=seed,
                protocol=rng.choice(protocols),
                strategy="random_value" if random_mutation else None,
            )
            yield NetCampaignCase(index, case, random_mutation)

    def summary(self, config: NetCampaignConfig) -> dict:
        return {
            "seed": config.seed,
            "count": config.count,
            "random_ratio": config.random_ratio,
            "protocols": self.catalog.protocols(),
            "random_mutation_count": int(round(config.count * config.random_ratio)),
            "grammar_mutation_count": config.count - int(round(config.count * config.random_ratio)),
        }
