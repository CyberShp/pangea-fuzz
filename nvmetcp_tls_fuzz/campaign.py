from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Iterator

from .case_generator import CaseGenerator, FuzzCase
from .catalog import FieldCatalog


DEFAULT_CASE_COUNT = 1_500_000
DEFAULT_RANDOM_RATIO = 0.10


@dataclass(frozen=True)
class CampaignConfig:
    seed: int
    count: int = DEFAULT_CASE_COUNT
    random_ratio: float = DEFAULT_RANDOM_RATIO
    directions: tuple[str, ...] = ("host", "target", "both")
    commands: tuple[str, ...] = ("connect", "identify", "read", "write", "flush")

    def validate(self) -> None:
        if self.count <= 0:
            raise ValueError("campaign count must be positive")
        if not 0.0 <= self.random_ratio <= 1.0:
            raise ValueError("random_ratio must be between 0.0 and 1.0")
        if not self.directions:
            raise ValueError("campaign directions must not be empty")
        if not self.commands:
            raise ValueError("campaign commands must not be empty")


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
    """Streaming generator for large fuzz campaigns.

    A 1.5M-case campaign is intentionally yielded item by item so callers can
    pipe to JSONL, enqueue jobs, or stop at the first interesting failure
    without materializing millions of case objects.
    """

    def __init__(self, catalog: FieldCatalog):
        self.catalog = catalog
        self.case_generator = CaseGenerator(catalog)

    def iter_cases(self, config: CampaignConfig) -> Iterator[CampaignCase]:
        config.validate()
        rng = random.Random(config.seed)
        random_budget = int(round(config.count * config.random_ratio))
        random_indexes = set(rng.sample(range(config.count), random_budget)) if random_budget else set()
        pdu_types = self.catalog.pdu_types()

        for index in range(config.count):
            random_mutation = index in random_indexes
            case_seed = rng.randrange(0, 2**63)
            direction = rng.choice(config.directions)
            pdu_type = rng.choice(pdu_types)
            command = rng.choice(config.commands)
            strategy = "random_value" if random_mutation else None

            try:
                case = self.case_generator.generate(
                    seed=case_seed,
                    direction=direction,
                    pdu_type=pdu_type,
                    command=command,
                    strategy=strategy,
                )
            except ValueError:
                case = self.case_generator.generate(
                    seed=case_seed,
                    direction="both",
                    pdu_type=pdu_type,
                    command=command,
                    strategy=strategy,
                )
            yield CampaignCase(index, case, random_mutation)

    def summary(self, config: CampaignConfig) -> dict:
        config.validate()
        return {
            "seed": config.seed,
            "count": config.count,
            "random_ratio": config.random_ratio,
            "random_mutation_count": int(round(config.count * config.random_ratio)),
            "grammar_mutation_count": config.count - int(round(config.count * config.random_ratio)),
            "directions": list(config.directions),
            "commands": list(config.commands),
            "pdu_types": self.catalog.pdu_types(),
        }
