"""USD prices per million tokens, for cost visibility per scan.

Anthropic first-party API rates as of 2026-06-24. Cache writes (5-minute TTL) cost
1.25x input, cache reads 0.1x. Unknown models are priced at 0 and flagged.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPrice:
    input_per_mtok: float
    output_per_mtok: float


PRICES: dict[str, ModelPrice] = {
    "claude-fable-5-1": ModelPrice(10.0, 50.0),
    "claude-fable-5": ModelPrice(10.0, 50.0),
    "claude-opus-5": ModelPrice(5.0, 25.0),
    "claude-opus-4-8": ModelPrice(5.0, 25.0),
    "claude-opus-4-7": ModelPrice(5.0, 25.0),
    "claude-opus-4-6": ModelPrice(5.0, 25.0),
    "claude-sonnet-5": ModelPrice(2.0, 10.0),
    "claude-sonnet-4-6": ModelPrice(3.0, 15.0),
    "claude-haiku-4-5": ModelPrice(1.0, 5.0),
}
CACHE_WRITE_MULTIPLIER = 1.25
CACHE_READ_MULTIPLIER = 0.1


def is_priced(model: str) -> bool:
    return model in PRICES


def cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_creation_input_tokens: int = 0,
    cache_read_input_tokens: int = 0,
) -> float:
    price = PRICES.get(model)
    if price is None:
        return 0.0
    total = (
        input_tokens * price.input_per_mtok
        + cache_creation_input_tokens * price.input_per_mtok * CACHE_WRITE_MULTIPLIER
        + cache_read_input_tokens * price.input_per_mtok * CACHE_READ_MULTIPLIER
        + output_tokens * price.output_per_mtok
    )
    return round(total / 1_000_000, 6)
