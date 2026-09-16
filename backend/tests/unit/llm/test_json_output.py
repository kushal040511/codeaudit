from typing import Literal

import pytest
from pydantic import BaseModel

from app.services.llm.json_output import OutputParseError, extract_json_text, parse_model_output


class Fix(BaseModel):
    confidence: Literal["high", "medium", "low"]
    patch: str


@pytest.mark.parametrize(
    "text",
    [
        '{"confidence": "high", "patch": ""}',
        '```json\n{"confidence": "high", "patch": ""}\n```',
        '```\n{"confidence": "high", "patch": ""}\n```',
        'Here is the fix:\n```json\n{"confidence": "high", "patch": ""}\n```\nLet me know!',
        'Sure. {"confidence": "high", "patch": ""} Hope that helps.',
        '﻿  {"confidence": "high", "patch": "",}  ',  # BOM, trailing comma
        "{“confidence”: “high”, “patch”: “”}",  # smart quotes
    ],
)
def test_recovers_json_from_fenced_or_noisy_output(text: str) -> None:
    assert parse_model_output(text, Fix) == Fix(confidence="high", patch="")


def test_patch_containing_backticks_survives_fence_stripping() -> None:
    diff = "--- a/x.md\\n+++ b/x.md\\n@@ -1 +1 @@\\n-`a`\\n+`b`\\n"
    text = '```json\n{"confidence": "low", "patch": "' + diff + '"}\n```'

    assert parse_model_output(text, Fix).patch.endswith("+`b`\n")


def test_schema_violation_is_reported_with_the_field() -> None:
    with pytest.raises(OutputParseError, match=r"schema validation failed: confidence"):
        parse_model_output('{"confidence": "certain", "patch": ""}', Fix)


@pytest.mark.parametrize(
    "text", ["", "I can't help with that.", '{"confidence": "high", "patch": ']
)
def test_unparsable_output_raises(text: str) -> None:
    with pytest.raises(OutputParseError):
        parse_model_output(text, Fix)


def test_extract_prefers_fenced_block() -> None:
    assert extract_json_text('note {x}\n```json\n{"a": 1}\n```') == '{"a": 1}'
