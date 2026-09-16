"""Defensive parsing of JSON the model was asked to return."""

import json
import re

from pydantic import BaseModel, ValidationError

_FENCE = re.compile(r"```(?:json|JSON)?\s*\n?(.*?)\n?\s*```", re.DOTALL)


class OutputParseError(ValueError):
    """The response isn't valid JSON for the expected schema."""


def extract_json_text(text: str) -> str:
    """The JSON object in a response: fenced block, bare object, or prose around an object."""
    stripped = text.strip().lstrip("﻿")
    if match := _FENCE.search(stripped):
        return match.group(1).strip()
    if stripped.startswith(("{", "[")):
        return stripped
    start, end = stripped.find("{"), stripped.rfind("}")
    if start != -1 and end > start:
        return stripped[start : end + 1]
    return stripped


def _repair(text: str) -> str:
    """Conservative fixes for common near-JSON: trailing commas and smart quotes."""
    repaired = re.sub(r",(\s*[}\]])", r"\1", text)
    return repaired.replace("“", '"').replace("”", '"')


def parse_model_output[T: BaseModel](text: str, schema: type[T]) -> T:
    candidate = extract_json_text(text)
    errors: list[str] = []
    for attempt in (candidate, _repair(candidate)):
        try:
            data = json.loads(attempt)
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}")
            continue
        try:
            return schema.model_validate(data)
        except ValidationError as exc:
            details = "; ".join(
                f"{'.'.join(map(str, e['loc'])) or '<root>'}: {e['msg']}" for e in exc.errors()[:10]
            )
            raise OutputParseError(f"schema validation failed: {details}") from exc
    raise OutputParseError(errors[-1] if errors else "empty response")
