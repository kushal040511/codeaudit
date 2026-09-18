import pytest

from app.main import load


def test_load_missing() -> None:
    with pytest.raises(OSError):
        load("/nonexistent")
