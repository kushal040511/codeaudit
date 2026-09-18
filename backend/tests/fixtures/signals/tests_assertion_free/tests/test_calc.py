import unittest
from unittest import mock

import pytest

from src.calc import add, divide


def assert_positive(value):
    assert value > 0


def test_add():
    assert add(1, 2) == 3
    assert add(0, 0) == 0


def test_add_runs():
    add(1, 2)


def test_uses_helper():
    assert_positive(add(1, 2))


def test_divide_by_zero():
    with pytest.raises(ZeroDivisionError):
        divide(1, 0)


@pytest.mark.parametrize("a", [1, 2])
def test_param_smoke(a):
    add(a, a)


def test_mock_called():
    m = mock.Mock()
    m(1)
    m.assert_called_once_with(1)


class TestCalc:
    def test_method_no_assert(self):
        result = add(2, 2)
        print(result)

    def helper(self):
        return 1


class CalcCase(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(add(1, 1), 2)
        self.assertTrue(add(1, 1))
