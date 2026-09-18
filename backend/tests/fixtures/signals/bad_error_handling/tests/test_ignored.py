"""Test files are excluded entirely: nothing here may be counted."""


def test_bare():
    try:
        open("x")
    except:
        pass
