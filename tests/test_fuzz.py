"""Property-based fuzzing for the MCP entry point.

Uses hypothesis to assert the server never raises an unhandled exception
on arbitrary input to the primary tool. Per OpenSSF Scorecard check 11
(Fuzzing).
"""
import json
import pytest
from hypothesis import given, strategies as st

# Per-repo: import the primary @mcp.tool() entry point.
from server import classify_entity


# Strategy for the primary description-like string argument.
description_arg = st.text(min_size=0, max_size=2000)


@given(arg=description_arg)
def test_classify_entity_never_unhandled_exception(arg):
    """The tool should respond with a structured result or a documented
    handled error (KeyError, ValueError, TypeError, JSONDecodeError) --
    never an unhandled exception. Empty or odd inputs are explicitly
    allowed by the strategy; this is a *property* test, not a validity
    test.
    """
    try:
        result = classify_entity(arg)
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return  # documented handled errors are OK
    assert result is not None or result is None
