"""Hermetic test environment.

auth_middleware persists per-day usage counters and PAYG balances under
~/.meok (machine-global, file-backed). Without isolation the suite:
  (a) inherits whatever quota the developer's real machine has already burned, and
  (b) self-rate-limits — 40+ anonymous tool calls per run exceed the 10/day cap.

Redirect HOME to a temp dir BEFORE server/auth_middleware import (their paths are
computed at import time via expanduser), and wipe the usage state between tests.
This also forces the deterministic in-repo auth_middleware fallback (the
~/clawd/meok-labs-engine path no longer exists under the temp HOME).
"""
import os
import shutil
import tempfile

import pytest

_TMP_HOME = tempfile.mkdtemp(prefix="meok-test-home-")
os.environ["HOME"] = _TMP_HOME
os.environ.pop("MEOK_PAYG_KEY", None)   # never let a real PAYG key leak into tests
os.environ.pop("X402_ENABLED", None)    # x402 stays off unless a test enables it


@pytest.fixture(autouse=True)
def _fresh_usage_state():
    """Each test starts with a clean ~/.meok (usage counters + PAYG balances)."""
    shutil.rmtree(os.path.join(_TMP_HOME, ".meok"), ignore_errors=True)
    yield
