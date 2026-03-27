import os
import pytest


def integration_enabled() -> bool:
    return os.environ.get("TESTSSL_INTEGRATION") == "1"


@pytest.fixture
def integration():
    """Fixture that skips the test if TESTSSL_INTEGRATION=1 is not set."""
    if not integration_enabled():
        pytest.skip("Set TESTSSL_INTEGRATION=1 to run network integration tests")
