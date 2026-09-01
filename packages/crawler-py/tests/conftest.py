from __future__ import annotations

import pytest

from tests.helpers import FixtureServer


@pytest.fixture
def fx():
    server = FixtureServer()
    server.start()
    yield server
    server.stop()
