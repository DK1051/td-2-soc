"""Pytest fixture `kusto`: connect to the Kusto emulator, load the fixtures, hand back a client.

Environment variables:
  KUSTO_URL       where the emulator listens (default http://localhost:9000)
  KUSTO_REQUIRED  "1" = an unreachable emulator FAILS the tests (used by the `kql` CI job);
                  anything else = the tests that need it are SKIPPED, so the normal `checks`
                  job can never fail just because no emulator is running.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import kql_common

DEFAULT_URL = "http://localhost:9000"
PROBE_SECONDS = 5


def probe(url: str) -> str | None:
    """Ask the emulator `.show cluster`. Returns None if it answers HTTP 200, else a short reason."""
    request = urllib.request.Request(
        f"{url.rstrip('/')}/v1/rest/mgmt",
        data=json.dumps({"csl": ".show cluster"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=PROBE_SECONDS) as response:
            return None if response.status == 200 else f"HTTP {response.status}"
    except urllib.error.HTTPError as error:
        return f"HTTP {error.code}"
    except (urllib.error.URLError, OSError, ValueError) as error:
        return type(error).__name__


@pytest.fixture(scope="session")
def kusto():
    """A KustoClient on a database freshly loaded with fixtures/signin.jsonl and audit.jsonl."""
    url = os.environ.get("KUSTO_URL", DEFAULT_URL)
    problem = probe(url)
    if problem is not None:
        message = f"Kusto emulator unreachable at {url} ({problem})"
        if os.environ.get("KUSTO_REQUIRED") == "1":
            pytest.fail(f"{message}; KUSTO_REQUIRED=1 so this is a failure, not a skip", pytrace=False)
        pytest.skip(f"{message}; skipping (set KUSTO_REQUIRED=1 to fail instead)")
    client = kql_common.connect(url)
    # load_data re-creates the database, ingests both files and raises if a row count differs
    # from the number of lines in the file, so no test ever runs on partly loaded data.
    kql_common.load_data(client, REPO / "fixtures")
    return client
