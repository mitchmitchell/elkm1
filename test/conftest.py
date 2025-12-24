# test/conftest.py

import pytest
from pathlib import Path
from test.helpers.reporter import Reporter
from elkm1_lib.notify import Notifier

def pytest_addoption(parser):
    parser.addoption("--e27-live", action="store_true")
    parser.addoption("--e27-report", choices=["jsonl", "yaml", "both"], default="jsonl")

@pytest.fixture
def notifier():
    return Notifier()

@pytest.fixture
def reporter(request, pytestconfig, tmp_path):
    emit_yaml = pytestconfig.getoption("--e27-report") in ("yaml", "both")
    r = Reporter(
        test_name=request.node.name,
        artifacts_dir=Path("artifacts/test_runs"),
        emit_yaml=emit_yaml,
    )
    yield r
    outcome = getattr(request.node.rep_call, "outcome", "unknown")
    r.finalize(outcome)

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)
