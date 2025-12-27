from __future__ import annotations

from elke27_lib.handlers.zone import _reconcile_bulk_zone_status
from elke27_lib.states import PanelState


def test_zone_status_string_updates_zone_state() -> None:
    state = PanelState()
    payload = {"status": "1A4"}

    outcome = _reconcile_bulk_zone_status(state, payload, now=1.0)

    assert outcome.updated_ids == (1, 2, 3)

    z1 = state.zones[1]
    assert z1.status_code == "1"
    assert z1.enabled is True
    assert z1.violated is False
    assert z1.trouble is False
    assert z1.bypassed is False

    z2 = state.zones[2]
    assert z2.status_code == "A"
    assert z2.enabled is True
    assert z2.violated is True
    assert z2.trouble is False
    assert z2.bypassed is False

    z3 = state.zones[3]
    assert z3.status_code == "4"
    assert z3.enabled is False
    assert z3.violated is False
    assert z3.trouble is False
    assert z3.bypassed is False
