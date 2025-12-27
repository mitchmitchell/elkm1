from __future__ import annotations

from elke27_lib.handlers.area import make_area_get_status_handler
from elke27_lib.states import PanelState
from elke27_lib.events import ApiError, AreaStatusUpdated


class _EmitSpy:
    def __init__(self) -> None:
        self.events = []

    def __call__(self, evt, ctx) -> None:
        self.events.append(evt)


class _Ctx:
    pass


def test_area_get_status_updates_state_and_emits_event() -> None:
    state = PanelState()
    emit = _EmitSpy()
    handler = make_area_get_status_handler(state, emit, now=lambda: 123.0)

    msg = {
        "area": {
            "get_status": {
                "area_id": 1,
                "arm_state": "armed",
                "ready_status": "ready",
                "alarm_state": "none",
                "error_code": 0,
            }
        }
    }

    assert handler(msg, _Ctx()) is True
    area = state.areas[1]
    assert area.arm_state == "armed"
    assert area.ready_status == "ready"
    assert area.alarm_state == "none"
    assert any(isinstance(e, AreaStatusUpdated) for e in emit.events)


def test_area_get_status_error_code_emits_api_error() -> None:
    state = PanelState()
    emit = _EmitSpy()
    handler = make_area_get_status_handler(state, emit, now=lambda: 123.0)

    msg = {"area": {"get_status": {"area_id": 1, "error_code": 7}}}

    assert handler(msg, _Ctx()) is True
    assert any(isinstance(e, ApiError) for e in emit.events)
