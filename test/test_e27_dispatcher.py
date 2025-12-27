import pytest

from elke27_lib.dispatcher import (
    Dispatcher,
    PendingRequest,
    MessageKind,
    ERROR_DOMAIN,
    ERROR_ALL,
    ERR_ROOT_EMPTY,
    ERR_ROOT_MULTI,
    ERR_DOMAIN_EMPTY,
    ERR_DOMAIN_MULTI,
    ERR_UNEXPECTED_VALUE_TYPE,
    ERR_INVALID_SEQ,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class Recorder:
    def __init__(self):
        self.calls = []

    def handler(self, msg, ctx):
        self.calls.append((msg, ctx))
        return True


# ---------------------------------------------------------------------------
# routing tests
# ---------------------------------------------------------------------------

def test_simple_domain_and_command_route():
    d = Dispatcher()
    r = Recorder()
    d.register(("zone", "status"), r.handler)

    msg = {"zone": {"status": {"id": 1}}, "seq": 1}
    result = d.dispatch(msg)

    assert result.route == ("zone", "status")
    assert result.kind == MessageKind.DIRECTED
    assert result.classification == "UNSOLICITED"
    assert result.handled is True
    assert len(result.errors) == 0
    assert len(r.calls) == 1


def test_domain_empty_dict_routes_to_empty_and_emits_error():
    d = Dispatcher()
    r = Recorder()
    e = Recorder()

    d.register(("zone", "__root__"), r.handler)
    d.register((ERROR_DOMAIN, ERR_DOMAIN_EMPTY), e.handler)

    msg = {"zone": {}, "seq": 1}
    result = d.dispatch(msg)

    assert result.route == ("zone", "__empty__")
    assert any(err.code == ERR_DOMAIN_EMPTY for err in result.errors)
    assert len(r.calls) == 1
    assert len(e.calls) == 1


def test_domain_multi_key_routes_to_root():
    d = Dispatcher()
    r = Recorder()

    d.register(("zone", "__root__"), r.handler)

    msg = {"zone": {"a": 1, "b": 2}, "seq": 1}
    result = d.dispatch(msg)

    assert result.route == ("zone", "__root__")
    assert any(err.code == ERR_DOMAIN_MULTI for err in result.errors)
    assert len(r.calls) == 1


def test_domain_unexpected_value_type():
    d = Dispatcher()
    r = Recorder()

    d.register(("zone", "__root__"), r.handler)

    msg = {"zone": True, "seq": 1}
    result = d.dispatch(msg)

    assert result.route == ("zone", "__value__")
    assert any(err.code == ERR_UNEXPECTED_VALUE_TYPE for err in result.errors)
    assert len(r.calls) == 1


def test_root_empty():
    d = Dispatcher()
    e = Recorder()

    d.register((ERROR_DOMAIN, ERR_ROOT_EMPTY), e.handler)

    msg = {"seq": 1}
    result = d.dispatch(msg)

    assert result.route == ("__root__", "__empty__")
    assert any(err.code == ERR_ROOT_EMPTY for err in result.errors)
    assert len(e.calls) == 1


def test_root_multi_domain():
    d = Dispatcher()
    e = Recorder()

    d.register((ERROR_DOMAIN, ERR_ROOT_MULTI), e.handler)

    msg = {"zone": {}, "area": {}, "seq": 1}
    result = d.dispatch(msg)

    assert result.route == ("__root__", "__multi__")
    assert any(err.code == ERR_ROOT_MULTI for err in result.errors)
    assert len(e.calls) == 1


# ---------------------------------------------------------------------------
# seq + classification tests
# ---------------------------------------------------------------------------

def test_missing_seq_is_unknown_without_error():
    d = Dispatcher()
    r = Recorder()
    d.register(("zone", "status"), r.handler)

    msg = {"zone": {"status": {}}}
    result = d.dispatch(msg)

    assert result.kind == MessageKind.UNKNOWN
    assert result.classification == "UNKNOWN"
    assert len(result.errors) == 0


def test_broadcast_seq_zero():
    d = Dispatcher()
    r = Recorder()
    d.register(("zone", "status"), r.handler)

    msg = {"zone": {"status": {}}, "seq": 0}
    result = d.dispatch(msg)

    assert result.kind == MessageKind.BROADCAST
    assert result.classification == "BROADCAST"
    assert len(r.calls) == 1


def test_invalid_seq_type_emits_error():
    d = Dispatcher()
    e = Recorder()

    d.register((ERROR_DOMAIN, ERR_INVALID_SEQ), e.handler)

    msg = {"zone": {"status": {}}, "seq": "abc"}
    result = d.dispatch(msg)

    assert any(err.code == ERR_INVALID_SEQ for err in result.errors)
    assert len(e.calls) == 1


def test_negative_seq_emits_error_and_unknown():
    d = Dispatcher()
    e = Recorder()

    d.register((ERROR_DOMAIN, ERR_INVALID_SEQ), e.handler)

    msg = {"zone": {"status": {}}, "seq": -1}
    result = d.dispatch(msg)

    assert result.kind == MessageKind.UNKNOWN
    assert any(err.code == ERR_INVALID_SEQ for err in result.errors)
    assert len(e.calls) == 1


# ---------------------------------------------------------------------------
# pending correlation tests
# ---------------------------------------------------------------------------

def test_pending_request_is_matched_and_popped():
    d = Dispatcher()
    r = Recorder()

    d.register(("zone", "status"), r.handler)

    pending = PendingRequest(seq=42)
    d.add_pending(pending)

    msg = {"zone": {"status": {}}, "seq": 42}
    result = d.dispatch(msg)

    assert result.classification == "RESPONSE"
    assert result.response_match is pending
    assert d.match_pending(42, pop=False) is None


def test_directed_without_pending_is_unsolicited():
    d = Dispatcher()

    msg = {"zone": {"status": {}}, "seq": 99}
    result = d.dispatch(msg)

    assert result.classification == "UNSOLICITED"


# ---------------------------------------------------------------------------
# error envelope tests
# ---------------------------------------------------------------------------

def test_error_envelope_shape_and_raw_route():
    d = Dispatcher()
    e = Recorder()

    d.register((ERROR_DOMAIN, ERR_DOMAIN_EMPTY), e.handler)
    d.register((ERROR_DOMAIN, ERROR_ALL), e.handler)

    msg = {"zone": {}, "seq": 5}
    result = d.dispatch(msg)

    assert len(e.calls) == 2

    err_msg, ctx = e.calls[0]

    assert ERROR_DOMAIN in err_msg
    code = list(err_msg[ERROR_DOMAIN].keys())[0]
    payload = err_msg[ERROR_DOMAIN][code]

    assert payload["message"]
    assert payload["domain"] == "zone"
    assert payload["severity"]
    assert ctx.raw_route == ("zone", "__empty__")
    assert ctx.route == (ERROR_DOMAIN, ERR_DOMAIN_EMPTY)


# ---------------------------------------------------------------------------
# handler isolation
# ---------------------------------------------------------------------------

def test_handler_exception_does_not_break_dispatch():
    d = Dispatcher()
    good = Recorder()

    def bad_handler(msg, ctx):
        raise RuntimeError("boom")

    d.register(("zone", "status"), bad_handler)
    d.register(("zone", "status"), good.handler)

    msg = {"zone": {"status": {}}, "seq": 1}
    result = d.dispatch(msg)

    assert result.handled is True
    assert len(good.calls) == 1
