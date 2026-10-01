"""OSIRIS-CANONICAL-JSON-V1 is a strict subset of RFC 8785 (JCS).

Checked against the independent `rfc8785` package (dev extra): every value the OSIRIS profile
accepts must serialize to exactly the bytes RFC 8785 produces. Values it rejects are allowed to
be anything RFC 8785 accepts; the profile is narrower on purpose.
"""

import hashlib
import random

import pytest

from osiris_governance.canonical import JCS_SAFE_INTEGER_MAX, canonicalize_json
from osiris_governance.errors import SchemaValidationError

rfc8785 = pytest.importorskip("rfc8785")


def _osiris_or_none(value):
    try:
        return canonicalize_json(value)
    except SchemaValidationError:
        return None


# Worked example from the C-000125 closure design notes, step 1 -> step 2 (2026-10-01).
CLOSURE_EXAMPLE = {
    "schema_version": "1.0",
    "document_type": "OSIRIS_CLAIM_CLOSURE",
    "claim_id": "C-000125",
    "experiment_id": "THETA_SWEEP_W2_PCAR_v1",
    "created_at": "2026-10-01T14:26:00Z",
    "claim_adjudication": {
        "evidence_status": "EXPLORATORY_EMPIRICAL",
        "claim_ceiling": "BOUNDED_EXPLORATORY_OBSERVATION",
        "decision": "CLAIM_ALLOWED",
    },
    "authority_decisions": {
        "execution_decision": "BLOCK",
        "release_decision": "HOLD",
        "customer_claim_allowed": False,
    },
}
CLOSURE_EXAMPLE_CANONICAL = (
    b'{"authority_decisions":{"customer_claim_allowed":false,"execution_decision":"BLOCK",'
    b'"release_decision":"HOLD"},"claim_adjudication":{"claim_ceiling":'
    b'"BOUNDED_EXPLORATORY_OBSERVATION","decision":"CLAIM_ALLOWED","evidence_status":'
    b'"EXPLORATORY_EMPIRICAL"},"claim_id":"C-000125","created_at":"2026-10-01T14:26:00Z",'
    b'"document_type":"OSIRIS_CLAIM_CLOSURE","experiment_id":"THETA_SWEEP_W2_PCAR_v1",'
    b'"schema_version":"1.0"}'
)


def test_closure_example_matches_both_implementations():
    assert canonicalize_json(CLOSURE_EXAMPLE) == CLOSURE_EXAMPLE_CANONICAL
    assert rfc8785.dumps(CLOSURE_EXAMPLE) == CLOSURE_EXAMPLE_CANONICAL
    assert hashlib.sha256(CLOSURE_EXAMPLE_CANONICAL).hexdigest() == (
        "01fa4fee71298b21319d1a41f27e4a7507ccf4112279b2efd6186a7c2c3837af"
    )


@pytest.mark.parametrize(
    "value",
    [
        {"s": 'quote " backslash \\ tab \t newline \n return \r'},
        {"s": "\u00e9 \u03b8 W\u2082 \U0001F600 \u2028 \u2029 \x7f"},
        {"nested": [{"z": 1, "a": [True, False, None]}, [], {}], "a": ""},
        {"n": [JCS_SAFE_INTEGER_MAX, -JCS_SAFE_INTEGER_MAX, 0, -1, 10**15]},
        "top-level string",
        [1, "two", None],
    ],
    ids=["escapes", "non-ascii-values", "nested", "integers", "scalar", "array"],
)
def test_accepted_values_match_rfc8785(value):
    assert canonicalize_json(value) == rfc8785.dumps(value)


@pytest.mark.parametrize(
    "value",
    [
        {"n": JCS_SAFE_INTEGER_MAX + 1},
        {"s": "e\u0301"},
        {"x": 1.0},
        {"\u00e9": 1},
        {"s": "\x1f"},
    ],
    ids=["big-int", "non-nfc", "float", "non-ascii-key", "control-char"],
)
def test_divergent_inputs_are_rejected_not_reserialized(value):
    with pytest.raises(SchemaValidationError):
        canonicalize_json(value)


# Characters chosen to hit every serialization edge: JSON escapes, C0 controls, DEL, line/paragraph
# separators, bidi controls, combining marks (NFC and not), BMP above U+E000, and astral planes.
_ALPHABET = (
    list("azAZ09 _-:/") + ['"', "\\", "\t", "\n", "\r", "\x00", "\x1f", "\x7f"]
    + ["\u00e9", "e", "\u0301", "\u212b", "\u2028", "\u202e", "\ue000", "\uffff", "\U0001F600"]
)
_KEY_ALPHABET = list("abcAZ_09-") + ['"', "\\", "\u00e9", "\U0001F600"]


def _random_value(rng, depth=0):
    kind = rng.randrange(8 if depth < 3 else 5)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False])
    if kind == 2:
        edge = rng.choice([0, 1, JCS_SAFE_INTEGER_MAX, JCS_SAFE_INTEGER_MAX + 1, 10**21])
        return rng.choice([1, -1]) * (edge if rng.random() < 0.3 else rng.randrange(10**16))
    if kind in (3, 4):
        return "".join(rng.choice(_ALPHABET) for _ in range(rng.randrange(6)))
    if kind == 5:
        return [_random_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    return {
        "".join(rng.choice(_KEY_ALPHABET) for _ in range(rng.randrange(1, 4))):
            _random_value(rng, depth + 1)
        for _ in range(rng.randrange(4))
    }


def test_differential_every_accepted_value_matches_rfc8785():
    rng = random.Random(8785)
    accepted = rejected = 0
    for _ in range(5000):
        value = _random_value(rng)
        ours = _osiris_or_none(value)
        if ours is None:
            rejected += 1
            continue
        accepted += 1
        assert ours == rfc8785.dumps(value), value
    # Guard against a vacuous pass: both branches must be exercised substantially.
    assert accepted > 1000 and rejected > 1000, (accepted, rejected)
