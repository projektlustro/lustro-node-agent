"""Red->green for the opted-in scraping session envelope (plan §6.4).

A separate X25519 key per opted-in node, bound to the Ed25519 identity by
signature. Target-specific allowlisted session from necessary cookies and
origin storage only — proxy credentials, unrelated origins and other account
secrets are excluded. Envelope encrypted to node+account+target+deadline;
plaintext sessions never appear in logs or public blob storage.
"""

import base64
import importlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _mod():
    return importlib.import_module("node_agent.session_envelope")


def test_x25519_key_bound_to_ed25519_identity():
    m = _mod()
    ed = Ed25519PrivateKey.generate()
    x = m.generate_node_key()
    proof = m.bind_key(x, ed)
    assert m.verify_binding(x.public_key().public_bytes_raw(), proof, ed.public_key())


def test_envelope_excludes_unrelated_origins_and_proxy_creds():
    m = _mod()
    session = {
        "cookies": [{"name": "session", "domain": ".x.com", "value": "abc"}],
        "origins": {"https://x.com": {"localStorage": {"token": "t"}}},
        "proxy_credentials": {"user": "p", "pass": "secret"},
        "other_origin": {"https://evil.com": {"localStorage": {"k": "v"}}},
    }
    env = m.build_envelope(session, target="x.com", account="acc-1", deadline="2026-11-10T00:00:00Z")
    assert "proxy_credentials" not in env
    assert "evil.com" not in json.dumps(env)
    assert env["target"] == "x.com" and env["account"] == "acc-1"
    assert env["deadline"] == "2026-11-10T00:00:00Z"


def test_envelope_encrypted_to_node_key_and_decryptable():
    m = _mod()
    node_x = X25519PrivateKey.generate()
    env = m.build_envelope({"cookies": [{"name": "s", "domain": ".x.com", "value": "v"}]},
                           target="x.com", account="a", deadline="2026-11-10T00:00:00Z")
    sealed = m.encrypt_envelope(env, node_x.public_key())
    # plaintext session value must not appear in the sealed blob
    assert b'"value": "v"' not in sealed and b"cookies" not in sealed
    opened = m.decrypt_envelope(sealed, node_x)
    assert opened["cookies"][0]["value"] == "v"


def test_expired_deadline_rejected():
    m = _mod()
    with pytest.raises(m.EnvelopeExpired):
        m.check_deadline("2020-01-01T00:00:00Z", now="2026-11-09T00:00:00Z")
    m.check_deadline("2026-11-10T00:00:00Z", now="2026-11-09T00:00:00Z")
