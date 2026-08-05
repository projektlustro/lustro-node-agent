# Node agent tier gate — HTTP 403 handling and token sourcing

## Finding: agent is safe, no code change needed

Investigated `node_agent/client.py` in lustro-node-agent to confirm the agent
surfaces HTTP 403s from the commons-api backend gracefully and does not mint
tokens client-side.

### 403 handling (`_report_activity`)

- Uses `self._participant_token`, sourced from env `LUSTRO_NODE_TOKEN`
  (`node_agent/cli.py:136`).
- The activity POST to `/elfik/node/activity` calls
  `response.raise_for_status()` inside a `try`.
- An invalid/expired/revoked token yields HTTP 403 → `raise_for_status()`
  raises `httpx.HTTPStatusError`, which is a subclass of `httpx.HTTPError`.
- That exception is caught by the `except (httpx.HTTPError, OSError)` block at
  `client.py:119`, which logs `activity_sync_failed` to the JobLog and returns
  — the agent does not crash and continues processing.
- If `LUSTRO_NODE_TOKEN` is unset, `_participant_token` is empty and
  `_report_activity` returns early (line 109) without attempting the call.

### No client-side token mint

- The only token the agent holds is read from `LUSTRO_NODE_TOKEN` env; there is
  no code path that creates, signs, or mints a session/participant token.
- Registration is the operator-gated invite flow (`register_agent` →
  `/v1/wu/register-agent` with an optional `LUSTRO_NODE_INVITE_TOKEN`), which is
  a backend acceptance step, not a token mint.
- No `/node/token` client call and no token-bypass/shorthand logic exists in the
  agent — all authorization tokens are issued by the backend.

## Conclusion

The agent is safe: the participant token is backend-issued (never minted
client-side), and a 403 is handled gracefully as a logged, non-fatal activity
sync failure. No code change required.