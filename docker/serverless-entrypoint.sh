#!/bin/sh
# Serverless drain worker entrypoint.
#
# Restore the agent state (ed25519 key, registered marker, seen log, ship
# offset) from object storage so every job run keeps the same agent identity;
# supervise the agent loop; sync the state back periodically and on exit.
# S3 access stays HERE, in the wrapper — the agent process keeps its
# single-host egress allowlist (node_agent/egress.py) untouched.
set -u

STATE=/agent/.lustro-node-agent
SYNC_INTERVAL="${STATE_SYNC_SECONDS:-300}"
S3_ARGS=""
[ -n "${S3_ENDPOINT_URL:-}" ] && S3_ARGS="--endpoint-url ${S3_ENDPOINT_URL}"

mkdir -p "$STATE"
chmod -R a+rwX "$STATE" 2>/dev/null || true

if [ -n "${STATE_S3_URI:-}" ]; then
    if aws s3 cp $S3_ARGS "${STATE_S3_URI}/state.tar.gz" /tmp/state-restore.tar.gz >/dev/null 2>&1; then
        if tar -xzf /tmp/state-restore.tar.gz -C "$STATE"; then
            echo "serverless: state restored from bucket"
        else
            echo "serverless: WARNING restore archive unreadable; fresh registration"
        fi
    else
        echo "serverless: no prior state in bucket; fresh registration"
    fi
    rm -f /tmp/state-restore.tar.gz
else
    echo "serverless: STATE_S3_URI unset; ephemeral state (fresh registration)"
fi

sync_state() {
    [ -n "${STATE_S3_URI:-}" ] || return 0
    tar -czf /tmp/state-sync.tar.gz -C "$STATE" . 2>/dev/null || return 0
    aws s3 cp $S3_ARGS /tmp/state-sync.tar.gz "${STATE_S3_URI}/state.tar.gz" >/dev/null 2>&1 \
        || echo "serverless: WARNING state sync failed (continuing)"
    rm -f /tmp/state-sync.tar.gz
}

python -m node_agent.cli "$@" &
AGENT_PID=$!
trap 'kill -TERM "$AGENT_PID" 2>/dev/null; sync_state; exit 0' TERM INT

while kill -0 "$AGENT_PID" 2>/dev/null; do
    sleep "$SYNC_INTERVAL"
    kill -0 "$AGENT_PID" 2>/dev/null && sync_state
done
sync_state
wait "$AGENT_PID"
