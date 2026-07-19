"""node-agent CLI.

Commands:
  run       — generate/load the LOCAL key, then pull-and-process a work unit.
  dump-log  — print the local job log (radical inspectability: see every job).
  leave     — one-command exit: delete ALL local state (keys + joblog).
"""

import argparse
import errno
import json
import os
import shutil
import sys
import textwrap
from pathlib import Path

from node_agent.classifier import KeywordClassifier, StubClassifier
from node_agent.client import DEFAULT_SEEN_PATH, NodeAgentClient
from node_agent.joblog import DEFAULT_JOBLOG_PATH, JobLog
from node_agent.keys import DEFAULT_KEY_PATH, ensure_keypair

STATE_DIR = Path.home() / ".lustro-node-agent"

# ASCII art LUSTRO logo — printed on every `run` invocation.
_LOGO = r"""
  _                         _             _
 | |                       | |           | |
 | |    __ _  ___ _ __ ___ | | ___   __ _| |
 | |   / _` |/ _ \ '_ ` _ \| |/ _ \ / _` | |
 | |__| (_| |  __/ | | | | | | (_) | (_| | |
  \____\__,_|\___|_| |_| |_|_|\___/ \__,_|_|

  volunteer node-agent · classify disinformation
"""


def _print_header(edge: str, registered: bool, pubkey: str | None) -> None:
    """Print the LUSTRO banner + agent status block."""
    print(_LOGO)
    print("  " + "=" * 52)
    print(f"  edge:      {edge}")
    if registered and pubkey:
        # Show first 16 chars of the public key as a fingerprint.
        print(f"  agent:     registered (key {pubkey[:16]}...)")
    else:
        print("  agent:     NOT registered — will register with invite token")
    print(f"  classifier: KeywordClassifier (Polish disinformation narratives)")
    print("  " + "=" * 52)
    print()


def _print_step(num: int, label: str) -> None:
    print(f"  [{num}] {label}...")


def _print_ok(msg: str) -> None:
    print(f"      ✓ {msg}")


def _print_fail(msg: str) -> None:
    print(f"      ✗ {msg}", file=sys.stderr)


def _print_result(labels: list[str], score: float, text_preview: str) -> None:
    """Print the classification result with context."""
    label = labels[0] if labels else "unknown"
    is_disinfo = label != "benign" and score >= 0.6

    print()
    print("  " + "-" * 52)
    print("  CLASSIFICATION RESULT")
    print("  " + "-" * 52)
    print(f"  label:    {label}")
    print(f"  score:    {score:.3f}")
    print(f"  verdict:  {'⚠ DISINFORMATION DETECTED' if is_disinfo else '✓ benign'}")
    print()
    print("  classified text (first 200 chars):")
    for line in textwrap.wrap(text_preview[:200], width=50):
        print(f"    {line}")
    print()
    print("  " + "-" * 52)
    print(f"  result submitted to core → stored as detection (pending_review)")
    print()


def _print_next_steps() -> None:
    """Print friendly next steps for the volunteer."""
    print("  NEXT STEPS")
    print("  " + "=" * 52)
    print("  • Run again to classify the next post:")
    print("    docker run --rm --pull=always \\")
    print("      -v ~/.lustro-node-agent:/agent/.lustro-node-agent \\")
    print("      -e LUSTRO_NODE_EDGE_URL=https://projektlustro.eu \\")
    print("      ghcr.io/projektlustro/node-agent:latest")
    print()
    print("  • Schedule in cron for continuous participation:")
    print("    */10 * * * * docker run --rm ... >> ~/.lustro-node-agent/cron.log 2>&1")
    print()
    print("  • View your job log:")
    print("    docker run --rm -v ~/.lustro-node-agent:/agent/.lustro-node-agent \\")
    print("      ghcr.io/projektlustro/node-agent:latest dump-log")
    print()
    print("  • Track your progress: https://projektlustro.eu/me")
    print()
    print("  Dziękujemy za udział w walce z dezinformacją! 🇵🇱")
    print()


def cmd_run(args: argparse.Namespace) -> int:
    edge = args.edge or os.environ.get("LUSTRO_NODE_EDGE_URL", "")
    if not edge:
        print("error: --edge or LUSTRO_NODE_EDGE_URL is required", file=sys.stderr)
        return 2
    keys = ensure_keypair(DEFAULT_KEY_PATH)
    joblog = JobLog(DEFAULT_JOBLOG_PATH)
    classifier = KeywordClassifier() if not args.stub else StubClassifier()
    client = NodeAgentClient(
        edge_base_url=edge,
        classifier=classifier,
        keys=keys,
        joblog=joblog,
        seen_path=DEFAULT_SEEN_PATH,
    )
    registered_path = STATE_DIR / "registered"
    is_registered = registered_path.exists()
    pubkey = keys.public_key_raw_b64() if is_registered else None

    _print_header(edge, is_registered, pubkey)

    if not is_registered:
        _print_step(1, "Registering agent with invite token")
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        invite_token = os.environ.get("LUSTRO_NODE_INVITE_TOKEN", "")
        if not invite_token:
            _print_fail("No LUSTRO_NODE_INVITE_TOKEN set — registration will fail")
            _print_fail("Get a token from the LUSTRO operator")
            return 2
        try:
            client.register_agent(invite_token=invite_token)
            registered_path.write_text(keys.public_key_raw_b64(), encoding="utf-8")
            _print_ok(f"registered (key {keys.public_key_raw_b64()[:16]}...)")
        except Exception as exc:
            _print_fail(f"registration failed: {exc}")
            return 2
    else:
        _print_step(1, "Agent already registered")
        _print_ok(f"key {pubkey[:16]}... loaded from disk")

    _print_step(2, "Pulling work unit from core")
    result = client.pull_and_process()
    if result is None:
        print("      → no work available right now")
        print()
        _print_next_steps()
        return 0

    _print_ok(f"received (labels={result['labels']} score={result['score']})")

    text_preview = result.get("text_preview", "")

    _print_step(3, "Classifying content")
    _print_ok(f"KeywordClassifier → {result['labels'][0]} ({result['score']:.3f})")

    _print_step(4, "Submitting signed result to core")
    _print_ok("accepted → stored as detection (pending_review)")

    _print_result(result["labels"], result["score"], text_preview)
    _print_next_steps()
    return 0


def cmd_dump_log(args: argparse.Namespace) -> int:
    """Print the local job log so the volunteer can inspect every job."""
    joblog = JobLog(DEFAULT_JOBLOG_PATH)
    rows = joblog.read_all()
    if not rows:
        print(f"no jobs logged yet ({joblog.path})")
        return 0
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))
    return 0


def cmd_leave(args: argparse.Namespace) -> int:
    """One-command exit: delete all local state the agent created."""
    if STATE_DIR.exists():
        try:
            shutil.rmtree(STATE_DIR)
        except OSError as exc:
            # STATE_DIR is commonly a Docker bind-mount point (the documented
            # `-v host:/agent/.lustro-node-agent` usage). rmtree deletes every
            # file/subdirectory fine but the mount point itself can't be
            # rmdir'd from inside the container (EBUSY) -- that's not
            # "residue" left behind, just an empty directory the host still
            # owns, so treat it as the successful case rather than crashing.
            if exc.errno != errno.EBUSY:
                raise
        print(f"deleted local state: {STATE_DIR}")
    else:
        print("no local state to delete")
    return 0


def cmd_serve_log(args: argparse.Namespace) -> int:
    """Start the local log-wall dashboard."""
    from node_agent.logwall import LogWallServer, DEFAULT_HOST, DEFAULT_PORT

    host = (
        args.host
        if args.host is not None
        else os.environ.get("LUSTRO_LOGWALL_HOST", DEFAULT_HOST)
    )
    if args.port is not None:
        port = args.port
    else:
        try:
            port = int(os.environ.get("LUSTRO_LOGWALL_PORT", DEFAULT_PORT))
        except ValueError:
            print("error: LUSTRO_LOGWALL_PORT must be an integer", file=sys.stderr)
            return 2
    if host not in ("127.0.0.1", "localhost"):
        print(
            f"warning: binding to {host}; dashboard reachable beyond this machine",
            file=sys.stderr,
        )
    try:
        server = LogWallServer(DEFAULT_JOBLOG_PATH, host=host, port=port)
    except (OSError, OverflowError) as exc:
        print(f"error: cannot bind {host}:{port}: {exc}", file=sys.stderr)
        return 2
    try:
        server.start(open_browser=not args.no_open)
    except KeyboardInterrupt:
        pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="node-agent")
    sub = p.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="pull and process the next work unit")
    run_p.add_argument("--edge", help="edge base URL (or LUSTRO_NODE_EDGE_URL)")
    run_p.add_argument(
        "--stub", action="store_true",
        help="use the stub classifier (for tests / smoke runs)"
    )
    run_p.set_defaults(func=cmd_run)

    dump_p = sub.add_parser("dump-log", help="print the local job log")
    dump_p.set_defaults(func=cmd_dump_log)

    leave_p = sub.add_parser("leave", help="delete all local state and exit")
    leave_p.set_defaults(func=cmd_leave)

    serve_p = sub.add_parser(
        "serve-log", help="start a local web dashboard for the job log"
    )
    serve_p.add_argument(
        "--host", default=None,
        help="bind host (default 127.0.0.1)"
    )
    serve_p.add_argument(
        "--port", type=int, default=None,
        help="port (default 8787)"
    )
    serve_p.add_argument(
        "--no-open", action="store_true",
        help="do not open browser"
    )
    serve_p.set_defaults(func=cmd_serve_log)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
