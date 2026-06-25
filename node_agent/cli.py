"""node-agent CLI.

Commands:
  run    — generate/load local key, then pull-and-process work units.
  leave  — one-command exit: delete ALL local state (keys + joblog).
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

from node_agent.classifier import StubClassifier
from node_agent.client import NodeAgentClient
from node_agent.joblog import DEFAULT_JOBLOG_PATH, JobLog
from node_agent.keys import DEFAULT_KEY_PATH, ensure_keypair

STATE_DIR = Path.home() / ".lustro-node-agent"


def cmd_run(args: argparse.Namespace) -> int:
    edge = args.edge or os.environ.get("LUSTRO_NODE_EDGE_URL", "")
    if not edge:
        print("error: --edge or LUSTRO_NODE_EDGE_URL is required", file=sys.stderr)
        return 2
    keys = ensure_keypair(DEFAULT_KEY_PATH)
    joblog = JobLog(DEFAULT_JOBLOG_PATH)
    client = NodeAgentClient(
        edge_base_url=edge,
        classifier=StubClassifier(),
        keys=keys,
        joblog=joblog,
    )
    result = client.pull_and_process()
    if result is None:
        print("no work available")
    else:
        print(f"processed wu {result.get('wu_id')}: {result.get('label')}")
    return 0


def cmd_leave(args: argparse.Namespace) -> int:
    """One-command exit: delete all local state the agent created."""
    if STATE_DIR.exists():
        shutil.rmtree(STATE_DIR)
        print(f"deleted local state: {STATE_DIR}")
    else:
        print("no local state to delete")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="node-agent")
    sub = p.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="pull and process work units")
    run_p.add_argument("--edge", help="edge base URL (or LUSTRO_NODE_EDGE_URL)")
    run_p.set_defaults(func=cmd_run)

    leave_p = sub.add_parser("leave", help="delete all local state and exit")
    leave_p.set_defaults(func=cmd_leave)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
