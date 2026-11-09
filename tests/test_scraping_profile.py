"""RED: the opted-in scraping profile must be a separate explicit flag.

Default remains edge-only: without --enable-scraping, a scraping-kind work
unit must be refused (never executed). With the flag, the manifest rules
(scrape_manifest) gate every request.
"""

import importlib

import pytest


def _cli():
    return importlib.import_module("node_agent.cli")


def _daemon():
    return importlib.import_module("node_agent.daemon")


def test_cli_accepts_enable_scraping_flag():
    cli = _cli()
    args = cli.build_parser().parse_args(["run", "--edge", "http://x", "--enable-scraping"])
    assert args.enable_scraping is True
    args2 = cli.build_parser().parse_args(["run", "--edge", "http://x"])
    assert args2.enable_scraping is False


def test_scraping_work_refused_without_opt_in():
    daemon = _daemon()

    class ScrapeClient:
        def claim(self):
            return {"wu_id": "l2_s1", "kind": "scrape.fetch"}

        def process(self, wu):
            raise AssertionError("must not run scraping without opt-in")

    result = daemon.run_once(ScrapeClient(), state_dir=None, allow_scraping=False)
    assert result.claimed == 0  # refused, not processed


def test_scraping_work_allowed_with_opt_in():
    daemon = _daemon()
    processed = []

    class ScrapeClient:
        def claim(self):
            return {"wu_id": "l2_s2", "kind": "scrape.fetch"}

        def process(self, wu):
            processed.append(wu["wu_id"])

    result = daemon.run_once(ScrapeClient(), state_dir=None, allow_scraping=True)
    assert result.claimed == 1
    assert processed == ["l2_s2"]
