#!/usr/bin/env python3
"""Update the bundled AWS action catalog from the official AWS Service Reference API.

Usage::

    python scripts/update_catalog.py [--out PATH]

The script fetches every service from the AWS Service Reference API
(https://servicereference.us-east-1.amazonaws.com/) and writes a compact
JSON file mapping IAM service prefixes to sorted action-name lists::

    {"iam": ["AddClientIDToOpenIDConnectProvider", ...], "s3": [...], ...}

This file is committed as ``src/scpz/data/aws_actions.json`` and loaded
at runtime via ``importlib.resources``.  It should be refreshed periodically
(the CI workflow does this weekly).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

INDEX_URL = "https://servicereference.us-east-1.amazonaws.com/"
DEFAULT_OUT = Path(__file__).parent.parent / "src" / "scpz" / "data" / "aws_actions.json"
MAX_WORKERS = 20
TIMEOUT = 30


def fetch_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def fetch_service_actions(entry: dict[str, str]) -> tuple[str, list[str]]:
    """Fetch action names for a single service entry from the index."""
    svc = entry["service"]
    url = entry["url"]
    try:
        data = fetch_json(url)
        actions = sorted(a["Name"] for a in data.get("Actions", []))
        return svc, actions
    except Exception as exc:
        print(f"  WARNING: failed to fetch {svc}: {exc}", file=sys.stderr)
        return svc, []


def main(out: Path) -> None:
    print(f"Fetching service index from {INDEX_URL} …")
    index: list[dict[str, str]] = fetch_json(INDEX_URL)  # type: ignore[assignment]
    print(f"Found {len(index)} services.")

    catalog: dict[str, list[str]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_service_actions, entry): entry for entry in index}
        for done, future in enumerate(as_completed(futures), start=1):
            svc, actions = future.result()
            if actions:
                catalog[svc] = actions
            if done % 50 == 0:
                print(f"  … {done}/{len(index)} services fetched")

    # Sort keys for stable diffs
    sorted_catalog = dict(sorted(catalog.items()))

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(sorted_catalog, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    total_actions = sum(len(v) for v in sorted_catalog.values())
    print(f"\nWrote {len(sorted_catalog)} services / {total_actions:,} actions → {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output path for aws_actions.json (default: %(default)s)",
    )
    args = parser.parse_args()
    main(args.out)
