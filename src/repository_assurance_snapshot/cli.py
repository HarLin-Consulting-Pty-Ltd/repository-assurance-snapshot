from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import SnapshotError, generate_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repository-assurance-snapshot",
        description=(
            "Generate a read-only assurance snapshot for a public GitHub repository "
            "or an explicitly declared local public-repository fixture."
        ),
    )
    parser.add_argument("source", help="owner/repo, a github.com URL, or a local fixture path")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("snapshot-output"),
        help="output directory (default: ./snapshot-output)",
    )
    parser.add_argument(
        "--local-public-fixture",
        action="store_true",
        help="required acknowledgement when scanning a local fixture",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        paths = generate_snapshot(
            source=args.source,
            output_dir=args.output,
            local_public_fixture=args.local_public_fixture,
        )
    except SnapshotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for name, path in paths.items():
        print(f"{name}: {path}")
    return 0

