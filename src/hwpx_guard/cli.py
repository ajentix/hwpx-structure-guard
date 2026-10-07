from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .core import GuardError, compare, inspect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only structural HWPX checks, not rendering verification")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_command = commands.add_parser("inspect")
    inspect_command.add_argument("document", type=Path)
    compare_command = commands.add_parser("compare")
    compare_command.add_argument("candidate", type=Path)
    compare_command.add_argument("reference", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "inspect":
            document = inspect(arguments.document)
            report = document.report()
            status = 1 if document.issues else 0
        else:
            candidate = inspect(arguments.candidate)
            reference = inspect(arguments.reference)
            report = compare(candidate, reference)
            status = 0 if report["equivalent"] and not candidate.issues and not reference.issues else 1
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return status
    except GuardError as error:
        print(json.dumps({"error": str(error), "status": "ERROR"}), file=sys.stderr)
        return 2
    except OSError:
        print(json.dumps({"error": "Unable to read input", "status": "ERROR"}), file=sys.stderr)
        return 2
