"""Generate realistic fixture logs as JSON for manual experimentation.

Usage:
    uv run python scripts/generate_test_logs.py --scenario mongodb --count 2000
    uv run python scripts/generate_test_logs.py --list
"""

from __future__ import annotations

import argparse
import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from fixtures.generators import SCENARIOS  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="mongodb", choices=sorted(SCENARIOS))
    parser.add_argument("--count", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--list", action="store_true", help="List scenarios and exit")
    args = parser.parse_args()

    if args.list:
        for name, fn in sorted(SCENARIOS.items()):
            print(f"{name:<20} {fn.__doc__.strip().splitlines()[0]}")
        return

    generator = SCENARIOS[args.scenario]
    kwargs = {}
    if args.count is not None and "count" in inspect.signature(generator).parameters:
        kwargs["count"] = args.count
    rows = generator(**kwargs)
    output = args.output or Path("examples") / f"generated_{args.scenario}.json"
    output.write_text(json.dumps({"results": rows}, indent=1))
    print(f"Wrote {len(rows)} CloudWatch-shaped events to {output}")


if __name__ == "__main__":
    main()
