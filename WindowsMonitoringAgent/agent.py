from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

from reporting.logger import create_logger


PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_DIR = PROJECT_ROOT / "config"
LOG_DIR = PROJECT_ROOT / "logs"


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON configuration file."""

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Expected a JSON object in {path}"
        )

    return data


def validate_windows() -> None:
    """Ensure the application is running on Windows."""

    if platform.system() != "Windows":
        raise RuntimeError(
            "WindowsMonitoringAgent requires Windows."
        )


def print_banner() -> None:
    print()
    print("=" * 64)
    print("       WINDOWS SERVICE & PROCESS MONITORING AGENT")
    print("=" * 64)
    print(f"Python  : {platform.python_version()}")
    print(f"Platform: {platform.platform()}")
    print("=" * 64)
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Windows Service & Process Monitoring Agent"
        )
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate configuration and environment.",
    )

    args = parser.parse_args()

    logger = create_logger(log_directory=LOG_DIR)

    try:
        validate_windows()

        rules = load_json(
            CONFIG_DIR / "rules.json"
        )

        whitelist = load_json(
            CONFIG_DIR / "whitelist.json"
        )

        print_banner()

        logger.info("Application initialized successfully.")

        print("[OK] Operating system       : Windows")
        print("[OK] Detection rules        : loaded")
        print("[OK] Process whitelist      : loaded")
        print("[OK] Logging subsystem      : ready")
        print()

        if args.self_test:
            print("[PASS] Foundation self-test completed.")
            return 0

        print(
            "Phase 1 foundation is ready."
        )
        print(
            "Process and service collectors "
            "will be added in later phases."
        )

        # Prevent unused-variable warnings in future tooling.
        _ = rules
        _ = whitelist

        return 0

    except Exception as exc:
        logger.exception(
            "Application initialization failed."
        )

        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())