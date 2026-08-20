#!/usr/bin/env python3
"""Validate a repository-controlled staged-update rollout manifest."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def parse_manifest(path: Path) -> tuple[bool, str, str, int, bool]:
    with path.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ValueError("rollout schema must be 1")
    enabled = value.get("enabled")
    target = value.get("target")
    activation = value.get("activation")
    sequence = value.get("sequence")
    allow_rollback = value.get("allow_rollback")
    if not isinstance(enabled, bool):
        raise ValueError("rollout enabled must be boolean")
    if not isinstance(target, str):
        raise ValueError("rollout target must be a string")
    if activation != "next-restart":
        raise ValueError("only next-restart activation is supported")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValueError("rollout sequence must be a non-negative integer")
    if not isinstance(allow_rollback, bool):
        raise ValueError("allow_rollback must be boolean")
    if target and not re.fullmatch(r"[0-9a-f]{40,64}", target):
        raise ValueError(
            "rollout target must be a full lowercase hexadecimal commit id")
    if enabled and target and sequence == 0:
        raise ValueError("enabled rollout requires a positive sequence")
    return enabled, target, activation, sequence, allow_rollback


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} MANIFEST", file=sys.stderr)
        return 2
    try:
        enabled, target, activation, sequence, allow_rollback = \
            parse_manifest(Path(sys.argv[1]))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid rollout manifest: {exc}", file=sys.stderr)
        return 1
    print("true" if enabled else "false")
    print(target)
    print(activation)
    print(sequence)
    print("true" if allow_rollback else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
