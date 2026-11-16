#!/usr/bin/env python3
"""Verify public integrity, sanitization, and JSONL validity for Gold-Trace-Datasets."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

# Patterns written with regex syntax (\s+, character classes) so this verifier
# does not self-match when scanning all text files in the repository.
DENY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "api_key_token",
        re.compile(
            r"(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
            r"|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}"
            r"|-----BEGIN\s+(?:RSA|OPENSSH|EC|PGP)\s+PRIVATE\s+KEY-----)"
        ),
    ),
    (
        "hardcoded_secret",
        re.compile(
            r"""(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token)"""
            r"""\s*[:=]\s*['"](?!not_captured\b)[^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
    ),
    (
        "email_address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "home_path_leak",
        re.compile(
            r"(?:/home/[a-zA-Z0-9_.-]+|/Users/(?!Public\b)[a-zA-Z0-9_.-]+"
            r"|[A-Za-z]:[/\\]Users[/\\](?!Public\b)[a-zA-Z0-9_.-]+)"
        ),
    ),
    (
        "assay_proprietary_license",
        re.compile(r"ASSAY\s+PROPRIETARY\s+LICENSE", re.IGNORECASE),
    ),
    (
        "gtdataworks_proprietary_license",
        re.compile(r"GTDataworks\s+Studio\s+Proprietary", re.IGNORECASE),
    ),
    (
        "private_engine_import",
        re.compile(r"\b(?:from|import)\s+(?:evalfoundry|assay|labyrinth)\b"),
    ),
    (
        "private_engine_module_path",
        re.compile(r"(?:studio[/]src[/]evalfoundry|studio[/]src[/]labyrinth|assay[/]src[/]assay)"),
    ),
)

FORBIDDEN_PATHS = (
    ".env",
    "evalfoundry",
    "labyrinth",
    "pack_sources",
    "assay/src",
    "studio/src",
)

EXPECTED_PREVIEW_DIRS = (
    "policy-gate-public-v1",
    "tool-contract-public-v1",
    "cyber-defense-public-v1",
)

PRIVATE_CD_SOURCE_IDS = {"cd-011", "cd-012", "cd-013", "cd-014", "cd-015"}
FORBIDDEN_PUBLIC_KEYS = {"oracle", "initial_state", "reference_grade"}


def _verify_hallmark() -> dict[str, Any]:
    hallmark = REPO_ROOT / "hallmark" / "hallmark.py"
    sample_run = REPO_ROOT / "samples" / "mock-demo-run"
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, str(hallmark), "run", str(sample_run)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"hallmark exited {proc.returncode}: stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
    payload = json.loads(proc.stdout)
    if payload.get("status") != "PASS":
        raise AssertionError(f"hallmark status != PASS: {payload}")
    if payload.get("root_hash_verified") is not True:
        raise AssertionError(f"hallmark root_hash_verified != True: {payload}")
    if payload.get("errors"):
        raise AssertionError(f"hallmark reported errors: {payload['errors']}")
    return payload


def _verify_boundary_paths() -> None:
    for rel in FORBIDDEN_PATHS:
        target = REPO_ROOT / rel
        if target.exists():
            raise AssertionError(f"forbidden private path present in public repo: {rel}")
    for env_file in REPO_ROOT.rglob(".env*"):
        if ".git" in env_file.parts:
            continue
        if env_file.name != ".env.example":
            raise AssertionError(
                f"forbidden env file present: {env_file.relative_to(REPO_ROOT)}"
            )


def _scan_text_files() -> dict[str, Any]:
    scanned = 0
    hits: list[str] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT)
        if ".git" in rel.parts or "__pycache__" in rel.parts:
            continue
        raw = path.read_bytes()
        if b"\x00" in raw:
            continue
        text = raw.decode("utf-8")
        scanned += 1
        for label, pattern in DENY_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text[: match.start()].count("\n") + 1
                hits.append(f"{rel.as_posix()}:{line_no} [{label}] {match.group(0)}")
    if hits:
        raise AssertionError("DENY_PATTERNS matched:\n" + "\n".join(hits[:20]))
    return {"files_scanned": scanned, "deny_hits": 0}


def _parse_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            raise AssertionError(f"blank line at {path.relative_to(REPO_ROOT)}:{lineno}")
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise AssertionError(
                f"expected JSON object at {path.relative_to(REPO_ROOT)}:{lineno}"
            )
        rows.append(obj)
    if not rows:
        raise AssertionError(f"empty JSONL file: {path.relative_to(REPO_ROOT)}")
    return rows


def _verify_previews_and_samples() -> dict[str, Any]:
    for pack_name in EXPECTED_PREVIEW_DIRS:
        pack_dir = REPO_ROOT / "previews" / pack_name
        if not pack_dir.is_dir():
            raise AssertionError(f"missing preview directory: {pack_dir.relative_to(REPO_ROOT)}")
        if not list(pack_dir.glob("*.jsonl")):
            raise AssertionError(f"no JSONL files in {pack_dir.relative_to(REPO_ROOT)}")

    preview_counts: dict[str, int] = {}
    for jsonl_path in sorted((REPO_ROOT / "previews").glob("*/*.jsonl")):
        rows = _parse_jsonl(jsonl_path)
        rel = jsonl_path.relative_to(REPO_ROOT).as_posix()
        preview_counts[rel] = len(rows)
        if jsonl_path.parent.name == "cyber-defense-public-v1":
            for idx, row in enumerate(rows, 1):
                if row.get("source_id") in PRIVATE_CD_SOURCE_IDS:
                    raise AssertionError(
                        f"private eval source_id {row.get('source_id')} leaked in {rel}:{idx}"
                    )
                bad_keys = FORBIDDEN_PUBLIC_KEYS.intersection(row)
                if bad_keys:
                    raise AssertionError(
                        f"controller-only keys {sorted(bad_keys)} leaked in {rel}:{idx}"
                    )

    sample_counts: dict[str, int] = {}
    for sample_jsonl in (
        REPO_ROOT / "samples" / "seeds.jsonl",
        REPO_ROOT / "samples" / "mock-demo-run" / "records.jsonl",
        REPO_ROOT / "samples" / "mock-demo-run" / "inputs" / "seeds.jsonl",
    ):
        rows = _parse_jsonl(sample_jsonl)
        sample_counts[sample_jsonl.relative_to(REPO_ROOT).as_posix()] = len(rows)

    return {"preview_jsonl": preview_counts, "sample_jsonl": sample_counts}


def main() -> int:
    _verify_boundary_paths()
    hallmark_result = _verify_hallmark()
    scan_result = _scan_text_files()
    jsonl_result = _verify_previews_and_samples()
    report = {
        "status": "PASS",
        "hallmark": {
            "status": hallmark_result["status"],
            "files_checked": hallmark_result["files_checked"],
            "root_hash_verified": hallmark_result["root_hash_verified"],
        },
        "sanitization": scan_result,
        "jsonl": jsonl_result,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
