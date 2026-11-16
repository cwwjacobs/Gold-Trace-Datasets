#!/usr/bin/env python3
"""Hallmark: standalone integrity verifier for Assay packs and run archives.

Buyers: this tool lets you verify Assay Dataset Products yourself, without
trusting the seller. No network, no dependencies, Python 3.11+ only.

    python3 hallmark.py pack   <pack-dir>
    python3 hallmark.py run    <run-dir>

Exit code 0 = PASS, 1 = FAIL.
Licensed under Apache-2.0 (see LICENSE in this directory). You may embed,
redistribute, and modify this file freely.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    # Mirrors seedrunner.util.canonical_json byte-for-byte. The run-manifest
    # root_hash is DEFINED as sha256(canonical_json(manifest["files"])) in
    # seedrunner/src/seedrunner/integrity.py:31 — keep this in sync.
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _contained(root: Path, name: str) -> bool:
    """True when `name` is lexically safe and resolves inside `root`.

    The resolved-path check is required because a lexically safe in-pack
    symlink can otherwise point outside the pack/run boundary.
    """
    if not name or name.strip() != name:
        return False
    if name.startswith("/") or "\\" in name:
        return False
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        return False
    try:
        root_resolved = root.resolve(strict=True)
        target_resolved = (root / Path(*pure.parts)).resolve(strict=False)
        target_resolved.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _entries(files: Any) -> list[tuple[str, str, int | None]]:
    triples: list[tuple[str, str, int | None]] = []
    if isinstance(files, dict):
        for rel_path, expected in files.items():
            size: int | None = None
            digest = expected
            if isinstance(expected, dict):
                digest = expected.get("sha256")
                raw_size = expected.get("size_bytes")
                size = int(raw_size) if raw_size is not None else None
            triples.append((rel_path, str(digest), size))
    elif isinstance(files, list):
        for item in files:
            raw_size = item.get("size_bytes")
            size = int(raw_size) if raw_size is not None else None
            triples.append((str(item["path"]), str(item["sha256"]), size))
    return triples


def _fail(reason: str) -> dict[str, Any]:
    return {"status": "FAIL", "reason": reason, "files_checked": 0,
            "errors": []}


def verify_run(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        return _fail("manifest.json missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"manifest.json could not be read: {exc}")
    if not isinstance(manifest, dict):
        return _fail("manifest.json is not an object")

    entries = _entries(manifest.get("files"))
    if not entries:
        return _fail("manifest.files missing or empty")

    errors: list[str] = []
    checked = 0

    algorithm = manifest.get("algorithm", "sha256")
    if algorithm != "sha256":
        errors.append(f"unsupported-algorithm: {algorithm}")

    for rel_path, expected, size in sorted(entries):
        if not _contained(run_dir, str(rel_path)):
            errors.append(f"unsafe-path: {rel_path}")
            continue
        target = run_dir / rel_path
        if not target.is_file():
            errors.append(f"missing: {rel_path}")
            continue
        checked += 1
        if _sha256(target) != expected.lower():
            errors.append(f"hash-mismatch: {rel_path}")
        if size is not None and target.stat().st_size != size:
            errors.append(f"size-mismatch: {rel_path}")

    declared_root = manifest.get("root_hash")
    root_verified: bool | None = None
    if declared_root is not None:
        computed = hashlib.sha256(
            _canonical_json(manifest.get("files")).encode("utf-8")
        ).hexdigest()
        root_verified = computed == declared_root
        if not root_verified:
            errors.append("root-hash-mismatch")

    return {
        "status": "PASS" if not errors else "FAIL",
        "algorithm": algorithm,
        "algorithm_verified": algorithm == "sha256",
        "declared_root_hash": declared_root,
        "root_hash_verified": root_verified,
        "files_checked": checked,
        "errors": errors,
    }


def _jsonl_ids(path: Path) -> set[str]:
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            row = json.loads(line)
            if isinstance(row, dict) and "id" in row:
                ids.add(row["id"])
    return ids


def _answer_input_pairs(
    pack_dir: Path,
) -> tuple[list[tuple[Path, Path]], list[str]]:
    """Returns (paired, problems). An answers file with no matching inputs
    file is a problem, never a silent drop."""
    problems: list[str] = []
    answers_dir = pack_dir / "answers"
    answers = (
        sorted(answers_dir.glob("*.answers.jsonl"))
        if answers_dir.is_dir()
        else []
    )
    if not answers:
        problems.append(
            "no-answer-files: pack contains no answers/*.answers.jsonl"
        )
        return [], problems

    inputs_by_stem: dict[str, Path] = {}
    for candidate in ("export", "canonical"):
        directory = pack_dir / candidate
        if not directory.is_dir():
            continue
        for path in directory.glob("*inputs.jsonl"):
            stem = path.name.split(".")[0]
            inputs_by_stem.setdefault(stem, path)

    pairs = []
    for answer_path in answers:
        stem = answer_path.name.split(".")[0]
        input_path = inputs_by_stem.get(stem)
        if input_path is None:
            problems.append(f"unpaired-answers: {answer_path.name}")
            continue
        pairs.append((input_path, answer_path))
    return pairs, problems


_HEX_DIGEST_CHARS = set("0123456789abcdef")


def _parse_sums(sums_path: Path, errors: list[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for lineno, line in enumerate(
        sums_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition(" ")
        digest = digest.strip().lower()
        name = name.lstrip("*").strip()
        if name.startswith("./"):
            name = name[2:]
        if len(digest) != 64 or not set(digest) <= _HEX_DIGEST_CHARS:
            errors.append(
                f"malformed-digest line {lineno}: not a sha256 hex digest"
            )
            continue
        if not _contained(sums_path.parent, name):
            errors.append(f"unsafe-path: {name}")
            continue
        entries.append((digest, name))
    return entries


def verify_pack(pack_dir: Path) -> dict[str, Any]:
    sums_path = pack_dir / "SHA256SUMS.txt"
    if not sums_path.exists():
        return _fail("SHA256SUMS.txt missing")

    errors: list[str] = []
    entries = _parse_sums(sums_path, errors)
    if not entries:
        if not any(e.startswith(("malformed", "unsafe")) for e in errors):
            errors.append("SHA256SUMS.txt is empty")
        return {
            "status": "FAIL",
            "reason": "no verifiable entries",
            "files_checked": 0,
            "errors": errors,
        }

    checked = 0
    for expected, name in entries:
        target = pack_dir / name
        if not target.is_file():
            errors.append(f"listed-but-missing: {name}")
            continue
        checked += 1
        if _sha256(target) != expected:
            errors.append(f"hash-mismatch: {name}")

    on_disk = {
        str(path.relative_to(pack_dir))
        for path in pack_dir.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt"
    }
    listed = {name for _, name in entries}
    for stray in sorted(on_disk - listed):
        errors.append(f"unlisted-file: {stray}")

    pairs, problems = _answer_input_pairs(pack_dir)
    errors.extend(problems)
    for input_path, answer_path in pairs:
        try:
            in_ids = _jsonl_ids(input_path)
            ans_ids = _jsonl_ids(answer_path)
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"unreadable-jsonl {answer_path.name}: {exc}")
            continue
        missing = ans_ids - in_ids
        extra = in_ids - ans_ids
        if missing:
            errors.append(
                f"id-mismatch {answer_path.name}: answers without inputs: "
                f"{sorted(missing)[:5]}"
            )
        if extra:
            errors.append(
                f"id-mismatch {answer_path.name}: inputs without answers: "
                f"{sorted(extra)[:5]}"
            )
    return {
        "status": "PASS" if not errors else "FAIL",
        "files_checked": checked,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hallmark", description="Verify Assay dataset products.")
    sub = parser.add_subparsers(dest="target", required=True)
    for name, help_text in (("pack", "verify an eval pack directory"), ("run", "verify a harvest run directory")):
        child = sub.add_parser(name, help=help_text)
        child.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    result = verify_pack(args.path) if args.target == "pack" else verify_run(args.path)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
