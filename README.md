# Gold-Trace-Datasets

Public sample **Traces**, preview evaluation slices, and the standalone Apache-2.0 integrity verifier (`hallmark`).

This repository contains only public-safe fixtures, sample run archives, and public preview slices. Private engine source, local `.env` configuration, and withheld/commercial evaluation packs are excluded from this repository.

## Repository Contents

- [`hallmark/hallmark.py`](hallmark/hallmark.py) ([Apache-2.0](hallmark/LICENSE)): Zero-dependency Python 3.11+ integrity verifier for run archives and eval packs.
- [`samples/mock-demo-run/`](samples/mock-demo-run/): Deterministic sample Trace run archive (3 seed records: `intentional-pass`, `intentional-fail`, `intentional-error`) with `manifest.json` SHA-256 checksums, `root_hash`, `receipt.json`, `records.jsonl`, `summary.json`, `verification.json`, and `report.html`.
- [`samples/seeds.jsonl`](samples/seeds.jsonl): Example input seed definitions corresponding to `samples/mock-demo-run/`.
- [`previews/policy-gate-public-v1/`](previews/policy-gate-public-v1/): 8-row preview slice (`preview_8.jsonl`), `PACK_CONTRACT.json`, and `PUBLIC_SAFE.md` for `policy-shall-gate-v1` (public policy atom + action classification).
- [`previews/tool-contract-public-v1/`](previews/tool-contract-public-v1/): 8-row preview slice (`preview_8.jsonl`), `PACK_CONTRACT.json`, and `PUBLIC_SAFE.md` for `tool-contract-v1` (tool schema + proposed call + granted scopes classification).
- [`previews/cyber-defense-public-v1/`](previews/cyber-defense-public-v1/): 10-row synthetic defensive-security public trajectory slice (`public_10.jsonl`, `cd-001` through `cd-010`), `DATASET_CARD.md`, `SPLIT_RECEIPT.json`, and [`LICENSE.md`](previews/cyber-defense-public-v1/LICENSE.md) (`CDLA-Permissive-2.0`).
- [`scripts/verify_public_samples.py`](scripts/verify_public_samples.py): Verifies `hallmark` against `samples/mock-demo-run/`, scans repository text files against deny patterns, and parses all `previews/*/*.jsonl` and sample JSONL files.

## Independent Verification

Anyone can verify the sample Trace run archive locally with Python 3.11+ and zero external dependencies:

```bash
python3 hallmark/hallmark.py run samples/mock-demo-run
```

Expected output includes `"status": "PASS"`, `"root_hash_verified": true`, `"files_checked": 21`, and `"errors": []` with exit code `0`.

To run the full public-repository verification check (hallmark verification, sanitization deny-pattern scan, and JSONL validation):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_public_samples.py
```

## Licensing

- Repository code and `hallmark/` are licensed under Apache-2.0 (see [`LICENSE`](LICENSE) and [`hallmark/LICENSE`](hallmark/LICENSE)).
- `previews/cyber-defense-public-v1/` is licensed under `CDLA-Permissive-2.0` (see [`previews/cyber-defense-public-v1/LICENSE.md`](previews/cyber-defense-public-v1/LICENSE.md)).
