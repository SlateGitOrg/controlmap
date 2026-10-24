"""Scale benchmark on a synthetic company (seeded, offline).

Generates N employees (IdP + HR + one laptop each), N/10 buckets and security groups, and
N/50 repositories, then times collect, evaluate, package build and package verification.

Usage: python scripts/bench.py [--sizes 100,1000,10000] [--repeat 3]
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

from controlmap.package import build_package, verify_package
from controlmap.project import collect, evaluate_project, load_config

ROOT = Path(__file__).resolve().parent.parent
ACME = ROOT / "examples" / "acme"


def generate(root: Path, size: int, seed: int) -> Path:
    rng = random.Random(seed)
    shutil.copytree(ACME / "library", root / "library")
    shutil.copytree(ACME / "data" / "documents", root / "documents")
    shutil.copy(ACME / "exceptions.yaml", root / "exceptions.yaml")
    idp = ["Okta ID,Username,Status,MFA Factors,Last Login,Created,Groups,User Type"]
    hris = [
        "employee_id,email,status,start_date,termination_date,department,manager_email,"
        "training_completed_on"
    ]
    mdm = [
        "device_id,hostname,serial,owner_email,platform,os_version,disk_encrypted,edr_agent,"
        "edr_last_seen,screen_lock_minutes,last_checkin"
    ]
    for i in range(size):
        email = f"user{i}@bench.example"
        terminated = rng.random() < 0.05
        mfa = "Okta Verify" if rng.random() > 0.02 else "SMS"
        status = "DEPROVISIONED" if terminated and rng.random() > 0.2 else "ACTIVE"
        idp.append(
            f"id{i},{email},{status},{mfa},2026-09-{rng.randint(1, 30):02d},"
            "2022-01-01,Engineering,human"
        )
        hris.append(
            f"E{i},{email},{'terminated' if terminated else 'active'},2022-01-01,"
            f"{'2026-09-01' if terminated else ''},Eng,,2026-0{rng.randint(1, 9)}-01"
        )
        mdm.append(
            f"D{i},h{i},s{i},{email},macOS,14.{rng.randint(0, 6)},"
            f"{'yes' if rng.random() > 0.01 else 'no'},edr,"
            f"2026-09-{rng.randint(20, 30)},5,2026-09-30"
        )
    (root / "idp.csv").write_text("\n".join(idp) + "\n", encoding="utf-8")
    (root / "hris.csv").write_text("\n".join(hris) + "\n", encoding="utf-8")
    (root / "mdm.csv").write_text("\n".join(mdm) + "\n", encoding="utf-8")
    snapshot = json.loads((ACME / "data/aws/prod-snapshot-2026-09-28.json").read_text())
    snapshot["s3"]["buckets"] = [
        dict(snapshot["s3"]["buckets"][0], Name=f"bucket-{i}") for i in range(max(1, size // 10))
    ]
    groups = snapshot["ec2"]["describe_security_groups"]["SecurityGroups"]
    snapshot["ec2"]["describe_security_groups"]["SecurityGroups"] = [
        dict(groups[i % len(groups)], GroupId=f"sg-{i}") for i in range(max(1, size // 10))
    ]
    (root / "aws.json").write_text(json.dumps(snapshot), encoding="utf-8")
    protection = ACME / "data/github/api.main.protection.json"
    repos = [
        {"repo": f"bench/r{i}", "branch": "main", "protection": str(protection)}
        for i in range(max(1, size // 50))
    ]
    config = {
        "company": "Bench Co (synthetic)",
        "library": "library/controls.yaml",
        "exceptions": "exceptions.yaml",
        "as_of": "2026-10-01",
        "collectors": [
            {"name": "gh", "type": "github", "repos": repos, "collected_at": "2026-09-30"},
            {"name": "aws", "type": "aws_snapshot", "path": "aws.json"},
            {
                "name": "okta",
                "type": "idp_csv",
                "preset": "okta",
                "tenant": "bench",
                "path": "idp.csv",
                "collected_at": "2026-09-30",
            },
            {"name": "hr", "type": "hris_csv", "path": "hris.csv", "collected_at": "2026-09-30"},
            {
                "name": "mdm",
                "type": "endpoint_csv",
                "path": "mdm.csv",
                "collected_at": "2026-09-30",
            },
            {"name": "docs", "type": "manual_documents", "path": "documents"},
        ],
    }
    path = root / "controlmap.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def one_run(size: int, seed: int) -> tuple[dict[str, float], dict[str, Any]]:
    """Generate, collect, evaluate, package and verify once; return step timings."""
    timings: dict[str, float] = {}
    with tempfile.TemporaryDirectory(prefix="controlmap-bench-") as tmp:
        root = Path(tmp)
        config = load_config(generate(root, size, seed))
        start = time.perf_counter()
        report = collect(config)
        timings["collect"] = time.perf_counter() - start
        assert report.ok, report.collectors
        start = time.perf_counter()
        evaluation = evaluate_project(config)
        timings["evaluate"] = time.perf_counter() - start
        start = time.perf_counter()
        info = build_package(
            root / "pkg",
            run=evaluation.run,
            library=evaluation.library,
            library_source=config.library_path,
            records=evaluation.records,
            store=config.store(),
        )
        timings["package"] = time.perf_counter() - start
        start = time.perf_counter()
        verified = verify_package(root / "pkg")
        timings["verify"] = time.perf_counter() - start
        assert verified.ok, verified.problems
        detail = {
            "evidence_bytes": sum(p.stat().st_size for p in config.store_path.rglob("*.json")),
            "package_files": info.files,
            "counts": evaluation.run.counts(),
        }
    return timings, detail


def bench(size: int, repeat: int) -> dict[str, Any]:
    samples: dict[str, list[float]] = {"collect": [], "evaluate": [], "package": [], "verify": []}
    detail: dict[str, Any] = {}
    for attempt in range(repeat):
        timings, detail = one_run(size, seed=attempt)
        for step, seconds in timings.items():
            samples[step].append(seconds)
    return {"size": size, **{k: statistics.median(v) for k, v in samples.items()}, **detail}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sizes", default="100,1000,10000")
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    print("| employees | collect (s) | evaluate (s) | package (s) | verify (s) | evidence JSON |")
    print("|---:|---:|---:|---:|---:|---:|")
    for size in (int(s) for s in args.sizes.split(",")):
        row = bench(size, args.repeat)
        print(
            f"| {size:,} | {row['collect']:.3f} | {row['evaluate']:.3f} | {row['package']:.3f} | "
            f"{row['verify']:.3f} | {row['evidence_bytes'] / 1024:,.0f} KiB |",
            flush=True,
        )
    print(f"\nmedian of {args.repeat} runs per size; synthetic data, single process")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
