"""PP 批量驱动器（Gate P-a 的 Rust-only 扫描工具）。

按 prey-existence-probe runbook 的口径，对 corpus manifest 逐 crate 跑
`extract-static-facts` + `extract-rust-contracts`，输出**盲化**的 Tier A-R / Tier A-A
统计与流失原因分类。

判据（runbook §3.1）：

- 装配成功 = C-1（safe-entry lineage 可达）+ C-2（有回调参数）+ C-4（符号解析成功）
  同时成立（`assemble_rust_contract_facts` 的装配条件）；
- **Tier A-R**：装配成功 ∧ capture_admission = permits_non_static_capture；
- **Tier A-A**：装配成功 ∧ allocation = rust_retains_and_may_free_early；
- C-5（L1：外部源码随构建）是样本框属性，由 manifest 与运行配置声明，本工具记录不判定。

盲化：per-crate 行只输出 crate_id 的 sha256 前 12 位与家族标签，不暴露 crate 身份
（runbook：独立 runner 只返回盲化聚合统计）。正式 Gate P 的参数预注册由维护者负责，
本工具只生产统计输入。
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import subprocess
import sys

SCHEMA_VERSION = "bw.pp-scan/0.1"


def digest(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def run(cmd: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


def scan_crate(
    bw: pathlib.Path,
    wrapper: pathlib.Path,
    manifest_row: dict,
    output_root: pathlib.Path,
    run_id: str,
    build_profile: str,
    extra_env: dict[str, str],
) -> dict:
    crate_id = manifest_row["crate_id"]
    crate_name = manifest_row["crate_name"]
    family = manifest_row.get("corpus_id", "unknown")
    row_out = output_root / digest(crate_id)
    row_out.mkdir(parents=True, exist_ok=True)

    env = dict(extra_env)
    facts_proc = run(
        [
            str(bw), "extract-static-facts",
            "--manifest", str(manifest_row["_manifest_path"]),
            "--output-dir", str(row_out / "analysis"),
            "--logs-root", str(row_out / "logs"),
            "--run-id", run_id,
            "--rustc-wrapper", str(wrapper),
            "--all-features",
        ]
        + (["--locked"] if manifest_row.get("locked") else []),
        env=env,
    )
    if facts_proc.returncode != 0:
        return {
            "crate": digest(crate_id),
            "family": digest(family),
            "status": "static_facts_failed",
            "failure": facts_proc.stdout.strip().splitlines()[-1:] or facts_proc.stderr.strip().splitlines()[-1:],
        }

    contracts_proc = run(
        [
            str(bw), "extract-rust-contracts",
            "--facts", str(row_out / "analysis" / "static-facts.jsonl"),
            "--output-dir", str(row_out / "contracts"),
            "--run-id", run_id,
            "--build-profile", build_profile,
            "--rust-artifact", f"rust:{crate_name}:lib:{digest(crate_id, 16)}",
        ],
        env=env,
    )
    if contracts_proc.returncode != 0:
        return {
            "crate": digest(crate_id),
            "family": digest(family),
            "status": "contracts_failed",
            "failure": contracts_proc.stdout.strip().splitlines()[-1:] or contracts_proc.stderr.strip().splitlines()[-1:],
        }

    stats = {
        "crate": digest(crate_id),
        "family": digest(family),
        "status": "ok",
        "handoffs_total": 0,
        "assembled": 0,
        "gapped": 0,
        "tier_a_r": 0,
        "tier_a_a": 0,
        "guard_none": 0,
        "guard_ties": 0,
        "guard_owner_holds": 0,
        "guard_unresolved": 0,
        "gap_reasons": collections.Counter(),
    }
    for line in (row_out / "contracts" / "rust-contracts.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        stats["handoffs_total"] += 1
        if row.get("contract") is None:
            stats["gapped"] += 1
            for gap in row.get("gaps", []):
                stats["gap_reasons"][gap] += 1
            continue
        stats["assembled"] += 1
        contract = row["contract"]
        if contract["capture_admission"] == "permits_non_static_capture":
            stats["tier_a_r"] += 1
        if contract["allocation"] == "rust_retains_and_may_free_early":
            stats["tier_a_a"] += 1
        guard = contract["guard"]
        key = f"guard_{guard}"
        if key in stats:
            stats[key] += 1
    stats["gap_reasons"] = dict(stats["gap_reasons"])
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--bw", required=True, type=pathlib.Path)
    parser.add_argument("--rustc-wrapper", required=True, type=pathlib.Path)
    parser.add_argument("--output-root", required=True, type=pathlib.Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--build-profile", default="x86_64-unknown-linux-gnu/dev")
    parser.add_argument("--max-crates", type=int, default=None)
    args = parser.parse_args()

    rows = [json.loads(line) for line in args.manifest.read_text().splitlines() if line.strip()]
    if args.max_crates is not None:
        rows = rows[: args.max_crates]
    # materialize_corpus 的产物带 source_ref；这里由调用方确保 manifest 的
    # source_ref 可直接解析，逐行注入 manifest 路径供 extract-static-facts 使用。
    for row in rows:
        row["_manifest_path"] = args.manifest

    args.output_root.mkdir(parents=True, exist_ok=True)
    import os

    # 继承完整环境（PATH/HOME 对 wrapper 与 cargo 必需），只叠加必要变量。
    env = dict(os.environ)

    per_crate = []
    for row in rows:
        per_crate.append(
            scan_crate(args.bw, args.rustc_wrapper, row, args.output_root, args.run_id, args.build_profile, env)
        )

    aggregate = {
        "schema_version": SCHEMA_VERSION,
        "run_id": args.run_id,
        "crates_total": len(rows),
        "crates_ok": sum(1 for r in per_crate if r["status"] == "ok"),
        "handoffs_total": sum(r.get("handoffs_total", 0) for r in per_crate),
        "assembled_total": sum(r.get("assembled", 0) for r in per_crate),
        "tier_a_r_total": sum(r.get("tier_a_r", 0) for r in per_crate),
        "tier_a_a_total": sum(r.get("tier_a_a", 0) for r in per_crate),
        "gap_reasons": dict(
            collections.Counter()
        ),
    }
    for r in per_crate:
        for reason, count in r.get("gap_reasons", {}).items():
            aggregate["gap_reasons"][reason] = aggregate["gap_reasons"].get(reason, 0) + count

    summary_path = args.output_root / "pp-scan-summary.json"
    summary_path.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n")
    per_path = args.output_root / "pp-scan-per-crate.jsonl"
    per_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in per_crate) + "\n"
    )
    print(json.dumps(aggregate, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
