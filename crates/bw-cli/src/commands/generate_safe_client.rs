//! 从反证计划生成 safe-only 客户端 crate（执行计划阶段 5.2）。
//!
//! 每个计划导出 [`exportable_variants`] 列出的变体；每个变体是一个独立的可编译
//! crate（独立目录、独立包名），因为控制组与 primary 的差异必须体现在**源码**
//! 里并各自留下 checksum，而不是运行期开关——运行期开关无法被 receipt 钉住。
//!
//! # 拒绝也是产物
//!
//! adapter 关联不上、形状没有模板、组件路径缺失都逐条记录。只写成功目录会让
//! 「为什么这个判定没有反证」变成考古问题。

use std::collections::BTreeMap;
use std::path::PathBuf;

use bw_model::SAFE_CLIENT_SCHEMA_V01;
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    commands::{
        DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl,
        safe_client::{
            Adapter, ClientVariant, GeneratedClient, exportable_variants, generate_client,
            resolve_foreign_source,
        },
        write_json_file, write_records,
    },
    exit::{CliError, CommandStatus},
};

#[derive(Deserialize)]
struct PlanRecord {
    run_id: String,
    api_id: String,
    plan: bw_model::WitnessPlan,
}

#[derive(Serialize)]
struct GeneratedRecord {
    plan_id: String,
    api_id: String,
    /// 该计划判定的外部 artifact。控制矩阵用它把 primary 配对到正确的外部实现。
    foreign_artifact: String,
    client_variant: &'static str,
    dir: String,
    package: String,
    main_rs_sha256: String,
    /// 该客户端是否引用外部触发入口。同步 stub（没有触发符号）不能与它配对。
    references_trigger: bool,
}

#[derive(Serialize)]
struct RefusedRecord {
    plan_id: String,
    api_id: String,
    client_variant: String,
    reason_token: &'static str,
}

#[derive(Serialize)]
struct ForeignBuildEntry {
    id: String,
    source: String,
    source_sha256: String,
    provides_trigger_symbol: bool,
}

#[derive(Serialize)]
struct GenerationManifest {
    schema_version: &'static str,
    run_id: String,
    adapter_id: String,
    component_crate: String,
    component_version: Option<String>,
    output_root: String,
    generated: Vec<GeneratedRecord>,
    refused: Vec<RefusedRecord>,
    foreign_builds: Vec<ForeignBuildEntry>,
    notes: Vec<&'static str>,
}

#[derive(Args)]
pub struct GenerateSafeClientArgs {
    /// `plan-witnesses` 写出的 witness-plans.jsonl。
    #[arg(long = "plans")]
    plans: PathBuf,
    /// 冻结的 adapter（中性 API 表面）。
    #[arg(long = "adapter")]
    adapter: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    /// 仓库根目录，用于解析 adapter 里的相对路径。
    #[arg(long = "repo-root", default_value = ".")]
    repo_root: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

pub fn run(args: GenerateSafeClientArgs) -> Result<CommandStatus, CliError> {
    let plans: Vec<PlanRecord> = read_jsonl(&args.plans, args.max_line_bytes)?
        .into_iter()
        .map(|located| located.value)
        .collect();
    let adapter_text = std::fs::read_to_string(&args.adapter).map_err(|error| {
        CliError::input("BW-IO", format!("{}: {}", args.adapter.display(), error))
    })?;
    let adapter = Adapter::parse(&adapter_text)
        .map_err(|error| CliError::input("BW-SAFE-CLIENT-ADAPTER", error))?;
    let repo_root = args.repo_root.canonicalize().map_err(|error| {
        CliError::input(
            "BW-SAFE-CLIENT-REPO-ROOT",
            format!("{}: {error}", args.repo_root.display()),
        )
    })?;

    let mut manifest = GenerationManifest {
        schema_version: SAFE_CLIENT_SCHEMA_V01,
        run_id: plans.first().map(|p| p.run_id.clone()).unwrap_or_default(),
        adapter_id: adapter.adapter_id.clone(),
        component_crate: adapter.target.crate_name.clone(),
        component_version: adapter.target.version.clone(),
        output_root: args.output_dir.display().to_string(),
        generated: Vec::new(),
        refused: Vec::new(),
        foreign_builds: adapter
            .foreign_builds
            .iter()
            .map(|build| {
                let absolute = resolve_foreign_source(&repo_root, &build.source);
                let bytes = std::fs::read(&absolute).unwrap_or_default();
                ForeignBuildEntry {
                    id: build.id.clone(),
                    source: absolute.display().to_string(),
                    source_sha256: hex_digest(Sha256::digest(bytes)),
                    provides_trigger_symbol: build.provides_trigger_symbol,
                }
            })
            .collect(),
        notes: vec![
            "clients are forbidden-unsafe crates; UB can only come from the analyzed component",
            "client_variant tokens are referenced by the controls matrix (bw.controls/0.1)",
            "refusals are coverage gaps, not errors",
        ],
    };

    // dir_name → 实际写出的文件相对名。条件 build.rs 意味着不能假设每个 crate
    // 都是三个文件；清单以写出为准。
    let mut written_by_dir = BTreeMap::<String, Vec<String>>::new();
    for record in &plans {
        for variant in exportable_variants(&record.plan, &adapter) {
            match generate_client(&record.plan, variant, &adapter, &repo_root) {
                Ok(client) => {
                    let written = write_client(&args.output_dir, &client)?;
                    written_by_dir.insert(client.dir_name.clone(), written);
                    manifest.generated.push(GeneratedRecord {
                        plan_id: record.plan.plan_id.clone(),
                        api_id: record.api_id.clone(),
                        foreign_artifact: record.plan.hand_off.foreign_artifact.clone(),
                        client_variant: variant.token(),
                        dir: args.output_dir.join(&client.dir_name).display().to_string(),
                        package: client.package_name.clone(),
                        main_rs_sha256: client.main_rs_sha256.clone(),
                        references_trigger: variant != ClientVariant::NoTrigger,
                    });
                }
                Err(refusal) => manifest.refused.push(RefusedRecord {
                    plan_id: record.plan.plan_id.clone(),
                    api_id: record.api_id.clone(),
                    client_variant: variant.token().to_owned(),
                    reason_token: refusal.token(),
                }),
            }
        }
    }

    // 决定性：同一输入重复运行逐字节一致。
    manifest.generated.sort_by(|left, right| {
        (&left.plan_id, left.client_variant).cmp(&(&right.plan_id, right.client_variant))
    });
    manifest.refused.sort_by(|left, right| {
        (&left.plan_id, &left.client_variant).cmp(&(&right.plan_id, &right.client_variant))
    });

    std::fs::create_dir_all(&args.output_dir)?;
    let manifest_path = args.output_dir.join("generation-manifest.json");
    write_json_file(&manifest_path, &manifest)?;

    // 客户端清单单独成行，供 run-safe-client 精确读取（manifest JSON 不逐行）。
    let clients_path = args.output_dir.join("clients.jsonl");
    write_records(&clients_path, &manifest.generated)?;

    // 清单覆盖全部产物：两个顶层文件加每个客户端 crate 实际写出的文件。
    // verify-run 对未登记文件零容忍，漏一个都会让整个 run 目录不可复核。
    let mut checksum_files = Vec::<(String, std::path::PathBuf)>::new();
    checksum_files.push(("clients.jsonl".to_owned(), clients_path));
    checksum_files.push(("generation-manifest.json".to_owned(), manifest_path.clone()));
    for client in &manifest.generated {
        let root = std::path::PathBuf::from(&client.dir);
        let dir_name = root
            .strip_prefix(&args.output_dir)
            .expect("generated dir 记录在 output_dir 之下")
            .to_string_lossy()
            .to_string();
        for relative in &written_by_dir[dir_name.as_str()] {
            checksum_files.push((relative.clone(), args.output_dir.join(relative)));
        }
    }
    crate::commands::write_checksums(&checksum_files, &args.output_dir.join("checksums.sha256"))?;

    let status = serde_json::json!({
        "kind": "safe-clients",
        "run_id": manifest.run_id,
        "manifest": manifest_path,
        "generated": manifest.generated.len(),
        "refused": manifest.refused.len(),
        "foreign_builds": manifest.foreign_builds.len(),
    });
    crate::commands::write_json_stdout(&status)?;
    Ok(CommandStatus::Success)
}

fn write_client(root: &std::path::Path, client: &GeneratedClient) -> Result<Vec<String>, CliError> {
    let dir = root.join(&client.dir_name);
    let dir_name = &client.dir_name;
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(dir.join("Cargo.toml"), &client.cargo_toml)?;
    // 组件自带外部库时 build_rs 为空：客户端不链接第二份外部实现，文件不写出。
    let mut written = vec![format!("{dir_name}/Cargo.toml")];
    if !client.build_rs.is_empty() {
        std::fs::write(dir.join("build.rs"), &client.build_rs)?;
        written.push(format!("{dir_name}/build.rs"));
    }
    std::fs::write(dir.join("src").join("main.rs"), &client.main_rs)?;
    written.push(format!("{dir_name}/src/main.rs"));
    Ok(written)
}
