use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    V3_2_BOUNDARY_INDEX_SCHEMA_V1, V32BoundaryEvidenceKind, V32BoundaryEvidenceRef,
    V32BoundaryIndexRecord, V32BoundaryKind, V32BuildabilityRecord, V32BuildabilityStatus,
    V32CorpusManifestRecord, V32CorpusSourceKind, validate_v3_2_boundary_index,
    validate_v3_2_buildability, validate_v3_2_corpus_manifest,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, strip_rust_comments, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct IndexBoundariesArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    buildability: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    logs_root: PathBuf,
    #[arg(long)]
    run_id: String,
    /// callback-retention API map TOML；可重复。声明的安全 API 也会被识别为边界。
    #[arg(long = "api-map")]
    api_maps: Vec<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

/// API map 里声明的一个注册方法，按方法名索引。
///
/// `classify_foreign_callback_handoff` 只认裸 FFI 调用：它要求显式的 user_data 参数。
/// 经 contract 包装的安全 API（`connection.update_hook(Some(closure))`）没有这个参数，
/// 因而整条链在 candidate 阶段就断了，尽管 compiler 侧已经能按同一份 API map 分类。
/// 本索引让 boundary 扫描消费同一份声明，两侧不再各说各话。
#[derive(Clone, Debug)]
struct ContractApiMethod {
    method: String,
    api_path: String,
    role: bw_model::RegistrationRole,
}

#[derive(Serialize)]
struct IndexBoundariesOutput {
    kind: &'static str,
    crate_count: u64,
    boundary_count: u64,
    negative_count: u64,
    skipped_count: u64,
    output: String,
}

#[derive(Clone, Debug)]
struct SourceLine {
    path: String,
    line_number: u64,
    text: String,
    enclosing_symbol: Option<String>,
}

#[derive(Clone, Debug)]
struct BoundaryHit {
    kind: V32BoundaryKind,
    api_path: String,
    evidence: V32BoundaryEvidenceRef,
    confidence: &'static str,
    note: &'static str,
}

pub fn run(args: IndexBoundariesArgs) -> Result<CommandStatus, CliError> {
    let manifest_records =
        read_jsonl::<V32CorpusManifestRecord>(&args.manifest, args.max_line_bytes)?;
    validate_v3_2_corpus_manifest(manifest_records.clone())?;
    let buildability_records =
        read_jsonl::<V32BuildabilityRecord>(&args.buildability, args.max_line_bytes)?;
    validate_v3_2_buildability(buildability_records.clone())?;

    fs::create_dir_all(&args.logs_root)?;
    let manifest_dir = args.manifest.parent().unwrap_or_else(|| Path::new("."));
    let manifest_by_crate = manifest_records
        .into_iter()
        .map(|located| (located.value.crate_id.clone(), located.value))
        .collect::<BTreeMap<_, _>>();

    let contract_apis = load_contract_apis(&args.api_maps)?;

    let mut records = Vec::<V32BoundaryIndexRecord>::new();
    let mut crate_count = 0_u64;
    let mut skipped_count = 0_u64;

    for located in buildability_records {
        let buildability = located.value;
        if buildability.status != V32BuildabilityStatus::Buildable {
            skipped_count += 1;
            continue;
        }
        let Some(manifest) = manifest_by_crate.get(&buildability.crate_id) else {
            return Err(CliError::input(
                "BW-BOUNDARY-MANIFEST-MISSING",
                format!(
                    "buildability 中的 crate_id {} 在 corpus manifest 中不存在",
                    buildability.crate_id
                ),
            ));
        };
        crate_count += 1;

        let crate_records = index_one_crate(&args, manifest_dir, manifest, &contract_apis)?;
        records.extend(crate_records);
    }

    validate_v3_2_boundary_index(records.iter().cloned().enumerate().map(|(index, value)| {
        bw_model::Located {
            path: args.output.clone(),
            line: index + 1,
            value,
        }
    }))?;
    write_records(&args.output, &records)?;

    let boundary_count = records
        .iter()
        .filter(|record| record.boundary_kind != V32BoundaryKind::NegativeSummary)
        .count() as u64;
    let negative_count = records.len() as u64 - boundary_count;
    let summary = IndexBoundariesOutput {
        kind: "v3-2-boundary-index",
        crate_count,
        boundary_count,
        negative_count,
        skipped_count,
        output: args.output.display().to_string(),
    };
    crate::commands::write_json_stdout(&summary)?;
    Ok(CommandStatus::Success)
}

fn index_one_crate(
    args: &IndexBoundariesArgs,
    manifest_dir: &Path,
    manifest: &V32CorpusManifestRecord,
    contract_apis: &[ContractApiMethod],
) -> Result<Vec<V32BoundaryIndexRecord>, CliError> {
    let source_path = resolve_local_source(manifest_dir, manifest)?;
    let crate_label = sanitize_id(&manifest.crate_id);
    let log_ref = format!("index/{crate_label}.log");
    let log_path = args.logs_root.join(&log_ref);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let source_lines = collect_source_lines(&source_path)?;
    let hits = scan_source_lines(&source_lines, contract_apis);
    let mut records = Vec::<V32BoundaryIndexRecord>::new();

    if hits.is_empty() {
        records.push(V32BoundaryIndexRecord {
            schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
            run_id: args.run_id.clone(),
            crate_id: manifest.crate_id.clone(),
            boundary_id: format!("boundary:{crate_label}:negative-summary"),
            boundary_kind: V32BoundaryKind::NegativeSummary,
            api_path: None,
            evidence_refs: vec![V32BoundaryEvidenceRef {
                kind: V32BoundaryEvidenceKind::Manifest,
                path: "Cargo.toml".to_owned(),
                line_start: None,
                line_end: None,
            }],
            confidence: "high".to_owned(),
            notes: vec!["no supported boundary pattern found in scanned Rust sources".to_owned()],
        });
    } else {
        for (ordinal, hit) in hits.into_iter().enumerate() {
            records.push(V32BoundaryIndexRecord {
                schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
                run_id: args.run_id.clone(),
                crate_id: manifest.crate_id.clone(),
                boundary_id: format!(
                    "boundary:{crate_label}:{}:{:04}",
                    boundary_kind_slug(hit.kind),
                    ordinal + 1
                ),
                boundary_kind: hit.kind,
                api_path: Some(hit.api_path),
                evidence_refs: vec![hit.evidence],
                confidence: hit.confidence.to_owned(),
                notes: vec![hit.note.to_owned(), format!("scan_log={log_ref}")],
            });
        }
    }

    write_log(&log_path, manifest, source_lines.len(), &records)?;
    Ok(records)
}

fn resolve_local_source(
    manifest_dir: &Path,
    record: &V32CorpusManifestRecord,
) -> Result<PathBuf, CliError> {
    match record.source_kind {
        V32CorpusSourceKind::LocalArchive | V32CorpusSourceKind::RegistrySnapshot => {
            let path = PathBuf::from(&record.source_ref);
            if path.is_absolute() {
                Ok(path)
            } else {
                Ok(manifest_dir.join(path))
            }
        }
        V32CorpusSourceKind::CratesIo | V32CorpusSourceKind::GitArchive => Err(CliError::input(
            "BW-BOUNDARY-SOURCE-NOT-MATERIALIZED",
            format!("crate {} source 尚未物化", record.crate_id),
        )),
    }
}

fn collect_source_lines(source_path: &Path) -> Result<Vec<SourceLine>, CliError> {
    let mut files = Vec::<PathBuf>::new();
    collect_rs_files(&source_path.join("src"), &mut files)?;
    files.sort();

    let mut lines = Vec::<SourceLine>::new();
    for file in files {
        let text = fs::read_to_string(&file)
            .map_err(|error| CliError::input("BW-IO", format!("{}: {}", file.display(), error)))?;
        let relative = file
            .strip_prefix(source_path)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let mut block_comment_depth = 0;
        let mut brace_depth = 0_i64;
        let mut scopes = Vec::<SourceScope>::new();
        let mut pending_symbol = None::<String>;
        for (index, line) in text.lines().enumerate() {
            let scan_text = strip_rust_comments(line, &mut block_comment_depth);
            if scan_text.trim().is_empty() {
                brace_depth = (brace_depth + brace_delta(&scan_text)).max(0);
                continue;
            }
            while scopes
                .last()
                .is_some_and(|scope| brace_depth <= scope.parent_depth)
            {
                scopes.pop();
            }
            let before_depth = brace_depth;
            let symbol = extract_symbol(&scan_text);
            let enclosing_symbol = symbol
                .clone()
                .or_else(|| scopes.last().map(|scope| scope.symbol.clone()));
            let ends_with_semicolon = scan_text.trim_end().ends_with(';');
            let after_depth = (before_depth + brace_delta(&scan_text)).max(0);
            lines.push(SourceLine {
                path: relative.clone(),
                line_number: index as u64 + 1,
                text: scan_text,
                enclosing_symbol,
            });
            if let Some(symbol) = symbol.clone() {
                if after_depth > before_depth {
                    scopes.push(SourceScope {
                        symbol,
                        parent_depth: before_depth,
                    });
                    pending_symbol = None;
                } else if !ends_with_semicolon {
                    pending_symbol = Some(symbol);
                } else {
                    pending_symbol = None;
                }
            } else if let Some(symbol) = pending_symbol.take() {
                if after_depth > before_depth {
                    scopes.push(SourceScope {
                        symbol,
                        parent_depth: before_depth,
                    });
                } else {
                    pending_symbol = Some(symbol);
                }
            }
            brace_depth = after_depth;
        }
    }
    Ok(lines)
}

#[derive(Clone, Debug)]
struct SourceScope {
    symbol: String,
    parent_depth: i64,
}

fn brace_delta(text: &str) -> i64 {
    text.chars().fold(0, |depth, character| match character {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), CliError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", dir.display(), error)))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name == "target" || file_name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect_rs_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

/// 从 API map 建立方法名索引。未提供 API map 时返回空表，扫描退回纯 FFI 模式。
fn load_contract_apis(paths: &[PathBuf]) -> Result<Vec<ContractApiMethod>, CliError> {
    let mut methods = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|error| {
            CliError::input(
                "BW-BOUNDARY-API-MAP",
                format!("{}: {error}", path.display()),
            )
        })?;
        let api_map = bw_model::CallbackRetentionApiMap::from_toml_str(&text).map_err(|error| {
            CliError::input(
                "BW-BOUNDARY-API-MAP",
                format!("{}: {error}", path.display()),
            )
        })?;
        for entry in api_map.apis {
            // rust_path 的最后一段是方法名；没有分段的条目无法按调用点匹配。
            let Some(method) = entry.rust_path.rsplit("::").next().map(ToOwned::to_owned) else {
                continue;
            };
            if method.is_empty() {
                continue;
            }
            let role = match entry.contract_api_id.as_str() {
                "api:register" => bw_model::RegistrationRole::Register,
                "api:unregister" => bw_model::RegistrationRole::Unregister,
                "api:replace" => bw_model::RegistrationRole::Replace,
                _ => continue,
            };
            methods.push(ContractApiMethod {
                method,
                api_path: entry.rust_path.clone(),
                role,
            });
        }
    }
    methods.sort_by(|left, right| {
        left.api_path
            .cmp(&right.api_path)
            .then(left.method.cmp(&right.method))
    });
    methods.dedup_by(|left, right| left.api_path == right.api_path && left.method == right.method);
    Ok(methods)
}

fn scan_source_lines(
    lines: &[SourceLine],
    contract_apis: &[ContractApiMethod],
) -> Vec<BoundaryHit> {
    let mut hits = BTreeMap::<(V32BoundaryKind, String, u64, String), BoundaryHit>::new();
    for (index, line) in lines.iter().enumerate() {
        for hit in classify_line(line) {
            let key = (
                hit.kind,
                hit.evidence.path.clone(),
                hit.evidence.line_start.unwrap_or_default(),
                hit.api_path.clone(),
            );
            hits.entry(key).or_insert(hit);
        }
        for hit in classify_contract_api_call(line, contract_apis) {
            let key = (
                hit.kind,
                hit.evidence.path.clone(),
                hit.evidence.line_start.unwrap_or_default(),
                hit.api_path.clone(),
            );
            hits.entry(key).or_insert(hit);
        }
        if let Some(hit) = classify_foreign_callback_handoff(lines, index) {
            let key = (
                hit.kind,
                hit.evidence.path.clone(),
                hit.evidence.line_start.unwrap_or_default(),
                hit.api_path.clone(),
            );
            hits.entry(key).or_insert(hit);
        }
    }
    hits.into_values().collect()
}

/// 匹配 API map 声明的方法调用。
///
/// 只按方法名匹配（`rust_path` 的最后一段），因此是 source-level 启发式，confidence
/// 记为 medium：候选不是结论，后续 compiler 事实与 contract 审计才决定是否成链。
/// 匹配面被 API map 限定，未声明的方法一律不产生 hit。
fn classify_contract_api_call(
    line: &SourceLine,
    contract_apis: &[ContractApiMethod],
) -> Vec<BoundaryHit> {
    let text = &line.text;
    let mut hits = Vec::new();
    for api in contract_apis {
        let needle = format!(".{}(", api.method);
        let Some(position) = text.find(&needle) else {
            continue;
        };
        let arguments = &text[position + needle.len()..];
        let kind = match api.role {
            bw_model::RegistrationRole::Register | bw_model::RegistrationRole::Replace => {
                // 注册必须带一个 callback；`None` 是注销而不是注册。
                if !arguments.contains("Some(") {
                    continue;
                }
                V32BoundaryKind::CallbackRegistration
            }
            bw_model::RegistrationRole::Unregister => {
                if !arguments.contains("None") {
                    continue;
                }
                V32BoundaryKind::CallbackUnregistration
            }
        };
        hits.push(BoundaryHit {
            kind,
            api_path: api.api_path.clone(),
            evidence: V32BoundaryEvidenceRef {
                kind: V32BoundaryEvidenceKind::SourceSpan,
                path: line.path.clone(),
                line_start: Some(line.line_number),
                line_end: Some(line.line_number),
            },
            confidence: "medium",
            note: "call to an API declared by the callback-retention contract map",
        });
    }
    hits
}

fn classify_foreign_callback_handoff(lines: &[SourceLine], index: usize) -> Option<BoundaryHit> {
    let line = lines.get(index)?;
    let callee = foreign_ffi_callee(&line.text)?;
    if !looks_like_callback_api(&callee) {
        return None;
    }
    let context = foreign_call_context(lines, index);
    let lower_context = context.to_ascii_lowercase();
    let kind = if has_callback_like_some_argument(&context)
        && has_explicit_callback_context_argument(&context)
    {
        V32BoundaryKind::CallbackRegistration
    } else if lower_context.contains("none")
        && (has_explicit_callback_release_api(&callee)
            || lower_context.contains("null_mut")
            || lower_context.contains("null()"))
    {
        V32BoundaryKind::CallbackUnregistration
    } else {
        return None;
    };

    Some(BoundaryHit {
        kind,
        api_path: api_path_for_foreign_call(line, &callee),
        evidence: V32BoundaryEvidenceRef {
            kind: V32BoundaryEvidenceKind::SourceSpan,
            path: line.path.clone(),
            line_start: Some(line.line_number),
            line_end: Some(line.line_number),
        },
        confidence: "medium",
        note: "callback-like argument passed to callback-oriented FFI API",
    })
}

fn foreign_ffi_callee(line: &str) -> Option<String> {
    let marker = "ffi::";
    let start = line.find(marker)? + marker.len();
    let callee = line[start..]
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>();
    (!callee.is_empty()).then_some(callee)
}

fn looks_like_callback_api(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    lower.contains("hook")
        || lower.contains("callback")
        || lower.contains("trace")
        || lower.contains("authorizer")
        || lower.contains("handler")
}

fn has_explicit_callback_release_api(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    lower.contains("clear")
        || lower.contains("unregister")
        || lower.contains("remove")
        || lower.contains("uninstall")
}

fn has_callback_like_some_argument(context: &str) -> bool {
    let lower = context.to_ascii_lowercase();
    let Some(start) = lower.find("some(") else {
        return false;
    };
    let argument = lower[start + "some(".len()..]
        .trim_start()
        .trim_start_matches('&')
        .split(|character: char| character == ')' || character == ',' || character.is_whitespace())
        .next()
        .unwrap_or("")
        .trim();
    let callback = argument.split("::<").next().unwrap_or(argument);
    let terminal = callback.rsplit("::").next().unwrap_or(callback);
    terminal.contains("callback")
        || terminal.contains("hook")
        || terminal.contains("closure")
        || terminal.contains("trace")
        || terminal.contains("authorizer")
        || terminal.contains("handler")
}

fn has_explicit_callback_context_argument(context: &str) -> bool {
    let lower = context.to_ascii_lowercase();
    lower.contains(" as *mut")
        || lower.contains(" as *const")
        || lower.contains("user_data")
        || lower.contains("userdata")
        || lower.contains("boxed_")
}

fn foreign_call_context(lines: &[SourceLine], index: usize) -> String {
    let line = &lines[index];
    let mut parenthesis_depth = 0_i64;
    let mut context = Vec::new();
    for candidate in lines[index..]
        .iter()
        .take_while(|candidate| candidate.path == line.path)
        .take(8)
    {
        parenthesis_depth += parenthesis_delta(&candidate.text);
        context.push(candidate.text.as_str());
        if parenthesis_depth <= 0 {
            break;
        }
    }
    context.join(" ")
}

fn parenthesis_delta(text: &str) -> i64 {
    text.chars().fold(0, |depth, character| match character {
        '(' => depth + 1,
        ')' => depth - 1,
        _ => depth,
    })
}

fn classify_line(line: &SourceLine) -> Vec<BoundaryHit> {
    let lower = line.text.to_ascii_lowercase();
    let mut hits = Vec::<BoundaryHit>::new();
    let evidence = || V32BoundaryEvidenceRef {
        kind: V32BoundaryEvidenceKind::SourceSpan,
        path: line.path.clone(),
        line_start: Some(line.line_number),
        line_end: Some(line.line_number),
    };

    if lower.contains("extern \"c\"") || lower.contains("extern \"system\"") {
        hits.push(BoundaryHit {
            kind: V32BoundaryKind::NativeLibrary,
            api_path: api_path_for_line(line, "extern"),
            evidence: evidence(),
            confidence: "high",
            note: "extern ABI boundary found in Rust source",
        });
    }

    if looks_like_foreign_retained_pointer(&lower) {
        hits.push(BoundaryHit {
            kind: V32BoundaryKind::ForeignRetainedPointer,
            api_path: api_path_for_line(line, "foreign_retained_pointer"),
            evidence: evidence(),
            confidence: "medium",
            note: "raw pointer or user_data appears near callback/register terminology",
        });
    }

    if looks_like_opaque_handle_transfer(&lower) {
        hits.push(BoundaryHit {
            kind: V32BoundaryKind::OpaqueHandleTransfer,
            api_path: api_path_for_line(line, "opaque_handle"),
            evidence: evidence(),
            confidence: "medium",
            note: "handle-like symbol carries raw pointer across the Rust/native boundary",
        });
    }

    hits
}

fn looks_like_foreign_retained_pointer(lower: &str) -> bool {
    (lower.contains("*mut") || lower.contains("*const") || lower.contains("user_data"))
        && (lower.contains("callback") || lower.contains("register") || lower.contains("handler"))
}

fn looks_like_opaque_handle_transfer(lower: &str) -> bool {
    lower.contains("handle") && (lower.contains("*mut") || lower.contains("*const"))
}

fn extract_symbol(line: &str) -> Option<String> {
    extract_after_keyword(line, "fn")
        .or_else(|| extract_after_keyword(line, "struct"))
        .or_else(|| extract_after_keyword(line, "type"))
}

fn api_path_for_line(line: &SourceLine, fallback: &str) -> String {
    let Some(symbol) = extract_symbol(&line.text).or_else(|| line.enclosing_symbol.clone()) else {
        return fallback.to_owned();
    };
    let source_scope = line
        .path
        .trim_end_matches(".rs")
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("::");
    if source_scope.is_empty() {
        fallback.to_owned()
    } else {
        let source_identity = format!("{source_scope}::{symbol}");
        // Keep public records role-free while preserving stable source-level identity.
        format!(
            "source_api::{:x}",
            Sha256::digest(source_identity.as_bytes())
        )
    }
}

fn api_path_for_foreign_call(line: &SourceLine, callee: &str) -> String {
    let source_scope = line
        .path
        .trim_end_matches(".rs")
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("::");
    if source_scope.is_empty() {
        return "foreign_callback_handoff".to_owned();
    }
    let source_identity = format!("{source_scope}::foreign_callback_handoff::{callee}");
    format!(
        "source_api::{:x}",
        Sha256::digest(source_identity.as_bytes())
    )
}

fn extract_after_keyword(line: &str, keyword: &str) -> Option<String> {
    let marker = format!("{keyword} ");
    let start = line.find(&marker)? + marker.len();
    let tail = &line[start..];
    let symbol = tail
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    if symbol.is_empty() {
        None
    } else {
        Some(symbol)
    }
}

fn boundary_kind_slug(kind: V32BoundaryKind) -> &'static str {
    match kind {
        V32BoundaryKind::NativeLibrary => "native-library",
        V32BoundaryKind::CallbackRegistration => "callback-registration",
        V32BoundaryKind::CallbackUnregistration => "callback-unregistration",
        V32BoundaryKind::ForeignRetainedPointer => "foreign-retained-pointer",
        V32BoundaryKind::OpaqueHandleTransfer => "opaque-handle-transfer",
        V32BoundaryKind::ReturnedBorrow => "returned-borrow",
        V32BoundaryKind::ExternalBuffer => "external-buffer",
        V32BoundaryKind::NegativeSummary => "negative-summary",
    }
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn write_log(
    path: &Path,
    manifest: &V32CorpusManifestRecord,
    scanned_line_count: usize,
    records: &[V32BoundaryIndexRecord],
) -> Result<(), CliError> {
    let mut file = File::create(path)?;
    writeln!(file, "crate_id: {}", manifest.crate_id)?;
    writeln!(file, "source_ref: {}", manifest.source_ref)?;
    writeln!(file, "scanned_line_count: {scanned_line_count}")?;
    writeln!(file, "record_count: {}", records.len())?;
    for record in records {
        writeln!(
            file,
            "{}\t{:?}\t{}",
            record.boundary_id,
            record.boundary_kind,
            record.api_path.as_deref().unwrap_or("-")
        )?;
    }
    Ok(())
}
