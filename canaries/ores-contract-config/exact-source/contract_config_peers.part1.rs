use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde_json::{Value as JsonValue, json};
use walkdir::{DirEntry, WalkDir};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const CONTRACTS_DIRECTORY: &str = "contracts";
const CONFIG_FILE: &str = "contracts.config.json";
const JSON_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_CONFIG_FILES: usize = 128;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_WALK_DEPTH: usize = 16;
const CONFLICT_MARKERS: [&str; 3] = ["<<<<<<<", "=======", ">>>>>>>"];
const GENERATED_COMPONENTS: [&str; 10] = [
    ".typespec-json-schema-validator",
    "artifacts",
    "build",
    "dist",
    "evidence",
    "generated",
    "node_modules",
    "out",
    "target",
    "tmp",
];

/// Inspect `contracts.config.json` files that declare TypeSpec and JSON Schema
/// peer authorities in separate source directories.
///
/// This is repository-shape lint only. It never transpiles TypeSpec, compares
/// semantics, or writes either authority. Canonical TJSV remains responsible
/// for producing comparison-only Schema B and comparing it with the separately
/// authored Draft 2020-12 JSON Schema.
pub(super) fn augment_contract_config_peer_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let contracts_root = options.path.join(CONTRACTS_DIRECTORY);
    let root_metadata = match fs::symlink_metadata(&contracts_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return report.finalize(),
        Err(error) => {
            report.push(
                Finding::error(
                    "contract-config-root-unreadable",
                    format!("contracts root metadata could not be read: {error}"),
                )
                .with_target(CONTRACTS_DIRECTORY),
            );
            return report.finalize();
        }
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        // The existing nested-peer audit owns the canonical contracts-root
        // finding. Avoid emitting a second contradictory diagnosis here.
        return report.finalize();
    }

    let mut configs = Vec::<PathBuf>::new();
    let mut overflow_reported = false;
    for result in WalkDir::new(&contracts_root)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_entry(should_descend)
    {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                let target = error.path().map_or_else(
                    || CONTRACTS_DIRECTORY.to_owned(),
                    |path| relative_display(&options.path, path),
                );
                report.push(
                    Finding::warning(
                        "contract-config-walk-failed",
                        format!("could not inspect part of the contracts tree: {error}"),
                    )
                    .with_target(target),
                );
                continue;
            }
        };
        if entry.file_name() != CONFIG_FILE {
            continue;
        }
        if configs.len() >= MAX_CONFIG_FILES {
            if !overflow_reported {
                report.push(
                    Finding::error(
                        "contract-config-file-limit",
                        format!(
                            "more than {MAX_CONFIG_FILES} {CONFIG_FILE} files were discovered; split or narrow the contract tree"
                        ),
                    )
                    .with_target(CONTRACTS_DIRECTORY),
                );
                overflow_reported = true;
            }
            continue;
        }
        configs.push(entry.path().to_path_buf());
    }

    report.insert_metadata("contractConfigCandidateCount", json!(configs.len()));
    let mut valid_pairs = 0usize;
    for config_path in configs {
        let before = report.issue_count();
        audit_config(&options.path, &config_path, &mut report);
        if report.issue_count() == before {
            valid_pairs += 1;
        }
    }
    report.insert_metadata("contractConfigValidPeerPairCount", json!(valid_pairs));
    if valid_pairs > 0 {
        report.push(
            Finding::info(
                "contract-config-peer-authorities-inspected",
                format!(
                    "inspected {valid_pairs} config-declared TypeSpec/JSON Schema peer-authority pair{}; semantic parity remains TJSV-owned",
                    if valid_pairs == 1 { "" } else { "s" }
                ),
            )
            .with_target(CONTRACTS_DIRECTORY),
        );
    }
    report.finalize()
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !GENERATED_COMPONENTS.contains(&name.as_ref()) && name != ".git"
}

fn audit_config(root: &Path, config_path: &Path, report: &mut CommandReport) {
    let target = relative_display(root, config_path);
    let Some(text) = read_regular_bounded_file(root, config_path, "contract config", report) else {
        return;
    };
    let document = match serde_json::from_str::<JsonValue>(&text) {
        Ok(document) => document,
        Err(error) => {
            report.push(
                Finding::error(
                    "contract-config-invalid-json",
                    format!("{CONFIG_FILE} is not valid JSON: {error}"),
                )
                .with_target(target),
            );
            return;
        }
    };
    let Some(object) = document.as_object() else {
        report.push(
            Finding::error(
                "contract-config-root-shape",
                format!("{CONFIG_FILE} root must be an object"),
            )
            .with_target(target),
        );
        return;
    };

    let typespec = config_string(object.get("typespec"), "typespec", &target, report);
    let schema = config_string(object.get("jsonSchema"), "jsonSchema", &target, report);
    let (Some(typespec), Some(schema)) = (typespec, schema) else {
        return;
    };
    let Some(home) = config_path.parent() else {
        return;
    };
    let typespec_path = resolve_authority_path(root, home, &typespec, "TypeSpec", &target, report);
    let schema_path = resolve_authority_path(root, home, &schema, "JSON Schema", &target, report);
    let (Some(typespec_path), Some(schema_path)) = (typespec_path, schema_path) else {
        return;
    };
    if typespec_path == schema_path {
        report.push(
            Finding::error(
                "contract-config-peer-path-alias",
                "TypeSpec and JSON Schema must be distinct independently editable source files",
            )
            .with_target(target.clone()),
        );
        return;
    }
    if typespec_path.extension().and_then(|value| value.to_str()) != Some("tsp") {
        report.push(
            Finding::error(
                "contract-config-typespec-extension",
                "config-declared TypeSpec authority must be a .tsp source file",
            )
            .with_target(relative_display(root, &typespec_path)),
        );
    }
    if schema_path.extension().and_then(|value| value.to_str()) != Some("json") {
        report.push(
            Finding::error(
                "contract-config-json-schema-extension",
                "config-declared JSON Schema authority must be a .json source file",
            )
            .with_target(relative_display(root, &schema_path)),
        );
    }

    audit_typespec(root, &typespec_path, report);
    audit_json_schema(root, &schema_path, report);
}

fn config_string(
    value: Option<&JsonValue>,
    field: &str,
    target: &str,
    report: &mut CommandReport,
) -> Option<String> {
    let Some(value) = value else {
        report.push(
            Finding::error(
                "contract-config-peer-field-missing",
                format!("{CONFIG_FILE} must declare the {field} peer-authority path"),
            )
            .with_target(target.to_owned()),
        );
        return None;
    };
    let Some(value) = value.as_str() else {
        report.push(
            Finding::error(
                "contract-config-peer-field-shape",
                format!("{CONFIG_FILE} field {field} must be a non-empty string"),
            )
            .with_target(target.to_owned()),
