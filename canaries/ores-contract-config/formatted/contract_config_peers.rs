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
        );
        return None;
    };
    if value.trim().is_empty() {
        report.push(
            Finding::error(
                "contract-config-peer-field-empty",
                format!("{CONFIG_FILE} field {field} must not be empty"),
            )
            .with_target(target.to_owned()),
        );
        return None;
    }
    Some(value.to_owned())
}

fn resolve_authority_path(
    root: &Path,
    home: &Path,
    relative: &str,
    authority: &str,
    target: &str,
    report: &mut CommandReport,
) -> Option<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        report.push(
            Finding::error(
                "contract-config-authority-path-unsafe",
                format!("{authority} authority path must be a normalized repository-relative path inside its contract home"),
            )
            .with_target(target.to_owned()),
        );
        return None;
    }
    if path.components().any(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        GENERATED_COMPONENTS.contains(&name.to_string_lossy().as_ref())
    }) {
        report.push(
            Finding::error(
                "contract-config-generated-authority",
                format!("{authority} authority must not live below a generated, evidence, dependency, build, output, target, or temporary directory"),
            )
            .with_target(relative_display(root, &home.join(path))),
        );
        return None;
    }

    let resolved = home.join(path);
    let mut cursor = home.to_path_buf();
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        cursor.push(name);
        let metadata = match fs::symlink_metadata(&cursor) {
            Ok(metadata) => metadata,
            Err(error) => {
                report.push(
                    Finding::error(
                        "contract-config-authority-unreadable",
                        format!("{authority} authority path could not be inspected: {error}"),
                    )
                    .with_target(relative_display(root, &resolved)),
                );
                return None;
            }
        };
        if metadata.file_type().is_symlink() {
            report.push(
                Finding::error(
                    "contract-config-authority-symlink",
                    format!("{authority} authority path must not traverse a symbolic link"),
                )
                .with_target(relative_display(root, &cursor)),
            );
            return None;
        }
    }
    Some(resolved)
}

fn audit_typespec(root: &Path, path: &Path, report: &mut CommandReport) {
    let target = relative_display(root, path);
    let Some(text) = read_regular_bounded_file(root, path, "TypeSpec", report) else {
        return;
    };
    if text.trim().is_empty() {
        report.push(
            Finding::error(
                "contract-config-typespec-empty",
                "config-declared TypeSpec authority must not be empty",
            )
            .with_target(target),
        );
        return;
    }
    audit_conflict_markers(
        &text,
        "contract-config-typespec-conflict-marker",
        &target,
        report,
    );
}

fn audit_json_schema(root: &Path, path: &Path, report: &mut CommandReport) {
    let target = relative_display(root, path);
    let Some(text) = read_regular_bounded_file(root, path, "JSON Schema", report) else {
        return;
    };
    audit_conflict_markers(
        &text,
        "contract-config-json-schema-conflict-marker",
        &target,
        report,
    );
    let document = match serde_json::from_str::<JsonValue>(&text) {
        Ok(document) => document,
        Err(error) => {
            report.push(
                Finding::error(
                    "contract-config-json-schema-invalid",
                    format!("config-declared JSON Schema is not valid JSON: {error}"),
                )
                .with_target(target),
            );
            return;
        }
    };
    let Some(object) = document.as_object() else {
        report.push(
            Finding::error(
                "contract-config-json-schema-root-shape",
                "config-declared JSON Schema root must be an object",
            )
            .with_target(target),
        );
        return;
    };
    if object.get("$schema").and_then(JsonValue::as_str) != Some(JSON_SCHEMA_DRAFT) {
        report.push(
            Finding::error(
                "contract-config-json-schema-draft",
                format!("config-declared JSON Schema must declare {JSON_SCHEMA_DRAFT}"),
            )
            .with_target(target),
        );
    }
}

fn read_regular_bounded_file(
    root: &Path,
    path: &Path,
    authority: &str,
    report: &mut CommandReport,
) -> Option<String> {
    let target = relative_display(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            report.push(
                Finding::error(
                    "contract-config-file-unreadable",
                    format!("{authority} source metadata could not be read: {error}"),
                )
                .with_target(target),
            );
            return None;
        }
    };
    if metadata.file_type().is_symlink() {
        report.push(
            Finding::error(
                "contract-config-file-symlink",
                format!("{authority} source must not be a symbolic link"),
            )
            .with_target(target),
        );
        return None;
    }
    if !metadata.is_file() {
        report.push(
            Finding::error(
                "contract-config-file-not-regular",
                format!("{authority} source must be a regular file"),
            )
            .with_target(target),
        );
        return None;
    }
    if metadata.len() > MAX_FILE_BYTES {
        report.push(
            Finding::error(
                "contract-config-file-too-large",
                format!("{authority} source exceeds the {MAX_FILE_BYTES}-byte audit bound"),
            )
            .with_target(target),
        );
        return None;
    }
    match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) => {
            report.push(
                Finding::error(
                    "contract-config-file-not-utf8",
                    format!("{authority} source could not be read as UTF-8: {error}"),
                )
                .with_target(target),
            );
            None
        }
    }
}

fn audit_conflict_markers(text: &str, code: &str, target: &str, report: &mut CommandReport) {
    let markers = text
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            CONFLICT_MARKERS
                .iter()
                .find(|marker| line.starts_with(*marker))
                .copied()
        })
        .collect::<BTreeSet<_>>();
    if !markers.is_empty() {
        report.push(
            Finding::error(
                code,
                format!(
                    "authored authority contains unresolved conflict marker{}: {}",
                    if markers.len() == 1 { "" } else { "s" },
                    markers.into_iter().collect::<Vec<_>>().join(", ")
                ),
            )
            .with_target(target.to_owned()),
        );
    }
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value as JsonValue;
    use tempfile::tempdir;

    use super::augment_contract_config_peer_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(setup: impl FnOnce(&std::path::Path)) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        setup(root.path());
        augment_contract_config_peer_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn write_hhm_layout(root: &std::path::Path) {
        let home = root.join("contracts/platform");
        fs::create_dir_all(home.join("typespec")).expect("TypeSpec directory");
        fs::create_dir_all(home.join("json-schema")).expect("JSON Schema directory");
        fs::write(
            home.join("typespec/main.tsp"),
            "namespace Hhaus.Platform.V1;\nmodel Reservation { id: string; }\n",
        )
        .expect("TypeSpec authority");
        fs::write(
            home.join("json-schema/contract.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://example.test/platform.schema.json","$defs":{"Reservation":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}}}"#,
        )
        .expect("JSON Schema authority");
        fs::write(
            home.join("contracts.config.json"),
            r#"{"typespec":"typespec/main.tsp","jsonSchema":"json-schema/contract.schema.json","out":"../../generated/platform","target":"../../target/platform"}"#,
        )
        .expect("contract config");
    }

    #[test]
    fn accepts_hhm_split_peer_authority_layout() {
        let report = audit(write_hhm_layout);
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("contractConfigValidPeerPairCount"),
            Some(&JsonValue::from(1))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == "contract-config-peer-authorities-inspected" })
        );
    }

    #[test]
    fn rejects_missing_independent_peer() {
        let report = audit(|root| {
            write_hhm_layout(root);
            fs::write(
                root.join("contracts/platform/contracts.config.json"),
                r#"{"typespec":"typespec/main.tsp"}"#,
            )
            .expect("contract config");
        });
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "contract-config-peer-field-missing")
        );
    }

    #[test]
    fn rejects_generated_source_masquerading_as_authority() {
        let report = audit(|root| {
            write_hhm_layout(root);
            let home = root.join("contracts/platform");
            fs::create_dir_all(home.join("generated")).expect("generated directory");
            fs::write(
                home.join("generated/authored.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("generated witness");
            fs::write(
                home.join("contracts.config.json"),
                r#"{"typespec":"typespec/main.tsp","jsonSchema":"generated/authored.schema.json"}"#,
            )
            .expect("contract config");
        });
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "contract-config-generated-authority")
        );
    }

    #[test]
    fn rejects_path_alias_and_parent_traversal() {
        let alias = audit(|root| {
            write_hhm_layout(root);
            fs::write(
                root.join("contracts/platform/contracts.config.json"),
                r#"{"typespec":"typespec/main.tsp","jsonSchema":"typespec/main.tsp"}"#,
            )
            .expect("contract config");
        });
        assert!(
            alias
                .findings
                .iter()
                .any(|finding| finding.code == "contract-config-peer-path-alias")
        );

        let traversal = audit(|root| {
            write_hhm_layout(root);
            fs::write(
                root.join("contracts/platform/contracts.config.json"),
                r#"{"typespec":"../elsewhere/main.tsp","jsonSchema":"json-schema/contract.schema.json"}"#,
            )
            .expect("contract config");
        });
        assert!(
            traversal
                .findings
                .iter()
                .any(|finding| finding.code == "contract-config-authority-path-unsafe")
        );
    }

    #[test]
    fn rejects_non_draft_2020_12_schema() {
        let report = audit(|root| {
            write_hhm_layout(root);
            fs::write(
                root.join("contracts/platform/json-schema/contract.schema.json"),
                r#"{"$schema":"http://json-schema.org/draft-07/schema#"}"#,
            )
            .expect("JSON Schema authority");
        });
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "contract-config-json-schema-draft")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_authority_component() {
        use std::os::unix::fs::symlink;

        let report = audit(|root| {
            write_hhm_layout(root);
            let home = root.join("contracts/platform");
            fs::remove_dir_all(home.join("typespec")).expect("remove TypeSpec directory");
            let outside = root.join("real-typespec");
            fs::create_dir_all(&outside).expect("real TypeSpec directory");
            fs::write(outside.join("main.tsp"), "model Packet {}\n").expect("TypeSpec");
            symlink(&outside, home.join("typespec")).expect("symlink TypeSpec directory");
        });
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "contract-config-authority-symlink")
        );
    }
}
