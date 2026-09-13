use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value as JsonValue;
use walkdir::{DirEntry, WalkDir};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const MAX_AUTHORITIES: usize = 1_024;
const MAX_FILES: usize = 1_024;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 20;
const SCAN_ROOTS: [&str; 3] = [".github/workflows", "scripts", "tools"];
const SOURCE_EXTENSIONS: [&str; 8] = ["yml", "yaml", "sh", "bash", "mjs", "js", "ts", "py"];
const GENERATED_COMPONENTS: [&str; 11] = [
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
    "vendor",
];

/// Reject repository automation that writes directly to either independently
/// authored contract authority. TypeSpec and authored Draft 2020-12 JSON Schema
/// are source inputs; generated JSON Schema B, reports, IR and other evidence
/// must be written to distinct generated/evidence paths instead.
///
/// Detection is destination-aware: merely reading an authority on the same line
/// as an unrelated output flag or redirect is valid. The audit discovers all
/// authored TypeSpec/JSON-Schema source spellings used by supported repository
/// layouts, including flat/split paths and `contracts.config.json` declarations.
pub(super) fn augment_authority_write_protection_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let authorities = discover_authority_paths(&options.path, &mut report);
    if authorities.is_empty() {
        return report.finalize();
    }

    let files = automation_sources(&options.path, &mut report);
    let mut rejected = 0usize;
    for path in &files {
        rejected += audit_file(&options.path, path, &authorities, &mut report);
    }
    report.insert_metadata(
        "peerAuthorityWriteProtectionAuthorityCount",
        serde_json::json!(authorities.len()),
    );
    report.insert_metadata(
        "peerAuthorityWriteProtectionFileCount",
        serde_json::json!(files.len()),
    );
    report.insert_metadata(
        "peerAuthorityWriteProtectionViolationCount",
        serde_json::json!(rejected),
    );
    report.finalize()
}

fn discover_authority_paths(root: &Path, report: &mut CommandReport) -> BTreeSet<String> {
    let contracts = root.join("contracts");
    if !contracts.is_dir() {
        return BTreeSet::new();
    }

    let mut authorities = BTreeSet::new();
    let mut configs = Vec::new();
    for entry in WalkDir::new(&contracts)
        .follow_links(false)
        .max_depth(MAX_DEPTH)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(should_descend)
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.push(
                    Finding::warning(
                        "peer-authority-write-discovery-failed",
                        format!("part of the contracts tree could not be inspected: {error}"),
                    )
                    .with_target("contracts"),
                );
                continue;
            }
        };
        if entry.file_type().is_symlink() || !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if name == "contracts.config.json" {
            configs.push(entry.path().to_path_buf());
        }
        if is_authored_typespec(entry.path()) || is_authored_schema(entry.path()) {
            insert_authority(root, entry.path(), &mut authorities, report);
        }
    }

    for config in configs {
        discover_config_authorities(root, &config, &mut authorities, report);
    }
    authorities
}

fn insert_authority(
    root: &Path,
    path: &Path,
    authorities: &mut BTreeSet<String>,
    report: &mut CommandReport,
) {
    if authorities.len() >= MAX_AUTHORITIES {
        if !report
            .findings
            .iter()
            .any(|finding| finding.code == "peer-authority-write-authority-limit")
        {
            report.push(
                Finding::error(
                    "peer-authority-write-authority-limit",
                    format!(
                        "more than {MAX_AUTHORITIES} authored contract sources were discovered"
                    ),
                )
                .with_target("contracts"),
            );
        }
        return;
    }
    if let Ok(relative) = path.strip_prefix(root) {
        authorities.insert(normalize_path(relative));
    }
}

fn discover_config_authorities(
    root: &Path,
    config: &Path,
    authorities: &mut BTreeSet<String>,
    report: &mut CommandReport,
) {
    let Ok(metadata) = fs::symlink_metadata(config) else {
        return;
    };
    if metadata.len() > MAX_FILE_BYTES || !metadata.is_file() {
        return;
    }
    let Ok(text) = fs::read_to_string(config) else {
        return;
    };
    let Ok(document) = serde_json::from_str::<JsonValue>(&text) else {
        return;
    };
    let Some(object) = document.as_object() else {
        return;
    };
    let Some(home) = config.parent() else {
        return;
    };
    let Ok(canonical_root) = root.canonicalize() else {
        return;
    };

    for field in ["typespec", "jsonSchema"] {
        let Some(value) = object.get(field).and_then(JsonValue::as_str) else {
            continue;
        };
        let candidate = home.join(value);
        let Ok(canonical) = candidate.canonicalize() else {
            continue;
        };
        if !canonical.starts_with(&canonical_root) || path_has_generated_component(&canonical) {
            continue;
        }
        insert_authority(&canonical_root, &canonical, authorities, report);
    }
}

fn automation_sources(root: &Path, report: &mut CommandReport) -> Vec<PathBuf> {
    let mut files = Vec::<PathBuf>::new();
    let mut overflow_reported = false;

    for relative_root in SCAN_ROOTS {
        let root = root.join(relative_root);
        if !root.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .max_depth(MAX_DEPTH)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(should_descend)
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    report.push(
                        Finding::error(
                            "peer-authority-write-scan-failed",
                            format!("automation tree could not be inspected: {error}"),
                        )
                        .with_target(relative_root),
                    );
                    continue;
                }
            };
            if entry.file_type().is_symlink() || !entry.file_type().is_file() {
                continue;
            }
            if !is_source_file(entry.path()) {
                continue;
            }
            if files.len() >= MAX_FILES {
                if !overflow_reported {
                    report.push(
                        Finding::error(
                            "peer-authority-write-file-limit",
                            format!(
                                "more than {MAX_FILES} automation source files were discovered"
                            ),
                        )
                        .with_target(relative_root),
                    );
                    overflow_reported = true;
                }
                continue;
            }
            files.push(entry.into_path());
        }
    }

    files.sort();
    files.dedup();
    files
}

fn audit_file(
    root: &Path,
    path: &Path,
    authorities: &BTreeSet<String>,
    report: &mut CommandReport,
) -> usize {
    let target = relative_display(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            report.push(
                Finding::error(
                    "peer-authority-write-file-unreadable",
                    format!("automation source metadata could not be read: {error}"),
                )
                .with_target(target),
            );
            return 0;
        }
    };
    if metadata.len() > MAX_FILE_BYTES {
        report.push(
            Finding::error(
                "peer-authority-write-file-too-large",
                "automation source exceeds the 2 MiB authority-write audit bound",
            )
            .with_target(target),
        );
        return 0;
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            report.push(
                Finding::error(
                    "peer-authority-write-file-not-utf8",
                    format!("automation source could not be read as UTF-8: {error}"),
                )
                .with_target(target),
            );
            return 0;
        }
    };

    let mut rejected = 0usize;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if !line_writes_authority(trimmed, authorities) {
            continue;
        }

        rejected += 1;
        report.push(
            Finding::error(
                "peer-authority-direct-write",
                "automation must not overwrite independently authored TypeSpec or JSON Schema; write generated comparison evidence to a distinct path",
            )
            .with_target(format!("{target}:{}", index + 1)),
        );
    }
    rejected
}

fn line_writes_authority(line: &str, authorities: &BTreeSet<String>) -> bool {
    let shell = line.strip_prefix("run:").map(str::trim).unwrap_or(line);

    if shell_transfer_writes_authority(shell, authorities) {
        return true;
    }
    if redirect_destination(shell).is_some_and(|path| authority_matches(&path, authorities)) {
        return true;
    }
    if output_destinations(shell)
        .iter()
        .any(|path| authority_matches(path, authorities))
    {
        return true;
    }
    write_api_destinations(shell)
        .iter()
        .any(|path| authority_matches(path, authorities))
}

fn shell_transfer_writes_authority(line: &str, authorities: &BTreeSet<String>) -> bool {
    let tokens = tokenize(line);
    let Some(command_index) = tokens
        .iter()
        .position(|token| matches!(token.as_str(), "cp" | "mv" | "install"))
    else {
        return false;
    };
    let command = tokens[command_index].as_str();
    let mut operands = Vec::<String>::new();
    let mut target_directory = None::<String>;
    let mut index = command_index + 1;
    while index < tokens.len() {
        let token = &tokens[index];
        if matches!(token.as_str(), "&&" | "||" | ";" | "|" | "&") {
            break;
        }
        if token == "-t" || token == "--target-directory" {
            target_directory = tokens.get(index + 1).cloned();
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--target-directory=") {
            target_directory = Some(value.to_owned());
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        operands.push(token.clone());
        index += 1;
    }

    if command == "mv"
        && operands
            .iter()
            .take(operands.len().saturating_sub(1))
            .any(|source| authority_matches(source, authorities))
    {
        return true;
    }

    if let Some(directory) = target_directory {
        return operands
            .iter()
            .any(|source| directory_transfer_hits_authority(source, &directory, authorities))
            || canonical_unknown_directory_transfer_is_risky(command, &operands, &directory);
    }

    if operands.len() < 2 {
        return false;
    }
    let destination = operands.last().expect("at least two operands");
    if authority_matches(destination, authorities) {
        return true;
    }

    let sources = &operands[..operands.len() - 1];
    let directory_like = operands.len() > 2 || destination_is_directory_like(destination);
    if directory_like
        && sources
            .iter()
            .any(|source| directory_transfer_hits_authority(source, destination, authorities))
    {
        return true;
    }

    // Preserve the earlier fail-closed protection for canonical authority
    // basenames when a destination may be an unknown directory. This catches
    // generated/main.tsp -> contracts/account and ambiguous variable targets,
    // while still allowing an authored peer to be copied to an explicitly
    // distinct negative-control filename.
    canonical_unknown_directory_transfer_is_risky(command, sources, destination)
}

fn canonical_unknown_directory_transfer_is_risky(
    command: &str,
    sources: &[String],
    destination: &str,
) -> bool {
    if command == "mv"
        && sources
            .iter()
            .any(|source| canonical_authority_literal(source))
    {
        return true;
    }
    if !destination_is_directory_like(destination) {
        return false;
    }
    sources
        .iter()
        .any(|source| canonical_authority_literal(source))
}

fn directory_transfer_hits_authority(
    source: &str,
    directory: &str,
    authorities: &BTreeSet<String>,
) -> bool {
    let Some(name) = normalize_candidate(source).rsplit('/').next() else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    let directory = normalize_candidate(directory)
        .trim_end_matches('/')
        .to_owned();
    if directory.starts_with('$') || directory.contains("${{") {
        return false;
    }
    authority_matches(&format!("{directory}/{name}"), authorities)
}

fn destination_is_directory_like(destination: &str) -> bool {
    let destination = normalize_candidate(destination);
    if destination.ends_with('/') || destination.starts_with('$') || destination.contains("${{") {
        return true;
    }
    let file_name = destination.rsplit('/').next().unwrap_or(&destination);
    matches!(file_name, "" | "." | "..") || !file_name.contains('.')
}

fn output_destinations(line: &str) -> BTreeSet<String> {
    let tokens = tokenize(line);
    let mut destinations = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        for flag in ["--output", "--out", "--output-file", "-o"] {
            if token == flag {
                if let Some(value) = tokens.get(index + 1) {
                    destinations.insert(value.clone());
                }
            } else if let Some(value) = token.strip_prefix(&format!("{flag}=")) {
                if !value.is_empty() {
                    destinations.insert(value.to_owned());
                }
            }
        }
    }
    destinations
}

fn write_api_destinations(line: &str) -> BTreeSet<String> {
    let mut destinations = BTreeSet::new();
    for needle in [
        "writeFileSync(",
        "writeFile(",
        "write_file(",
        "std::fs::write(",
        "fs::write(",
        "File::create(",
    ] {
        if let Some(destination) = first_string_argument_after(line, needle) {
            destinations.insert(destination);
        }
    }
    if (line.contains(".write_text(") || line.contains(".write_bytes("))
        && let Some(destination) = first_string_argument_after(line, "Path(")
    {
        destinations.insert(destination);
    }
    destinations
}

fn redirect_destination(line: &str) -> Option<String> {
    let chars = line.char_indices().collect::<Vec<_>>();
    let mut quote = None;
    let mut index = 0usize;
    while index < chars.len() {
        let (offset, ch) = chars[index];
        match quote {
            Some(active) if ch == active => quote = None,
            Some(_) => {}
            None if matches!(ch, '\'' | '"') => quote = Some(ch),
            None if ch == '>' => {
                let mut start = offset + ch.len_utf8();
                if line[start..].starts_with('>') {
                    start += 1;
                }
                return tokenize(line[start..].trim_start()).into_iter().next();
            }
            None => {}
        }
        index += 1;
    }
    None
}

fn first_string_argument_after(line: &str, needle: &str) -> Option<String> {
    let start = line.find(needle)? + needle.len();
    let tail = line[start..].trim_start();
    let quote = tail.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let rest = &tail[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in line.chars() {
        match quote {
            Some(active) if ch == active => quote = None,
            Some(_) => current.push(ch),
            None if matches!(ch, '\'' | '"') => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(clean_token(&current));
                    current.clear();
                }
            }
            None => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(clean_token(&current));
    }
    tokens
}

fn clean_token(token: &str) -> String {
    token
        .trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ';' | ')' | '('))
        .to_owned()
}

fn authority_matches(path: &str, authorities: &BTreeSet<String>) -> bool {
    authorities.contains(&normalize_candidate(path))
}

fn normalize_candidate(path: &str) -> String {
    let path = path.trim();
    let path = path.strip_prefix("./").unwrap_or(path);
    let path = path
        .strip_prefix("$GITHUB_WORKSPACE/")
        .or_else(|| path.strip_prefix("${GITHUB_WORKSPACE}/"))
        .unwrap_or(path);
    path.replace('\\', "/")
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            Component::CurDir => None,
            Component::ParentDir => Some("..".to_owned()),
            Component::RootDir | Component::Prefix(_) => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn canonical_authority_literal(path: &str) -> bool {
    let normalized = normalize_candidate(path).to_ascii_lowercase();
    normalized.ends_with("/main.tsp")
        || normalized == "main.tsp"
        || normalized.ends_with("/authored.schema.json")
        || normalized == "authored.schema.json"
}

fn is_authored_typespec(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("tsp")
        && !path_has_generated_component(path)
}

fn is_authored_schema(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    name.ends_with(".schema.json")
        && !name.ends_with(".generated.schema.json")
        && name != "typespec.generated.schema.json"
        && !path_has_generated_component(path)
}

fn path_has_generated_component(path: &Path) -> bool {
    path.components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        let name = value.to_string_lossy();
        GENERATED_COMPONENTS.contains(&name.as_ref())
    })
}

fn should_descend(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    name != ".git" && !GENERATED_COMPONENTS.contains(&name.as_ref())
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension))
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

    use tempfile::tempdir;

    use super::augment_authority_write_protection_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn pair() -> [(&'static str, &'static str); 2] {
        [
            ("contracts/account/main.tsp", "model Account {}\n"),
            (
                "contracts/account/authored.schema.json",
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
            ),
        ]
    }

    fn audit(authorities: &[(&str, &str)], path: &str, content: &str) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        for (authority, body) in authorities {
            let authority = root.path().join(authority);
            fs::create_dir_all(authority.parent().expect("authority parent"))
                .expect("authority directory");
            fs::write(authority, body).expect("authority source");
        }
        let file = root.path().join(path);
        fs::create_dir_all(file.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(file, content).expect("fixture source");
        augment_authority_write_protection_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    #[test]
    fn rejects_shell_overwrite_of_authored_json_schema() {
        let report = audit(
            &pair(),
            "scripts/generate.sh",
            "cp generated/schema.json contracts/account/authored.schema.json\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn rejects_shell_overwrite_of_authored_typespec() {
        let report = audit(
            &pair(),
            ".github/workflows/ci.yml",
            "run: cat generated.tsp > contracts/account/main.tsp\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn rejects_programmatic_write_to_authored_peer() {
        for source in [
            "fs.writeFileSync('contracts/account/authored.schema.json', body);\n",
            "std::fs::write(\"contracts/account/main.tsp\", body)?;\n",
            "Path('contracts/account/main.tsp').write_text(body)\n",
        ] {
            let report = audit(&pair(), "tools/generate.py", source);
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "peer-authority-direct-write")
            );
        }
    }

    #[test]
    fn allows_tjsv_reads_and_generated_json_output() {
        let report = audit(
            &pair(),
            ".github/workflows/contracts.yml",
            "run: tjsv check --typespec=contracts/account/main.tsp --schema=contracts/account/authored.schema.json --output-dir=.typespec-json-schema-validator/account/generated\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn output_flag_is_rejected_only_when_its_value_is_an_authority() {
        let allowed = audit(
            &pair(),
            "scripts/check.sh",
            "tool --input contracts/account/main.tsp --output generated/result.json\n",
        );
        assert_eq!(allowed.issue_count(), 0, "{:#?}", allowed.findings);

        let rejected = audit(
            &pair(),
            "scripts/generate.sh",
            "tool --input generated/schema.json --output=contracts/account/authored.schema.json\n",
        );
        assert!(
            rejected
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn redirect_is_rejected_only_when_its_target_is_an_authority() {
        let allowed = audit(
            &pair(),
            "scripts/check.sh",
            "cat contracts/account/main.tsp > evidence/main.sha-source\n",
        );
        assert_eq!(allowed.issue_count(), 0, "{:#?}", allowed.findings);

        let rejected = audit(
            &pair(),
            "scripts/generate.sh",
            "cat generated.tsp > contracts/account/main.tsp\n",
        );
        assert!(
            rejected
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn allows_hash_and_compare_of_both_authored_peers() {
        let report = audit(
            &pair(),
            "scripts/check.sh",
            "sha256sum contracts/account/main.tsp contracts/account/authored.schema.json\ncmp contracts/account/authored.schema.json evidence/authored.before.json\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn allows_copying_authored_peers_into_named_negative_control_fixtures() {
        let report = audit(
            &pair(),
            ".github/workflows/ci.yml",
            "cp contracts/account/main.tsp \"$RUNNER_TEMP/account-typespec-drift.tsp\"\ncp contracts/account/authored.schema.json \"$RUNNER_TEMP/account-schema-drift.json\"\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn still_rejects_directory_transfers_that_can_replace_canonical_peers() {
        for line in [
            "cp -f \"$RUNNER_TEMP/drift.tsp\" contracts/account/main.tsp",
            "install -m 0644 generated/schema.json contracts/account/authored.schema.json",
            "mv contracts/account/authored.schema.json \"$RUNNER_TEMP/moved.json\"",
            "cp generated/main.tsp contracts/account/",
            "cp generated/main.tsp \"$RUNNER_TEMP\"",
            "cp -t contracts/account generated/main.tsp",
            "cp generated/main.tsp generated/authored.schema.json contracts/account",
        ] {
            let report = audit(&pair(), "scripts/generate.sh", &format!("{line}\n"));
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "peer-authority-direct-write"),
                "expected rejection for {line}: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    fn protects_flat_split_authority_names() {
        let authorities = [
            ("contracts/typespec/package.tsp", "model Package {}\n"),
            (
                "contracts/json-schema/package.schema.json",
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
            ),
        ];
        for line in [
            "cp /tmp/package.tsp contracts/typespec/package.tsp",
            "tool --output contracts/json-schema/package.schema.json",
        ] {
            let report = audit(&authorities, "scripts/generate.sh", &format!("{line}\n"));
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "peer-authority-direct-write"),
                "{line}: {:#?}",
                report.findings
            );
        }
    }

    #[test]
    fn config_declared_custom_json_schema_is_protected() {
        let authorities = [
            (
                "contracts/account/contracts.config.json",
                r#"{"typespec":"src/account.tsp","jsonSchema":"schema/account.json"}"#,
            ),
            ("contracts/account/src/account.tsp", "model Account {}\n"),
            (
                "contracts/account/schema/account.json",
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
            ),
        ];
        let report = audit(
            &authorities,
            "tools/write.mjs",
            "writeFileSync('contracts/account/schema/account.json', body);\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn generated_schema_b_is_not_an_authored_write_target() {
        let mut authorities = pair().to_vec();
        authorities.push((
            "contracts/account/generated/typespec.generated.schema.json",
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
        ));
        let report = audit(
            &authorities,
            "scripts/generate.sh",
            "cp /tmp/schema.json contracts/account/generated/typespec.generated.schema.json\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn ignores_commented_write_examples() {
        let report = audit(
            &pair(),
            "scripts/check.sh",
            "# cp generated/schema.json contracts/account/authored.schema.json\n// fs.writeFileSync('contracts/account/main.tsp', body);\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }
}
