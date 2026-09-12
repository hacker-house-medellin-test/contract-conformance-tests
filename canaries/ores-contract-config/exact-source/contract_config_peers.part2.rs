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
