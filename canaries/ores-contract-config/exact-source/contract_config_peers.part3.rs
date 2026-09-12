
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
