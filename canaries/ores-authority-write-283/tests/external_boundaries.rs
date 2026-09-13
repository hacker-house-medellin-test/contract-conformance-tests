use std::fs;
use std::path::Path;

use ores_cli_authority_write_targets_certification::audit::run;
use tempfile::tempdir;

fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
    fs::write(path, content).expect("fixture file");
}

#[test]
fn flat_peer_directory_transfer_is_rejected() {
    let root = tempdir().expect("temporary repository");
    write(root.path(), "contracts/typespec/package.tsp", "model Package { name: string; }\n");
    write(root.path(), "contracts/json-schema/package.schema.json", r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#);
    write(root.path(), "scripts/generate.sh", "cp /tmp/package.tsp contracts/typespec/\n");
    let report = run(root.path());
    assert!(report.findings.iter().any(|finding| finding.code == "peer-authority-direct-write"), "flat TypeSpec authority was not protected: {:#?}", report.findings);
}

#[test]
fn config_declared_custom_schema_write_is_rejected() {
    let root = tempdir().expect("temporary repository");
    write(root.path(), "contracts/iam/contracts.config.json", r#"{"typespec":"source/iam.tsp","jsonSchema":"schema/account.json"}"#);
    write(root.path(), "contracts/iam/source/iam.tsp", "model IamPolicy { enabled: boolean; }\n");
    write(root.path(), "contracts/iam/schema/account.json", r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#);
    write(root.path(), "tools/rewrite.mjs", "writeFileSync('contracts/iam/schema/account.json', body);\n");
    let report = run(root.path());
    assert!(report.findings.iter().any(|finding| finding.code == "peer-authority-direct-write"), "config-declared custom JSON Schema authority was not protected: {:#?}", report.findings);
}

#[test]
fn peer_reads_with_unrelated_output_are_not_writes() {
    let root = tempdir().expect("temporary repository");
    write(root.path(), "contracts/iam/main.tsp", "model IamPolicy { enabled: boolean; }\n");
    write(root.path(), "contracts/iam/authored.schema.json", r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#);
    write(root.path(), ".github/workflows/contracts.yml", "run: tjsv check --typespec=contracts/iam/main.tsp --schema=contracts/iam/authored.schema.json --output=.typespec-json-schema-validator/iam/report.json\n");
    let report = run(root.path());
    assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    assert_eq!(report.metadata.get("peerAuthorityWriteProtectionAuthorityCount").and_then(serde_json::Value::as_u64), Some(2));
}
