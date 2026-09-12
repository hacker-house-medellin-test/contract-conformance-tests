use std::path::PathBuf;

use ores_cli::audit::{RepositoryAuditOptions, audit_repository};

#[test]
fn exact_scanner_discovers_hhm_config_declared_peer_pair() {
    let repository = std::env::var_os("ORES_CLI_TEST_CONTRACT_CONFIG_REPO")
        .map(PathBuf::from)
        .expect("ORES_CLI_TEST_CONTRACT_CONFIG_REPO must point at the HHM checkout");

    let report = audit_repository(&RepositoryAuditOptions {
        path: repository,
        profile: "baseline".to_owned(),
        additional_required_paths: Vec::new(),
    });

    assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    assert_eq!(
        report
            .metadata
            .get("contractConfigCandidateCount")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .metadata
            .get("contractConfigValidPeerPairCount")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
}
