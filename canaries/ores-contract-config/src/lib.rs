pub mod model;

pub mod audit {
    use std::path::PathBuf;

    use crate::model::CommandReport;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RepositoryAuditOptions {
        pub path: PathBuf,
        pub profile: String,
        pub additional_required_paths: Vec<String>,
    }

    mod contract_config_peers;

    #[must_use]
    pub fn audit_repository(options: &RepositoryAuditOptions) -> CommandReport {
        contract_config_peers::augment_contract_config_peer_audit(
            options,
            CommandReport::new("audit repo"),
        )
    }
}
