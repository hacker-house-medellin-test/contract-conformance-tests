mod authority_write_protection;

use std::path::{Path, PathBuf};

use crate::model::CommandReport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAuditOptions {
    pub path: PathBuf,
    pub profile: String,
    pub additional_required_paths: Vec<String>,
}

pub fn run(root: &Path) -> CommandReport {
    authority_write_protection::augment_authority_write_protection_audit(
        &RepositoryAuditOptions {
            path: root.to_path_buf(),
            profile: "baseline".to_owned(),
            additional_required_paths: Vec::new(),
        },
        CommandReport::new("audit repo"),
    )
}
