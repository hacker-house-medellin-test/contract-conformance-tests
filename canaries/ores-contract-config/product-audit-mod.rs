mod alignment;
mod cargo_git_pins;
mod cli_secret_flag_hygiene;
mod contract;
mod contract_config_peers;
mod contract_consumer;
#[cfg(test)]
mod contract_consumer_tests;
mod contract_evidence;
#[cfg(test)]
mod contract_evidence_tests;
mod contract_generated_evidence;
mod contract_tree;
mod docker_base_pins;
mod flags2env_source_hygiene;
mod flags2env_submodule_source_hygiene;
mod infra_policy;
mod infra_provider_state;
mod nested_peer_contracts;
mod oauth_provider_contract;
mod org;
mod package;
mod peer_authority_identity;
mod repository;
mod runtime_toml_env_boundary;
mod runtime_toml_indiebuild;
mod runtime_toml_otel;
mod runtime_toml_rate_limit;
mod runtime_toml_registry;
#[cfg(test)]
mod runtime_toml_registry_tests;
mod runtime_toml_sidecar;
mod split_peer_contracts;
mod tjsv_bidirectional_drift;
mod tjsv_full_check;
mod tjsv_generated_schema_provenance;
mod tjsv_invocation_scope;
mod tjsv_workflow_revision;
mod workflow_action_pins;
mod workflow_permissions;
mod workflow_tjsv_inputs;
mod workflow_tjsv_step_pairing;

use std::path::PathBuf;

pub use contract::audit_contract;
pub use contract_tree::audit_contract_tree;
pub use org::audit_github_org;
pub use package::audit_package;

use crate::model::CommandReport;

/// Audit one local repository tree, recursively inspect independently authored
/// TypeSpec/JSON Schema peers across direct, nested, flat split and config-declared
/// split layouts, enforce physical independence plus separation between editable
/// authorities and generated TJSV comparison evidence, validate OAuth/OIDC
/// provider source, workflow and `*-test` evidence boundaries, require symmetric
/// fail-closed TJSV drift controls, forbid authored-Schema-A/generated-Schema-B
/// cloning, require a full compiler/emitter/comparison/differential `tjsv check`
/// for every complete peer pair, require one scoped invocation per workflow
/// admission, require explicit current TypeSpec, authored Schema A, report,
/// Contract IR and generated-output bindings plus a fresh same-workflow
/// current-input verifier, require internally consistent immutable TJSV workflow
/// revisions, reject mutable GitHub Actions dependencies, require explicit
/// workflow-token posture and immutable Docker/Cargo Git identities, fail closed
/// on unknown ORES runtime TOML names, enforce credential/public-argv separation
/// plus canonical flags2env provenance, cross-check runtime-owned secret env
/// bindings against public argv exposure, apply bounded peer-authority runtime
/// configuration checks, and harden provider IaC when the infra profile is
/// explicitly selected.
#[must_use]
pub fn audit_repository(options: &RepositoryAuditOptions) -> CommandReport {
    let report = nested_peer_contracts::augment_nested_peer_contract_audit(
        options,
        repository::audit_repository(options),
    );
    let report = split_peer_contracts::augment_split_peer_contract_audit(options, report);
    let report = contract_config_peers::augment_contract_config_peer_audit(options, report);
    let report = peer_authority_identity::augment_peer_authority_identity_audit(options, report);
    let report = contract_generated_evidence::augment_contract_generated_evidence_audit(
        options, report,
    );
    let report = oauth_provider_contract::augment_oauth_provider_contract_audit(options, report);
    let report =
        tjsv_bidirectional_drift::augment_tjsv_bidirectional_drift_audit(options, report);
    let report = tjsv_generated_schema_provenance::augment_tjsv_generated_schema_provenance_audit(
        options, report,
    );
    let report = tjsv_full_check::augment_tjsv_full_check_audit(options, report);
    let report = tjsv_invocation_scope::augment_tjsv_invocation_scope_audit(options, report);
    let report = workflow_tjsv_inputs::augment_workflow_tjsv_input_audit(options, report);
    let report =
        workflow_tjsv_step_pairing::augment_workflow_tjsv_step_pairing_audit(options, report);
    let report = tjsv_workflow_revision::augment_tjsv_workflow_revision_audit(options, report);
    let report = workflow_action_pins::augment_workflow_action_pin_audit(options, report);
    let report = workflow_permissions::augment_workflow_permissions_audit(options, report);
    let report = docker_base_pins::augment_docker_base_pin_audit(options, report);
    let report = cargo_git_pins::augment_cargo_git_pin_audit(options, report);
    let report = runtime_toml_registry::augment_runtime_toml_registry_audit(options, report);
    let report = runtime_toml_rate_limit::augment_rate_limit_runtime_toml_audit(options, report);
    let report =
        runtime_toml_env_boundary::augment_runtime_toml_env_boundary_audit(options, report);
    let report = runtime_toml_otel::augment_otel_runtime_toml_audit(options, report);
    let report = runtime_toml_indiebuild::augment_indiebuild_runtime_toml_audit(options, report);
    let mut report = runtime_toml_sidecar::augment_sidecar_runtime_toml_audit(options, report);
    cli_secret_flag_hygiene::audit_cli_secret_flag_hygiene(&options.path, &mut report);
    flags2env_source_hygiene::audit_flags2env_source_hygiene(&options.path, &mut report);
    flags2env_submodule_source_hygiene::audit_flags2env_submodule_source_hygiene(
        &options.path,
        &mut report,
    );
    let report = report.finalize();
    if options.profile.trim() == "infra" {
        let report = infra_policy::augment_infra_policy_audit(options, report);
        infra_provider_state::augment_infra_provider_state_audit(options, report)
    } else {
        report
    }
}

/// Options for a GitHub organization audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubOrgAuditOptions {
    /// GitHub account or organization login.
    pub owner: String,
    /// Maximum repositories requested from `gh`.
    pub repo_limit: usize,
    /// Exact additional repository names that must exist.
    pub expected_repositories: Vec<String>,
    /// Optional standard family prefix.
    pub family_prefix: Option<String>,
    /// Standard family suffixes required with the prefix.
    pub family_members: Vec<String>,
    /// Require a `docs` or `*-docs` repository.
    pub require_docs_repository: bool,
    /// Inspect top-level entries for active repositories.
    pub check_layout: bool,
    /// Required top-level entries.
    pub required_root_entries: Vec<String>,
    /// Maximum repositories inspected for layout.
    pub max_layout_repositories: usize,
    /// Whether archived repositories receive layout checks.
    pub include_archived: bool,
}

/// Options for a local repository audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAuditOptions {
    /// Local repository root.
    pub path: PathBuf,
    /// Structural profile.
    pub profile: String,
    /// Additional required paths.
    pub additional_required_paths: Vec<String>,
}

/// Options for whole-repository TypeSpec/JSON Schema parity validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractTreeAuditOptions {
    /// Repository root containing `contracts/`.
    pub path: PathBuf,
    /// Root directory for generated/parity evidence.
    pub report_root: PathBuf,
    /// Validator executable.
    pub validator: String,
}

/// Options for Cargo/zed-pkg metadata parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageAuditOptions {
    /// Local package root.
    pub path: PathBuf,
    /// Whether Cargo.lock must exist.
    pub require_cargo_lock: bool,
}

/// Options for TypeSpec/JSON Schema parity validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractAuditOptions {
    /// TypeSpec source entry.
    pub typespec: PathBuf,
    /// Independently authored JSON Schema source.
    pub schema: PathBuf,
    /// Machine-readable validator report path.
    pub report: PathBuf,
    /// Validator executable.
    pub validator: String,
}
