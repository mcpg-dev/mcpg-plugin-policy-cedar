//! Operator-supplied configuration schema for `dev.mcpg.policy.cedar`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarConfig {
    /// Directory containing one or more `.cedar` policy files.
    /// Walked recursively at boot; every `.cedar` file is parsed
    /// and aggregated into a Cedar PolicySet.
    pub policy_dir: String,

    /// Translation rules — how MCPG's evaluation envelope maps
    /// to Cedar's typed Request.
    pub translation: TranslationConfig,

    /// Optional. Default-deny convention.
    #[serde(default)]
    pub evaluation: EvaluationConfig,

    /// Optional bundle hot-reload watcher. Default disabled
    /// (operator restarts to pick up policy changes — same as
    /// pre-reload behavior). When `enabled: true`, the plugin
    /// polls `policy_dir` every `check_interval_sec` and atomically
    /// swaps the PolicySet on detected changes.
    #[serde(default)]
    pub reload: ReloadConfig,

    /// Optional path to a Cedar schema file. Accepts both the
    /// human-readable `.cedarschema` syntax and JSON
    /// `.cedarschema.json`. When set:
    ///
    /// - Every policy load runs `Validator` against the schema;
    ///   incompatible policies fail the load (refuse-to-register
    ///   for the static path; reload retains the previous bundle).
    /// - `Request::new` uses the schema for type-checking, so
    ///   policies that reference attributes not in the schema
    ///   surface as evaluation errors instead of `false` matches.
    ///
    /// Schema is loaded once at construction and is NOT part of
    /// the reload bundle — operators wanting to evolve their
    /// schema restart the gateway.
    #[serde(default)]
    pub schema_path: Option<String>,

    /// Optional path to a Cedar entities JSON file. Loaded once
    /// at construction; supplies static principal / resource /
    /// group entities that policies reference (e.g. user-role
    /// memberships, document-owner relationships). When unset
    /// the plugin uses an empty entity store — policies must
    /// rely entirely on the principal / action / resource UIDs
    /// the gateway translates per request.
    ///
    /// Like the schema, entities are NOT part of the reload
    /// bundle — operators rebuild + restart to pick up entity
    /// updates. v0.2 may add a watcher.
    #[serde(default)]
    pub entities_path: Option<String>,

    /// When `true`, the plugin translates the request `input`
    /// JSON into Cedar's `Context` (a typed record passed to
    /// every policy as `context`). When `false` (default), the
    /// request context is empty — policies can only reference
    /// principal, action, resource, and `principal.<attr>` /
    /// `resource.<attr>` attributes from the entities store.
    ///
    /// Schema-typed deploys SHOULD set this `true`; the gateway's
    /// per-decision-point `input` shape becomes part of the
    /// schema's action context types.
    #[serde(default)]
    pub include_input_as_context: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReloadConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_check_interval_sec")]
    pub check_interval_sec: u64,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_sec: default_check_interval_sec(),
        }
    }
}

fn default_check_interval_sec() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationConfig {
    /// Cedar entity-type identifier for the principal — e.g.
    /// `"User"`, `"Caller"`, or a namespaced
    /// `"Acme::Identity::User"`. The plugin builds principal UIDs
    /// like `<principal_type>::"<subject_id_or_anonymous>"`.
    pub principal_type: String,

    /// Cedar action namespace — e.g. `"Action"` or
    /// `"Acme::Identity::Action"`. Action UIDs are
    /// `<action_namespace>::"<decision_point>"`.
    pub action_namespace: String,

    /// Per-decision-point resource type mapping. Required;
    /// at least one entry. A single `*` wildcard entry is
    /// allowed to cover decision_points not otherwise listed.
    pub resource_types: Vec<ResourceType>,

    /// Fallback principal id when `context.identity.subject_id`
    /// is None.
    #[serde(default = "default_anonymous_id")]
    pub anonymous_principal_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceType {
    /// The MCPG decision_point this entry covers, or `"*"` for
    /// catch-all.
    pub decision_point: String,
    /// Cedar entity-type identifier — e.g. `"Tool"`,
    /// `"Document"`.
    pub resource_type: String,
    /// JSON pointer (RFC 6901) into the request `input` to
    /// extract the resource id. Empty `""` denotes the literal
    /// `"unspecified"`. Pointer miss → `"unknown"`.
    #[serde(default)]
    pub resource_id_path: String,
}

fn default_anonymous_id() -> String {
    "anonymous".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationConfig {
    #[serde(default = "default_on_default_deny")]
    pub on_default_deny: DefaultDenyMode,
}

impl Default for EvaluationConfig {
    fn default() -> Self {
        Self {
            on_default_deny: default_on_default_deny(),
        }
    }
}

fn default_on_default_deny() -> DefaultDenyMode {
    DefaultDenyMode::NotApplicable
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultDenyMode {
    /// Cedar default-deny → `PolicyEffect::NotApplicable`. Lets
    /// chained policy plugins try after this one. Default.
    NotApplicable,
    /// Cedar default-deny → `PolicyEffect::Deny`. Strict-cedar-
    /// style; chains break here.
    Deny,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid policy.cedar config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("policy.cedar: policy_dir is empty")]
    EmptyPolicyDir,
    #[error("policy.cedar: translation.principal_type is empty")]
    EmptyPrincipalType,
    #[error("policy.cedar: translation.action_namespace is empty")]
    EmptyActionNamespace,
    #[error("policy.cedar: translation.resource_types must be non-empty")]
    EmptyResourceTypes,
    #[error(
        "policy.cedar: duplicate decision_point `{decision_point}` in \
         resource_types — operator must declare each decision_point at \
         most once (with optional `*` catch-all)"
    )]
    DuplicateDecisionPoint { decision_point: String },
    #[error(
        "policy.cedar: resource_types[{index}] (decision_point=`{decision_point}`): \
         resource_type is empty"
    )]
    EmptyResourceType {
        index: usize,
        decision_point: String,
    },
    #[error("policy.cedar: reload.check_interval_sec must be > 0 when reload.enabled = true")]
    InvalidCheckInterval,
    #[error("policy.cedar: schema_path is set but empty")]
    EmptySchemaPath,
    #[error("policy.cedar: entities_path is set but empty")]
    EmptyEntitiesPath,
}

impl CedarConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.policy_dir.trim().is_empty() {
            return Err(ConfigError::EmptyPolicyDir);
        }
        if self.reload.enabled && self.reload.check_interval_sec == 0 {
            return Err(ConfigError::InvalidCheckInterval);
        }
        if self.translation.principal_type.trim().is_empty() {
            return Err(ConfigError::EmptyPrincipalType);
        }
        if self.translation.action_namespace.trim().is_empty() {
            return Err(ConfigError::EmptyActionNamespace);
        }
        if self.translation.resource_types.is_empty() {
            return Err(ConfigError::EmptyResourceTypes);
        }
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for (index, entry) in self.translation.resource_types.iter().enumerate() {
            if entry.resource_type.trim().is_empty() {
                return Err(ConfigError::EmptyResourceType {
                    index,
                    decision_point: entry.decision_point.clone(),
                });
            }
            if let Some(prior) = seen.insert(entry.decision_point.clone(), index) {
                let _ = prior;
                return Err(ConfigError::DuplicateDecisionPoint {
                    decision_point: entry.decision_point.clone(),
                });
            }
        }
        if let Some(p) = self.schema_path.as_deref()
            && p.trim().is_empty()
        {
            return Err(ConfigError::EmptySchemaPath);
        }
        if let Some(p) = self.entities_path.as_deref()
            && p.trim().is_empty()
        {
            return Err(ConfigError::EmptyEntitiesPath);
        }
        // include_input_as_context with no schema is allowed — the
        // gateway hands an untyped Context; policies access it
        // via `context.<attr>` and Cedar errors at evaluation if
        // attrs are mistyped. With a schema it's the typed path.
        Ok(())
    }

    /// Resolve the `ResourceType` entry for a given decision_point.
    /// Falls back to the `*` catch-all if no exact match.
    pub fn resource_type_for(&self, decision_point: &str) -> Option<&ResourceType> {
        self.translation
            .resource_types
            .iter()
            .find(|r| r.decision_point == decision_point)
            .or_else(|| {
                self.translation
                    .resource_types
                    .iter()
                    .find(|r| r.decision_point == "*")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_config() {
        let cfg = json!({
            "policy_dir": "/etc/mcpg/cedar",
            "translation": {
                "principal_type": "User",
                "action_namespace": "Action",
                "resource_types": [
                    { "decision_point": "tool.call.pre", "resource_type": "Tool", "resource_id_path": "/tool" }
                ]
            }
        })
        .to_string();
        let parsed = CedarConfig::parse(&cfg).unwrap();
        assert_eq!(parsed.translation.resource_types.len(), 1);
        assert_eq!(parsed.translation.anonymous_principal_id, "anonymous");
    }

    #[test]
    fn rejects_empty_policy_dir() {
        let cfg = json!({
            "policy_dir": "",
            "translation": {
                "principal_type": "User",
                "action_namespace": "Action",
                "resource_types": [
                    { "decision_point": "*", "resource_type": "Tool" }
                ]
            }
        })
        .to_string();
        let err = CedarConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptyPolicyDir);
    }

    #[test]
    fn rejects_duplicate_decision_point() {
        let cfg = json!({
            "policy_dir": "/x",
            "translation": {
                "principal_type": "User",
                "action_namespace": "Action",
                "resource_types": [
                    { "decision_point": "read", "resource_type": "Tool" },
                    { "decision_point": "read", "resource_type": "Doc" }
                ]
            }
        })
        .to_string();
        let err = CedarConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::DuplicateDecisionPoint { .. });
    }

    #[test]
    fn rejects_empty_resource_types() {
        let cfg = json!({
            "policy_dir": "/x",
            "translation": {
                "principal_type": "User",
                "action_namespace": "Action",
                "resource_types": []
            }
        })
        .to_string();
        let err = CedarConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptyResourceTypes);
    }

    #[test]
    fn resource_type_for_uses_exact_match_then_catchall() {
        let cfg = CedarConfig::parse(
            &json!({
                "policy_dir": "/x",
                "translation": {
                    "principal_type": "User",
                    "action_namespace": "Action",
                    "resource_types": [
                        { "decision_point": "read", "resource_type": "Doc" },
                        { "decision_point": "*", "resource_type": "Generic" }
                    ]
                }
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(cfg.resource_type_for("read").unwrap().resource_type, "Doc");
        assert_eq!(
            cfg.resource_type_for("write").unwrap().resource_type,
            "Generic"
        );
    }
}
