//! `dev.mcpg.policy.cedar` — AWS Cedar `policy_engine` plugin.
//!
//! Operator-facing summary lives in `README.md`.
//!
//! # Core behaviour
//!
//! - PolicySet aggregated from a directory of `.cedar` files.
//! - Translation: principal = `<principal_type>::"<subject_id>"`;
//!   action = `<action_namespace>::"<decision_point>"`;
//!   resource = `<resource_type>::"<resolved id>"`.
//! - Decision mapping: Allow / Deny (with matched policy ids) /
//!   NotApplicable (default-deny).
//! - `policy_version()` SHA-256 of concatenated policy file
//!   bytes in lexicographic order.
//!
//! # Schema, entities, and context
//!
//! - **Schema** — operator-supplied `.cedarschema` (or
//!   `.cedarschema.json`) typechecks the PolicySet at load time
//!   AND informs `Request::new` so attribute references that
//!   don't fit the schema surface as policy errors instead of
//!   silent `false`s.
//! - **Entities store** — operator-supplied JSON file with
//!   principal / group / resource entities (membership +
//!   attributes). Policies can reference
//!   `principal.role == "admin"`, `principal in Group::"sec"`,
//!   etc.
//! - **Input → Context translation** — when
//!   `include_input_as_context: true`, the gateway's per-request
//!   `input` JSON becomes Cedar's typed `Context`. Schema-typed
//!   deploys make this the action-context type per
//!   decision_point.
//!
//! # Bundle reload
//!
//! Policy directory, schema, and entities files all live inside
//! the reload bundle's composite source via the shared
//! `mcpg-bundle-reload` crate. Changing any one of policy-dir /
//! schema / entities on disk triggers a unified rebuild.
//!
//! # Annotation-driven obligations + redactions
//!
//! Cedar's `Decision` is binary `Allow | Deny` — there's no native
//! side-channel for the side-effect metadata that
//! `PolicyDecision::{obligations, redactions}` carry. Matched
//! policies may carry these annotations:
//!
//! - `@advice("kind:json_args")` → emit `Obligation { kind,
//!   args: parsed_json }`. Format is `kind` alone (args =
//!   `null`) or `kind:<json_value>`. Multiple matched
//!   policies stack their advice on the final decision; one
//!   `@advice` per policy is the limit Cedar's annotation
//!   model imposes.
//! - `@redact("$.json/pointer")` → emit `Redaction {
//!   json_pointer: "$.json/pointer", replacement: "***" }`.
//!   Redactions only land on `Allow` (a `Deny` blocks the
//!   payload entirely; nothing flows through to redact).
//!
//! Operators with no annotations on their policies see no
//! behavioural change: a policy that doesn't carry these
//! annotations contributes zero obligations / redactions.

mod config;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet, Request, Schema,
    ValidationMode, Validator,
};
use mcpg_bundle_reload::{BundleReload, BundleSource, ReloadError};
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::policy::{
    Obligation, PolicyDecision, PolicyEffect, PolicyVersion, Redaction,
};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncPolicyEngine;
use serde_json::Value;

pub use config::{
    CedarConfig, ConfigError, DefaultDenyMode, EvaluationConfig, ReloadConfig, ResourceType,
    TranslationConfig,
};

const PLUGIN_ID: &str = "dev.mcpg.policy.cedar";
const ENGINE_NAME: &str = "cedar";

pub struct CedarPolicyPlugin {
    inner: Arc<Inner>,
}

/// Compiled bundle: PolicySet + indexed forbid ids + schema +
/// entities. Schema + entities are folded INTO the reload bundle
/// so any of the three (policy dir, schema file, entities file)
/// changing on disk triggers a unified rebuild.
pub(crate) struct CompiledBundle {
    pub policy_set: PolicySet,
    pub forbid_ids: std::collections::BTreeSet<PolicyId>,
    /// Cedar schema. `Some` when `schema_path` is configured;
    /// passed to every `Request::new` and used to validate the
    /// PolicySet at load time.
    pub schema: Option<Arc<Schema>>,
    /// Static entities store. Empty when `entities_path` is
    /// unset; policies fall back to principal/action/resource UIDs
    /// only.
    pub entities: Arc<Entities>,
}

struct Inner {
    manifest: PluginManifest,
    config: CedarConfig,
    bundle: BundleReload<CompiledBundle>,
    authorizer: Authorizer,
    /// Bundled tokio runtime — `BundleReload::start` is async and
    /// the plugin's factory is sync. Held only when reload is
    /// enabled; static-only deploys construct the bundle inline
    /// without spawning a watcher.
    _runtime: Option<tokio::runtime::Runtime>,
    /// Cluster client handed at `make` time when the operator has
    /// registered a `cluster_backend`. Today it emits a startup
    /// heartbeat on `policy.cedar.policies-loaded` carrying the
    /// bundle fingerprint AND subscribes to the same topic so
    /// policy-version skew across a rolling reload is visible in
    /// this node's logs. Future uses: coordinated entity-set
    /// refresh via `acquire_lock`.
    #[allow(dead_code)]
    cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    /// Active subscription on `policy.cedar.policies-loaded`.
    /// Held for the plugin's lifetime; Drop cancels the stream.
    #[allow(dead_code)]
    cluster_subscription: Option<mcpg_plugin_sdk::Subscription<mcpg_cluster_api::PublishedMessage>>,
    /// The unified host surface. Installed once at boot
    /// by the gateway / SDK factory via
    /// [`CedarPolicyPlugin::set_host_handle`] before any `evaluate`
    /// traffic flows. When `None` (test harnesses that construct the
    /// plugin without wiring a host), the per-call HostHandle
    /// observability triad short-circuits to no-ops and the
    /// plugin's existing internal `tracing::*` + `metrics::*`
    /// calls carry the load through their own sinks.
    ///
    /// Coexistence with the `cluster` client is intentional —
    /// `cluster` is the cross-node coordination surface
    /// (publish / subscribe / lock); `HostHandle` is the unified
    /// observability + audit surface. Both stay wired.
    host_handle: OnceLock<HostHandle>,
}

impl CedarPolicyPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        Self::from_config_json_with_cluster(config_json, None)
    }

    /// Factory that receives the optional cluster client from
    /// the SDK macro. Public so unit tests can construct the
    /// plugin with a synthetic client.
    pub fn from_config_json_with_cluster(
        config_json: &str,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    ) -> Self {
        let cfg = CedarConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "cedar policy: config parse failed; refusing to register"
            );
            panic!(
                "cedar policy config parse failed: {err}. A misconfigured \
                 policy engine is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg, cluster)
    }

    fn from_validated_config(
        cfg: CedarConfig,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    ) -> Self {
        // Schema + entities are part of the reload bundle. The
        // composite source covers the policy directory plus the
        // optional schema + entities files; a fingerprint change
        // in any of them triggers a unified rebuild.
        let policy_dir_source = BundleSource::Directory {
            root: cfg.policy_dir.clone().into(),
            extension: Some("cedar".into()),
        };
        let mut composite_parts = vec![policy_dir_source];
        if let Some(p) = cfg.schema_path.as_deref() {
            composite_parts.push(BundleSource::File(p.into()));
        }
        if let Some(p) = cfg.entities_path.as_deref() {
            composite_parts.push(BundleSource::File(p.into()));
        }
        let source = if composite_parts.len() == 1 {
            // Single-source — keep the existing Directory shape
            // (cheaper fingerprint than wrapping in Composite for
            // a singleton). Only happens when neither schema nor
            // entities is configured.
            composite_parts.into_iter().next().unwrap()
        } else {
            BundleSource::Composite(composite_parts)
        };

        let schema_path = cfg.schema_path.clone();
        let entities_path = cfg.entities_path.clone();
        let policy_dir_path = cfg.policy_dir.clone();
        let parse_full = move |_s: &BundleSource| {
            // Re-parse the full triple (policies + schema +
            // entities) on every reload. The bundle-reload
            // fingerprint already covers all three, so we only
            // get here when something actually changed.
            parse_full_bundle(
                &policy_dir_path,
                schema_path.as_deref(),
                entities_path.as_deref(),
            )
        };

        let (bundle, runtime) = if cfg.reload.enabled {
            // Spawn a private tokio runtime + the watcher.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("cedar policy: failed to build tokio runtime");
            let interval = Duration::from_secs(cfg.reload.check_interval_sec);
            // When clustered, gate each reload tick on a short-TTL
            // distributed lock (`policy.cedar.refresh`). The lock-
            // holder reloads; other nodes skip this tick (their
            // local cache is still valid; they'll re-acquire on the
            // next tick if the previous holder has since released).
            // `try_acquire_lock` returns `Ok(None)` immediately
            // when a peer holds the lease — that's exactly the
            // "skip this tick" semantic the watcher needs, whereas
            // a blocking `acquire_lock` would freeze the watcher
            // loop for up-to-TTL on contended ticks.
            let pre_tick: Option<mcpg_bundle_reload::PreTickHook> = cluster.as_ref().map(|c| {
                let c = c.clone();
                // The lock must outlive the WHOLE reload (held across
                // parse + ArcSwap), not just one poll interval — a TTL ==
                // interval lets the lease expire mid-reload so a peer
                // reloads concurrently, defeating the dedup. Hold it for
                // several intervals (clamped to a sane floor). This is a
                // best-effort dedup lock, NOT a safety fence: the work is
                // idempotent (each replica ArcSwap-stores its own copy) and
                // the fencing token is only logged, never used to fence a
                // write — so a too-short TTL costs redundant work, not
                // correctness.
                let lock_ttl = (interval * 5).max(Duration::from_secs(30));
                let arc: mcpg_bundle_reload::PreTickHook =
                    std::sync::Arc::new(move || -> Option<mcpg_bundle_reload::ReloadPermit> {
                        match c.try_acquire_lock("policy.cedar.refresh", lock_ttl) {
                            Ok(Some(lease)) => {
                                tracing::debug!(
                                    plugin_id = PLUGIN_ID,
                                    fencing_token = lease.fencing_token(),
                                    "cedar policy: refresh lock acquired"
                                );
                                Some(Box::new(lease) as mcpg_bundle_reload::ReloadPermit)
                            }
                            Ok(None) => {
                                tracing::debug!(
                                    plugin_id = PLUGIN_ID,
                                    "cedar policy: refresh lock held by peer; skipping tick"
                                );
                                None
                            }
                            Err(e) => {
                                tracing::warn!(
                                    plugin_id = PLUGIN_ID,
                                    error = %e,
                                    "cedar policy: refresh lock attempt failed; skipping tick"
                                );
                                None
                            }
                        }
                    });
                arc
            });
            let opts = match pre_tick {
                Some(h) => mcpg_bundle_reload::BundleReloadOptions::new(interval).with_pre_tick(h),
                None => mcpg_bundle_reload::BundleReloadOptions::new(interval),
            };
            let bundle = rt
                .block_on(async {
                    mcpg_bundle_reload::start_with_options(source, parse_full, opts).await
                })
                .unwrap_or_else(|err| panic!("cedar policy: failed to load policies: {err}"));
            (bundle, Some(rt))
        } else {
            // Static-only path: parse once + wrap. No background
            // task; same shape as pre-reload behavior.
            let parsed = parse_full(&source)
                .unwrap_or_else(|err| panic!("cedar policy: failed to load policies: {err}"));
            // Static-only fingerprint covers all three inputs
            // (policy dir + schema + entities). A short-lived
            // single-thread runtime is fine — fingerprint is just
            // file IO + sha256, no contention.
            let fingerprint = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("static-only fingerprint runtime")
                .block_on(async { source.fingerprint().await })
                .unwrap_or_else(|err| {
                    panic!("cedar policy: failed to fingerprint composite source: {err}")
                });
            let bundle = mcpg_bundle_reload::static_only(parsed, fingerprint);
            (bundle, None)
        };

        let snapshot = bundle.load();

        // Cluster opt-in. On startup, when a coordinator is bound,
        // subscribe to the policies-loaded topic FIRST (so we don't
        // miss the local self-publish), then emit our own heartbeat
        // carrying the bundle fingerprint. Failures are logged and
        // swallowed — best-effort coordination, never blocks plugin
        // registration.
        //
        // The subscriber compares the peer's published fingerprint
        // to the local bundle's fingerprint; on mismatch, calls
        // `poke()` on the BundleReload so the watcher runs an
        // out-of-band poll. Latency from peer-publish to local
        // convergence drops from ~interval to ~network round-trip.
        let mut subscription = None;
        if let Some(client) = &cluster {
            let info = client.node_info();
            let local_node_id = info.node_id.clone();
            let poke_handle = bundle.poke_handle();
            let bundle_for_subscriber = bundle.clone();
            tracing::info!(
                plugin_id = PLUGIN_ID,
                cluster_node_id = %info.node_id,
                cluster_address = %info.address,
                "cedar policy: cluster coordinator bound"
            );

            match client.subscribe("policy.cedar.policies-loaded", None, None, move |msg| {
                let from = msg.from_node.clone();
                if from == local_node_id {
                    return; // self-publish — already logged
                }
                // Decode the heartbeat to extract the peer's
                // fingerprint. Best-effort: garbled payloads
                // fall back to "poke anyway" — the watcher's
                // own fingerprint check skips the swap if
                // fingerprints turn out to match.
                let peer_fp = serde_json::from_slice::<serde_json::Value>(&msg.payload)
                    .ok()
                    .and_then(|v| {
                        v.get("fingerprint")
                            .and_then(|f| f.as_str())
                            .map(str::to_owned)
                    });
                // Read CURRENT local fingerprint; the captured
                // bundle is cloneable so we always see the
                // freshest swap, not the startup snapshot.
                let local_fp = bundle_for_subscriber.fingerprint();
                let should_poke = match &peer_fp {
                    Some(peer) => peer != &local_fp,
                    None => true,
                };
                tracing::info!(
                    plugin_id = PLUGIN_ID,
                    from_node = %from,
                    topic = %msg.topic,
                    peer_fingerprint = ?peer_fp,
                    local_fingerprint = %local_fp,
                    poked = should_poke,
                    "cedar policy: peer reloaded policies"
                );
                if should_poke {
                    poke_handle.poke();
                }
            }) {
                Ok(s) => subscription = Some(s),
                Err(e) => tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "cedar policy: subscription setup failed"
                ),
            }

            let payload = serde_json::json!({
                "plugin_id": PLUGIN_ID,
                "version": env!("CARGO_PKG_VERSION"),
                "policies_count": snapshot.policy_set.policies().count(),
                "fingerprint": bundle.fingerprint(),
                "node_id": info.node_id,
            });
            let bytes = bytes::Bytes::from(serde_json::to_vec(&payload).unwrap_or_default());
            if let Err(e) = client.publish("policy.cedar.policies-loaded", None, bytes) {
                tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "cedar policy: heartbeat publish failed"
                );
            }
        }

        tracing::info!(
            plugin_id = PLUGIN_ID,
            policy_dir = %cfg.policy_dir,
            policies_loaded = snapshot.policy_set.policies().count(),
            reload_enabled = cfg.reload.enabled,
            schema_loaded = snapshot.schema.is_some(),
            entities_loaded = cfg.entities_path.is_some(),
            include_input_as_context = cfg.include_input_as_context,
            cluster_bound = cluster.is_some(),
            "cedar policy: PolicySet compiled"
        );

        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "Cedar Policy Engine".into(),
                    plugin_class: PluginClass::PolicyEngine,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                bundle,
                authorizer: Authorizer::new(),
                _runtime: runtime,
                cluster,
                cluster_subscription: subscription,
                host_handle: OnceLock::new(),
            }),
        }
    }

    /// Install the unified [`HostHandle`] surface for
    /// per-call observability. The SDK factory installs this
    /// exactly once at boot, after constructing the plugin via
    /// [`CedarPolicyPlugin::from_config_json_with_cluster`] but
    /// before any `evaluate()` traffic is dispatched, threading a
    /// handle built from the late-bound `HostServices`.
    ///
    /// Idempotent — a second call returns `false` so reload paths
    /// that re-enter the install site don't panic. The returned
    /// `bool` indicates whether the handle was installed (`true`)
    /// or the slot was already occupied (`false`).
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.inner.host_handle.set(host).is_ok()
    }

    /// Borrow the installed unified host surface, if any.
    /// Returns `None` in test harnesses that constructed the plugin
    /// without calling [`CedarPolicyPlugin::set_host_handle`].
    /// Callers MUST treat `None` as "skip the host observability
    /// triad" — the plugin's internal `tracing::*` + `metrics::*`
    /// calls remain wired and carry the load through their own
    /// sinks.
    fn host_handle(&self) -> Option<&HostHandle> {
        self.inner.host_handle.get()
    }
}

/// Re-parses the full triple (policies + optional schema +
/// optional entities). Called by the bundle-reload watcher when
/// any of the three inputs changes; also called from the static-
/// only construction path to do the initial parse.
#[allow(clippy::result_large_err)]
fn parse_full_bundle(
    policy_dir: &str,
    schema_path: Option<&str>,
    entities_path: Option<&str>,
) -> Result<CompiledBundle, ReloadError> {
    // Schema first — entities + policies both depend on it.
    let schema = match schema_path {
        Some(path) => {
            let contents = std::fs::read_to_string(path).map_err(|e| ReloadError::Io {
                path: path.to_owned(),
                error: e.to_string(),
            })?;
            // Try human syntax first; fall back to JSON.
            let parsed = Schema::from_str(&contents)
                .or_else(|_| Schema::from_json_str(&contents))
                .map_err(|e| ReloadError::Parse(format!("schema parse '{path}' failed: {e}")))?;
            Some(Arc::new(parsed))
        }
        None => None,
    };

    // Entities second — typed against schema if present.
    let entities = match entities_path {
        Some(path) => {
            let contents = std::fs::read_to_string(path).map_err(|e| ReloadError::Io {
                path: path.to_owned(),
                error: e.to_string(),
            })?;
            let parsed = Entities::from_json_str(&contents, schema.as_deref())
                .map_err(|e| ReloadError::Parse(format!("entities parse '{path}' failed: {e}")))?;
            Arc::new(parsed)
        }
        None => Arc::new(Entities::empty()),
    };

    // Policy directory last — uses schema for validation.
    let policy_source = BundleSource::Directory {
        root: policy_dir.into(),
        extension: Some("cedar".into()),
    };
    let mut compiled = parse_bundle_with_schema(&policy_source, schema.as_deref())?;
    compiled.schema = schema;
    compiled.entities = entities;
    Ok(compiled)
}

/// Bundle parser used by `BundleReload`. Aggregates every
/// `.cedar` file in the source's directory into a single
/// PolicySet + indexes its forbid policy ids. When `schema` is
/// `Some`, runs `Validator` against the parsed PolicySet — any
/// validation error short-circuits the load (operators see the
/// schema-mismatch message in the panic / reload retain).
fn parse_bundle_with_schema(
    source: &BundleSource,
    schema: Option<&Schema>,
) -> Result<CompiledBundle, ReloadError> {
    let paths = source.list_files()?;
    let mut combined = String::new();
    for path in &paths {
        let bytes = std::fs::read(path).map_err(|e| ReloadError::Io {
            path: path.display().to_string(),
            error: e.to_string(),
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| ReloadError::Parse(format!("non-utf8 in {}: {e}", path.display())))?;
        combined.push_str(text);
        combined.push('\n');
    }
    let policy_set: PolicySet = combined
        .parse()
        .map_err(|e| ReloadError::Parse(format!("parsing combined PolicySet: {e}")))?;
    if let Some(schema) = schema {
        let validator = Validator::new(schema.clone());
        let result = validator.validate(&policy_set, ValidationMode::Strict);
        if !result.validation_passed() {
            let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
            return Err(ReloadError::Parse(format!(
                "schema validation failed: {}",
                errors.join("; ")
            )));
        }
    }
    let mut forbid_ids = std::collections::BTreeSet::new();
    for policy in policy_set.policies() {
        if matches!(policy.effect(), cedar_policy::Effect::Forbid) {
            forbid_ids.insert(policy.id().clone());
        }
    }
    Ok(CompiledBundle {
        policy_set,
        forbid_ids,
        // Filled in by `parse_full_bundle` after the policy set
        // compiles. Constructed here as defaults so this helper
        // remains useful in isolation (e.g. tests that don't
        // care about reload-aware schema/entities).
        schema: None,
        entities: Arc::new(Entities::empty()),
    })
}

fn quote_uid_id(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn build_request(
    config: &CedarConfig,
    schema: Option<&Schema>,
    decision_point: &str,
    input: &Value,
    context: &PluginContext,
) -> Result<Request, String> {
    let principal_id = context
        .identity
        .subject_id
        .clone()
        .unwrap_or_else(|| config.translation.anonymous_principal_id.clone());
    let principal: EntityUid = format!(
        "{}::\"{}\"",
        config.translation.principal_type,
        quote_uid_id(&principal_id)
    )
    .parse()
    .map_err(|e| format!("invalid principal UID: {e}"))?;

    let action: EntityUid = format!(
        "{}::\"{}\"",
        config.translation.action_namespace,
        quote_uid_id(decision_point)
    )
    .parse()
    .map_err(|e| format!("invalid action UID: {e}"))?;

    let resource_entry = config.resource_type_for(decision_point).ok_or_else(|| {
        format!(
            "no resource_types entry covers decision_point `{decision_point}` \
             (and no `*` catch-all configured)"
        )
    })?;
    let resource_id = if resource_entry.resource_id_path.is_empty() {
        "unspecified".to_owned()
    } else {
        match input.pointer(&resource_entry.resource_id_path) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(other) => other.to_string(),
            None => "unknown".to_owned(),
        }
    };
    let resource: EntityUid = format!(
        "{}::\"{}\"",
        resource_entry.resource_type,
        quote_uid_id(&resource_id)
    )
    .parse()
    .map_err(|e| format!("invalid resource UID: {e}"))?;

    let cedar_context = build_context(config, schema, &action, input)?;
    Request::new(principal, action, resource, cedar_context, schema)
        .map_err(|e| format!("invalid Cedar request: {e}"))
}

fn build_context(
    config: &CedarConfig,
    schema: Option<&Schema>,
    action: &EntityUid,
    input: &Value,
) -> Result<Context, String> {
    if !config.include_input_as_context {
        return Ok(Context::empty());
    }
    // Cedar's Context is a JSON object. If `input` is anything
    // other than an object, wrap it under a stable `value` key
    // so policies can still reference it.
    let json = match input {
        Value::Object(_) => input.clone(),
        _ => serde_json::json!({"value": input.clone()}),
    };
    let schema_pair = schema.map(|s| (s, action));
    Context::from_json_value(json, schema_pair)
        .map_err(|e| format!("input → context translation failed: {e}"))
}

fn evaluate_request(
    plugin: &CedarPolicyPlugin,
    decision_point: &str,
    input: &Value,
    context: &PluginContext,
) -> PolicyDecision {
    // Wrap each evaluation in an info_span so traces attribute back
    // to `dev.mcpg.policy.cedar`. Decision-point + version-hash flow
    // as span attributes so a downstream TelemetrySink can build
    // "deny rate by policy version" or "p99 latency per
    // decision_point" panels without parsing log lines.
    let _span = tracing::info_span!(
        "cedar_policy_evaluate",
        plugin_id = PLUGIN_ID,
        decision_point = %decision_point,
    )
    .entered();

    // Open a host-attributed span ALONGSIDE the
    // internal `info_span!` above. The internal span flows through
    // the local `tracing` subscriber; the host span routes to the
    // central observability sink with the plugin alias as a
    // resource attribute. Attrs carry the bundle fingerprint
    // (policy_id) so operators can correlate "deny spike" against
    // a specific compiled policy version. We deliberately avoid
    // putting individual rule ids here — operators may have
    // hundreds of rules; the per-deny audit event carries the
    // matched rule ids in `details` (high-cardinality is fine in
    // audit details, not in span attrs).
    let policy_id = plugin.inner.bundle.fingerprint();
    let host_span = plugin.host_handle().map(|h| {
        h.span(
            "policy_cedar.evaluate",
            serde_json::json!({
                "decision_point": decision_point,
                "policy_id": policy_id,
                "request_id": context.request_id,
            }),
        )
    });

    let started = std::time::Instant::now();
    let outcome = evaluate_request_inner(&plugin.inner, decision_point, input, context);
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_millis() as f64;
    metrics::histogram!(
        "mcpg_policy_cedar_evaluate_ms",
        "decision_point" => decision_point.to_owned(),
    )
    .record(elapsed_ms);
    // Internal metric — keep cardinality identical to the original
    // (allow / deny / not_applicable) so any existing operator
    // dashboards continue to render.
    let internal_outcome_label = match outcome.effect {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::NotApplicable => "not_applicable",
    };
    metrics::counter!(
        "mcpg_policy_cedar_decisions_total",
        "decision_point" => decision_point.to_owned(),
        "outcome" => internal_outcome_label,
    )
    .increment(1);

    // Unified host-observability triad. Runs ALONGSIDE
    // the metrics::* calls above; the two coexist intentionally
    // until the host sinks subsume the internal calls.
    //
    // Cardinality budget on host-side: outcome ∈ {allow, deny,
    // error}. `not_applicable` maps to `allow` because the gateway
    // treats it as "engine declined cleanly, traffic proceeds" —
    // the metric is "did this evaluation block traffic or not".
    // Operators wanting the finer breakdown read the internal
    // `mcpg_policy_cedar_decisions_total` above.
    let outcome_label = host_outcome_label(&outcome);
    plugin.emit_host_observability(decision_point, &outcome, outcome_label, elapsed, context);

    // Explicitly drop the host span here so its Drop-driven
    // `span_end` fires AFTER the metric + audit emission above.
    drop(host_span);

    outcome
}

/// Bounded host-side outcome label set:
/// `allow`, `deny`, `error`. `not_applicable` rolls into
/// `allow` because both let traffic through; operators wanting
/// the four-way breakdown read the internal
/// `mcpg_policy_cedar_decisions_total` counter.
fn host_outcome_label(decision: &PolicyDecision) -> &'static str {
    match decision.effect {
        PolicyEffect::Allow | PolicyEffect::NotApplicable => "allow",
        PolicyEffect::Deny => {
            // Differentiate engine-error path (request translation
            // failed) from rule-driven deny. The translation-error
            // path stamps `cedar translate:` into the reason; the
            // rule-driven deny stamps `cedar forbid:` or
            // `default-deny`.
            match decision.reason.as_deref() {
                Some(r) if r.starts_with("cedar translate:") => "error",
                _ => "deny",
            }
        }
    }
}

/// Inner implementation of `evaluate_request`. Split out so the
/// span + metrics wrapping in the public entry stays readable.
fn evaluate_request_inner(
    inner: &Inner,
    decision_point: &str,
    input: &Value,
    context: &PluginContext,
) -> PolicyDecision {
    // Snapshot the bundle once per call. arc_swap guarantees a
    // mid-evaluation reload doesn't affect this evaluation.
    // Schema + entities live INSIDE the bundle, so a single
    // load() snapshot covers all three inputs atomically.
    let bundle = inner.bundle.load();
    let version_hash = inner.bundle.fingerprint();
    let request = match build_request(
        &inner.config,
        bundle.schema.as_deref(),
        decision_point,
        input,
        context,
    ) {
        Ok(r) => r,
        Err(detail) => {
            tracing::warn!(
                plugin_id = PLUGIN_ID,
                decision_point = %decision_point,
                error = %detail,
                "cedar policy: request translation failed; denying"
            );
            return PolicyDecision::deny(format!("cedar translate: {detail}"), &version_hash);
        }
    };

    let response = inner
        .authorizer
        .is_authorized(&request, &bundle.policy_set, &bundle.entities);

    match response.decision() {
        Decision::Allow => {
            // Stack `@advice` + `@redact` annotations from
            // every matched permit onto the decision.
            let (obligations, redactions) = extract_advice(
                &bundle.policy_set,
                response.diagnostics().reason(),
                /* include_redactions */ true,
            );
            PolicyDecision {
                effect: PolicyEffect::Allow,
                reason: None,
                obligations,
                redactions,
                attributes: BTreeMap::new(),
                policy_version: version_hash,
            }
        }
        Decision::Deny => {
            // Distinguish explicit forbid match vs cedar default-deny.
            let matched_forbids: Vec<String> = response
                .diagnostics()
                .reason()
                .filter(|pid| bundle.forbid_ids.contains(*pid))
                .map(|pid| pid.to_string())
                .collect();
            if matched_forbids.is_empty() {
                match inner.config.evaluation.on_default_deny {
                    DefaultDenyMode::NotApplicable => PolicyDecision {
                        effect: PolicyEffect::NotApplicable,
                        reason: None,
                        obligations: vec![],
                        redactions: vec![],
                        attributes: BTreeMap::new(),
                        policy_version: version_hash,
                    },
                    DefaultDenyMode::Deny => PolicyDecision::deny(
                        "cedar: default-deny (no policy matched)",
                        &version_hash,
                    ),
                }
            } else {
                // Forbids may carry `@advice` (e.g. a
                // rejection-audit obligation). Redactions on a
                // Deny don't apply — the payload is blocked.
                let (obligations, _) = extract_advice(
                    &bundle.policy_set,
                    response
                        .diagnostics()
                        .reason()
                        .filter(|pid| bundle.forbid_ids.contains(*pid)),
                    /* include_redactions */ false,
                );
                PolicyDecision {
                    effect: PolicyEffect::Deny,
                    reason: Some(format!("cedar forbid: {}", matched_forbids.join(", "))),
                    obligations,
                    redactions: vec![],
                    attributes: BTreeMap::new(),
                    policy_version: version_hash,
                }
            }
        }
    }
}

/// Pull `@advice` + `@redact` annotations off every policy in
/// the matched-policy iterator and translate them into
/// [`Obligation`] + [`Redaction`] vectors.
///
/// `@advice` format is `kind` alone (args = `null`) or
/// `kind:<json_value>`. Anything that doesn't parse falls back
/// to `args = String(remainder)` so operator typos still surface
/// the policy's intent — failing closed (dropping the obligation)
/// would mask the policy's audit signal.
///
/// `@redact` carries a JSON-pointer string verbatim; replacement
/// is always `"***"` (a JSON string). Operators wanting other
/// replacement shapes (e.g. `null`, `0`) compose multiple
/// policies — Cedar's annotation model only allows one annotation
/// per key per policy.
fn extract_advice<'a, I>(
    policy_set: &PolicySet,
    matched: I,
    include_redactions: bool,
) -> (Vec<Obligation>, Vec<Redaction>)
where
    I: Iterator<Item = &'a PolicyId>,
{
    let mut obligations = Vec::new();
    let mut redactions = Vec::new();
    for pid in matched {
        let Some(policy) = policy_set.policy(pid) else {
            continue;
        };
        for (key, value) in policy.annotations() {
            match key {
                "advice" => match parse_advice(value) {
                    Some(o) => obligations.push(o),
                    None => tracing::warn!(
                        plugin_id = PLUGIN_ID,
                        policy_id = %pid,
                        annotation = %value,
                        "cedar: malformed @advice annotation; skipping"
                    ),
                },
                "redact" if include_redactions => {
                    let pointer = value.trim();
                    if pointer.is_empty() {
                        tracing::warn!(
                            plugin_id = PLUGIN_ID,
                            policy_id = %pid,
                            "cedar: empty @redact annotation; skipping"
                        );
                    } else {
                        redactions.push(Redaction {
                            json_pointer: pointer.to_owned(),
                            replacement: Value::String("***".into()),
                        });
                    }
                }
                _ => {} // unknown annotations: ignore
            }
        }
    }
    (obligations, redactions)
}

fn parse_advice(value: &str) -> Option<Obligation> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (kind, rest) = match trimmed.find(':') {
        Some(idx) => (trimmed[..idx].trim(), trimmed[idx + 1..].trim()),
        None => (trimmed, ""),
    };
    if kind.is_empty() {
        return None;
    }
    let args = if rest.is_empty() {
        Value::Null
    } else {
        // Try parsing as JSON; fall back to a plain-string arg
        // so operators typing `audit.emit:warn` (no quotes) get
        // an Obligation with args = "warn" rather than a parse
        // error swallowing the annotation.
        serde_json::from_str(rest).unwrap_or_else(|_| Value::String(rest.to_owned()))
    };
    Some(Obligation {
        kind: kind.to_owned(),
        args,
    })
}

impl CedarPolicyPlugin {
    /// Emit the per-evaluation host-observability triad:
    /// latency histogram + decisions counter + Deny / Error audit
    /// event, through the installed [`HostHandle`]. Short-circuits
    /// to a no-op when no handle is installed (test paths). Never
    /// audit-emits on `allow` — that's normal traffic.
    ///
    /// Cardinality budget: outcome ∈ {allow, deny, error}.
    ///
    /// Audit emission is gated to deny / error:
    ///
    /// - `dev.mcpg.policy.cedar.deny` on rule-driven Deny (carries
    ///   matched forbid policy ids in `details.matched_rules`).
    /// - `dev.mcpg.policy.cedar.error` on engine-error Deny (the
    ///   evaluator itself couldn't run — request translation
    ///   failed, schema mismatch, missing entity attribute, etc).
    ///
    /// `SyncPolicyEngine::evaluate` is sync; the gateway dispatches
    /// it from a `spawn_blocking` worker, so calling
    /// `HostHandle::audit_event` directly here is safe — the host's
    /// internal `block_on` lands on a blocking thread, not a tokio
    /// worker.
    fn emit_host_observability(
        &self,
        decision_point: &str,
        decision: &PolicyDecision,
        outcome_label: &'static str,
        duration: std::time::Duration,
        context: &PluginContext,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        let elapsed_secs = duration.as_secs_f64();
        host.histogram(
            "mcpg_policy_cedar_latency_seconds",
            elapsed_secs,
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_policy_cedar_decisions_total",
            1,
            &[("outcome", outcome_label)],
        );

        // Audit ONLY on `deny` / `error`. Allow is normal traffic
        // and would flood the audit sink at policy traffic rates.
        let action: Option<&'static str> = match outcome_label {
            "deny" => Some("dev.mcpg.policy.cedar.deny"),
            "error" => Some("dev.mcpg.policy.cedar.error"),
            _ => None,
        };
        let Some(action) = action else {
            return;
        };

        // Distinguish the engine-error path from rule-driven deny
        // for the audit outcome enum so compliance dashboards can
        // separate denied (expected) from errored (unexpected).
        let audit_outcome = match outcome_label {
            "error" => AuditOutcome::Failure,
            _ => AuditOutcome::Denied,
        };

        // Pull matched forbid policy ids out of the decision's
        // `reason` field. The rule-driven Deny stamps
        // "cedar forbid: <id>, <id>, ..." into the reason; the
        // default-deny path stamps "cedar: default-deny ..." and
        // exposes no rule ids. The error path stamps
        // "cedar translate: ...".
        let matched_rules: Vec<&str> = match decision.reason.as_deref() {
            Some(r) if r.starts_with("cedar forbid:") => r
                .trim_start_matches("cedar forbid:")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        };

        let subject = context
            .identity
            .subject_id
            .clone()
            .unwrap_or_else(|| self.inner.config.translation.anonymous_principal_id.clone());
        let resource_uri = format!("tool://{}/{}", context.tool_name, decision_point);

        let details = serde_json::json!({
            "engine": ENGINE_NAME,
            "decision_point": decision_point,
            "subject": subject,
            "resource": resource_uri,
            "matched_rules": matched_rules,
            "reason": decision.reason.clone().unwrap_or_default(),
            "policy_version": decision.policy_version.clone(),
            "duration_ms": duration.as_millis() as u64,
            "alias": host.alias(),
        });

        let actor = if context.identity.kind.is_empty() {
            synthetic_system_identity()
        } else {
            context.identity.clone()
        };

        let event = AuditEvent {
            event_id: format!("cedar-{}-{}", context.request_id, duration.as_nanos()),
            occurred_at: rfc3339_now(),
            actor,
            action: action.to_owned(),
            resource: Some(resource_uri),
            outcome: audit_outcome,
            request_id: Some(context.request_id.clone()),
            node_id: None,
            details,
            prev_event_hash: None,
        };
        let host_for_audit = host.clone();
        // SyncPolicyEngine::evaluate is sync — the SDK's FFI
        // adapter dispatches it on a blocking-friendly worker
        // (the host's `tokio::task::spawn_blocking` chain). We
        // call `HostHandle::audit_event` directly here; the
        // host's bridge handles the async crossing internally.
        // No `tokio::task::spawn_blocking` wrap because we may
        // not be inside a tokio runtime context at this call
        // site (the policy evaluator can be invoked from a
        // non-tokio thread via the sync SDK).
        if let Err(err) = host_for_audit.audit_event(event) {
            tracing::debug!(
                target: "mcpg::policy::cedar::host_handle",
                error = %err,
                "host_handle.audit_event emission failed"
            );
        }
    }
}

impl SyncPolicyEngine for CedarPolicyPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn name(&self) -> &str {
        ENGINE_NAME
    }

    fn evaluate(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        evaluate_request(self, decision_point, input, context)
    }

    fn policy_version(&self) -> PolicyVersion {
        current_policy_version(&self.inner)
    }
}

#[mcpg_plugin_protocol::async_trait]
impl mcpg_plugin_protocol::policy::PolicyEngine for CedarPolicyPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn name(&self) -> &str {
        ENGINE_NAME
    }

    async fn evaluate(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        evaluate_request(self, decision_point, input, context)
    }

    async fn policy_version(&self) -> PolicyVersion {
        current_policy_version(&self.inner)
    }
}

/// Best-effort RFC 3339 timestamp for audit event `occurred_at`.
/// Audit sinks sort lexicographically by `occurred_at`, so
/// calendar-correct formatting matters.
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Naïve epoch → (Y, M, D, h, m, s). Good enough for audit
/// timestamps; doesn't handle leap seconds. Mirrors the policy-opa
/// helper rather than pulling chrono into this crate.
fn epoch_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_today = secs.rem_euclid(86_400) as u32;
    let hour = secs_today / 3600;
    let min = (secs_today % 3600) / 60;
    let sec = secs_today % 60;
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

/// Synthetic identity for audit events emitted on inbound requests
/// that carry no caller attribution (system-initiated paths).
/// Audit sinks treat `kind = "system"` specially
/// so these events are easy to filter out of caller-attributed
/// dashboards. Mirrors the SQL / HTTP plugin synthetic identity
/// so cross-plugin audit search treats system traffic uniformly.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some(PLUGIN_ID.into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn current_policy_version(inner: &Inner) -> PolicyVersion {
    PolicyVersion {
        hash: inner.bundle.fingerprint(),
        loaded_at: now_marker(),
        source: format!("cedar policies in {}", inner.config.policy_dir),
    }
}

fn now_marker() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@{secs}")
}

declare_plugin! {
    plugin_id: "dev.mcpg.policy.cedar",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        policy_engine as policy {
            inner_name: "",
            plugin_type: CedarPolicyPlugin,
            // Receives a `HostHandle` from the macro. The plugin
            // derives cluster via `host.cluster()` to emit a
            // startup heartbeat on `policy.cedar.policies-loaded` carrying
            // the bundle fingerprint and stash the client for future
            // cross-node entity / policy refresh coordination.
            //
            // Also install the unified `HostHandle` on the
            // plugin so per-evaluation observability (span + latency
            // histogram + decisions counter + Deny / Error audit
            // events) routes through the gateway's central
            // host-services sink. Idempotent — a second install
            // returns false and the slot remains untouched.
            factory: |cfg: &str, host: ::mcpg_plugin_sdk::HostHandle| -> CedarPolicyPlugin {
                let plugin = CedarPolicyPlugin::from_config_json_with_cluster(
                    cfg,
                    host.cluster(),
                );
                let _installed = plugin.set_host_handle(host);
                plugin
            },
        }
    ],
}

#[allow(dead_code)]
fn _identity_marker(_: &PluginIdentity) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FIXTURE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn write_policy_dir(policies: &[&str]) -> std::path::PathBuf {
        let n = FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("mcpg-cedar-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        for (i, content) in policies.iter().enumerate() {
            let path = dir.join(format!("p{i}.cedar"));
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
        }
        dir
    }

    fn build(policies: &[&str], translation: serde_json::Value) -> CedarPolicyPlugin {
        let dir = write_policy_dir(policies);
        let cfg = json!({
            "policy_dir": dir.to_string_lossy().to_string(),
            "translation": translation,
        });
        CedarPolicyPlugin::from_config_json(&cfg.to_string())
    }

    fn ctx(subject: &str) -> PluginContext {
        PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "tool".into(),
            surface: "tool".into(),
            identity: PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some(subject.into()),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    fn standard_translation() -> serde_json::Value {
        json!({
            "principal_type": "User",
            "action_namespace": "Action",
            "resource_types": [
                { "decision_point": "*", "resource_type": "Tool", "resource_id_path": "/tool" }
            ]
        })
    }

    #[test]
    fn permit_allows_matching_request() {
        let plugin = build(
            &[r#"permit(
                principal == User::"alice",
                action == Action::"read",
                resource == Tool::"orders"
            );"#],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    #[test]
    fn no_match_maps_to_not_applicable() {
        let plugin = build(
            &[r#"permit(
                principal == User::"alice",
                action == Action::"read",
                resource == Tool::"orders"
            );"#],
            standard_translation(),
        );
        let dec =
            SyncPolicyEngine::evaluate(&plugin, "read", &json!({ "tool": "users" }), &ctx("alice"));
        assert_eq!(dec.effect, PolicyEffect::NotApplicable);
    }

    #[test]
    fn forbid_emits_explicit_deny_with_reason() {
        let plugin = build(
            &[
                r#"permit(principal, action, resource);"#,
                r#"@policy_id("forbid-write")
                forbid(
                    principal,
                    action == Action::"write",
                    resource
                );"#,
            ],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "write",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Deny);
        let reason = dec.reason.unwrap();
        assert!(reason.starts_with("cedar forbid:"));
    }

    #[test]
    fn strict_default_deny_returns_deny() {
        let dir = write_policy_dir(&[r#"permit(principal == User::"alice", action, resource);"#]);
        let cfg = json!({
            "policy_dir": dir.to_string_lossy().to_string(),
            "translation": standard_translation(),
            "evaluation": { "on_default_deny": "deny" }
        });
        let plugin = CedarPolicyPlugin::from_config_json(&cfg.to_string());
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("bob"), // doesn't match alice's permit
        );
        assert_eq!(dec.effect, PolicyEffect::Deny);
        assert!(dec.reason.unwrap().contains("default-deny"));
    }

    #[test]
    fn anonymous_principal_used_when_subject_id_absent() {
        let plugin = build(
            &[r#"permit(
                principal == User::"anonymous",
                action == Action::"read",
                resource
            );"#],
            standard_translation(),
        );
        let mut c = ctx("alice");
        c.identity.subject_id = None;
        let dec = SyncPolicyEngine::evaluate(&plugin, "read", &json!({ "tool": "x" }), &c);
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    #[test]
    fn resource_id_path_extraction() {
        let plugin = build(
            &[r#"permit(
                principal,
                action == Action::"read",
                resource == Tool::"orders"
            );"#],
            standard_translation(),
        );
        // Resource id is taken from input.tool path.
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    #[test]
    fn missing_resource_id_path_falls_back_to_unknown() {
        let plugin = build(
            &[r#"permit(
                principal,
                action == Action::"read",
                resource == Tool::"unknown"
            );"#],
            standard_translation(),
        );
        // Input doesn't contain "tool" path → resource id "unknown".
        let dec =
            SyncPolicyEngine::evaluate(&plugin, "read", &json!({ "other": "x" }), &ctx("alice"));
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    #[test]
    fn policy_version_hash_changes_with_policy_content() {
        let p1 = build(
            &[r#"permit(principal == User::"alice", action, resource);"#],
            standard_translation(),
        );
        let p2 = build(
            &[r#"permit(principal == User::"bob", action, resource);"#],
            standard_translation(),
        );
        assert_ne!(p1.inner.bundle.fingerprint(), p2.inner.bundle.fingerprint());
    }

    #[test]
    fn per_decision_point_resource_type_takes_precedence_over_catchall() {
        let plugin = build(
            &[r#"permit(
                principal,
                action == Action::"read",
                resource == Document::"x"
            );"#],
            json!({
                "principal_type": "User",
                "action_namespace": "Action",
                "resource_types": [
                    { "decision_point": "read", "resource_type": "Document", "resource_id_path": "/doc" },
                    { "decision_point": "*", "resource_type": "Tool" }
                ]
            }),
        );
        let dec =
            SyncPolicyEngine::evaluate(&plugin, "read", &json!({ "doc": "x" }), &ctx("alice"));
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    // -- Schema + entities + context tests --------------------------------

    fn write_aux_file(name: &str, body: &str) -> std::path::PathBuf {
        let n = FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "mcpg-cedar-test-{}-{}-{name}",
            std::process::id(),
            n
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        path
    }

    #[test]
    fn entities_store_enables_group_membership_policies() {
        let dir = write_policy_dir(&[r#"permit(
            principal in Group::"sec",
            action == Action::"read",
            resource == Tool::"orders"
        );"#]);
        let entities_path = write_aux_file(
            "entities.json",
            r#"[
                {"uid": {"type":"User","id":"alice"},"attrs":{},"parents":[{"type":"Group","id":"sec"}]},
                {"uid": {"type":"User","id":"bob"},"attrs":{},"parents":[]},
                {"uid": {"type":"Group","id":"sec"},"attrs":{},"parents":[]}
            ]"#,
        );
        let cfg = json!({
            "policy_dir": dir.to_string_lossy().to_string(),
            "translation": standard_translation(),
            "entities_path": entities_path.to_string_lossy().to_string(),
        });
        let plugin = CedarPolicyPlugin::from_config_json(&cfg.to_string());
        // Alice is in Group::sec → permit
        let dec =
            SyncPolicyEngine::evaluate(&plugin, "read", &json!({"tool": "orders"}), &ctx("alice"));
        assert_eq!(dec.effect, PolicyEffect::Allow);
        // Bob isn't in the group → no policy matches → NotApplicable
        let dec =
            SyncPolicyEngine::evaluate(&plugin, "read", &json!({"tool": "orders"}), &ctx("bob"));
        assert_eq!(dec.effect, PolicyEffect::NotApplicable);
    }

    #[test]
    fn include_input_as_context_makes_policies_see_input() {
        let dir = write_policy_dir(&[r#"permit(
            principal,
            action == Action::"call",
            resource
        ) when {
            context has env && context.env == "prod"
        };"#]);
        let cfg = json!({
            "policy_dir": dir.to_string_lossy().to_string(),
            "translation": standard_translation(),
            "include_input_as_context": true,
        });
        let plugin = CedarPolicyPlugin::from_config_json(&cfg.to_string());
        // env=prod → permit
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "call",
            &json!({"tool": "x", "env": "prod"}),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
        // env=dev → no match
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "call",
            &json!({"tool": "x", "env": "dev"}),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::NotApplicable);
    }

    #[test]
    fn schema_validation_rejects_action_not_in_schema() {
        let dir = write_policy_dir(&[r#"permit(
            principal,
            action == Action::"undeclared",
            resource
        );"#]);
        let schema_path = write_aux_file(
            "schema.cedarschema.json",
            r#"{
                "": {
                    "entityTypes": {
                        "User": {},
                        "Tool": {}
                    },
                    "actions": {
                        "read": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["Tool"]
                            }
                        }
                    }
                }
            }"#,
        );
        let cfg = json!({
            "policy_dir": dir.to_string_lossy().to_string(),
            "translation": standard_translation(),
            "schema_path": schema_path.to_string_lossy().to_string(),
        });
        let result =
            std::panic::catch_unwind(|| CedarPolicyPlugin::from_config_json(&cfg.to_string()));
        assert!(
            result.is_err(),
            "expected schema-incompatible policy to refuse load"
        );
    }

    #[test]
    fn schema_loaded_from_human_syntax_path() {
        let dir = write_policy_dir(&[r#"permit(
            principal,
            action == Action::"read",
            resource
        );"#]);
        // Cedar human-readable schema (.cedarschema)
        let schema_path = write_aux_file(
            "schema.cedarschema",
            r#"
                entity User;
                entity Tool;
                action read appliesTo {
                    principal: [User],
                    resource: [Tool]
                };
            "#,
        );
        let cfg = json!({
            "policy_dir": dir.to_string_lossy().to_string(),
            "translation": standard_translation(),
            "schema_path": schema_path.to_string_lossy().to_string(),
        });
        let plugin = CedarPolicyPlugin::from_config_json(&cfg.to_string());
        let dec =
            SyncPolicyEngine::evaluate(&plugin, "read", &json!({"tool": "orders"}), &ctx("alice"));
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    /// Schema + entities are part of the reload bundle. Verify the
    /// static-only path produces a fingerprint that includes BOTH
    /// the policy directory bytes
    /// AND the schema file bytes — changing the schema between
    /// runs MUST yield a different fingerprint.
    #[test]
    fn fingerprint_changes_when_schema_changes() {
        let dir = write_policy_dir(&[r#"permit(
            principal,
            action == Action::"read",
            resource
        );"#]);
        let schema_a = write_aux_file(
            "schema-a.cedarschema",
            r#"
                entity User;
                entity Tool;
                action read appliesTo { principal: [User], resource: [Tool] };
            "#,
        );
        let schema_b = write_aux_file(
            "schema-b.cedarschema",
            r#"
                entity Worker;
                entity Resource;
                action read appliesTo { principal: [Worker], resource: [Resource] };
            "#,
        );
        let plugin_a = CedarPolicyPlugin::from_config_json(
            &json!({
                "policy_dir": dir.to_string_lossy().to_string(),
                "translation": standard_translation(),
                "schema_path": schema_a.to_string_lossy().to_string(),
            })
            .to_string(),
        );
        let plugin_b = CedarPolicyPlugin::from_config_json(
            &json!({
                "policy_dir": dir.to_string_lossy().to_string(),
                "translation": standard_translation(),
                "schema_path": schema_b.to_string_lossy().to_string(),
            })
            .to_string(),
        );
        let v_a = SyncPolicyEngine::policy_version(&plugin_a);
        let v_b = SyncPolicyEngine::policy_version(&plugin_b);
        assert_ne!(
            v_a.hash, v_b.hash,
            "schema content change must surface as different policy_version hash"
        );
    }

    /// Same shape for entities — different entities file content
    /// → different fingerprint.
    #[test]
    fn fingerprint_changes_when_entities_change() {
        let dir = write_policy_dir(&[r#"permit(
            principal,
            action == Action::"read",
            resource
        );"#]);
        let entities_a = write_aux_file(
            "entities-a.json",
            r#"[
                {"uid":{"type":"User","id":"alice"},"attrs":{},"parents":[]}
            ]"#,
        );
        let entities_b = write_aux_file(
            "entities-b.json",
            r#"[
                {"uid":{"type":"User","id":"bob"},"attrs":{},"parents":[]}
            ]"#,
        );
        let plugin_a = CedarPolicyPlugin::from_config_json(
            &json!({
                "policy_dir": dir.to_string_lossy().to_string(),
                "translation": standard_translation(),
                "entities_path": entities_a.to_string_lossy().to_string(),
            })
            .to_string(),
        );
        let plugin_b = CedarPolicyPlugin::from_config_json(
            &json!({
                "policy_dir": dir.to_string_lossy().to_string(),
                "translation": standard_translation(),
                "entities_path": entities_b.to_string_lossy().to_string(),
            })
            .to_string(),
        );
        assert_ne!(
            SyncPolicyEngine::policy_version(&plugin_a).hash,
            SyncPolicyEngine::policy_version(&plugin_b).hash,
            "entities content change must surface as different policy_version hash"
        );
    }

    // ─────────────────────────────────────────────────────────
    // `@advice` + `@redact` annotation extraction
    // ─────────────────────────────────────────────────────────

    #[test]
    fn parse_advice_kind_only() {
        let obl = parse_advice("audit.emit").expect("kind-only parses");
        assert_eq!(obl.kind, "audit.emit");
        assert_eq!(obl.args, Value::Null);
    }

    #[test]
    fn parse_advice_kind_with_json_args() {
        let obl = parse_advice("audit.emit:{\"level\":\"warn\"}").expect("kind + json parses");
        assert_eq!(obl.kind, "audit.emit");
        assert_eq!(obl.args, json!({ "level": "warn" }));
    }

    #[test]
    fn parse_advice_kind_with_string_args_falls_back() {
        // Operator typed `audit.emit:warn` (no JSON quoting).
        // Don't drop the obligation — surface as String args.
        let obl = parse_advice("audit.emit:warn").expect("string fallback");
        assert_eq!(obl.kind, "audit.emit");
        assert_eq!(obl.args, Value::String("warn".into()));
    }

    #[test]
    fn parse_advice_strips_whitespace_around_kind_and_args() {
        let obl =
            parse_advice("  notify.operator  :  {\"who\":\"sec\"}  ").expect("whitespace-tolerant");
        assert_eq!(obl.kind, "notify.operator");
        assert_eq!(obl.args, json!({ "who": "sec" }));
    }

    #[test]
    fn parse_advice_rejects_empty_or_blank() {
        assert!(parse_advice("").is_none());
        assert!(parse_advice("   ").is_none());
        assert!(parse_advice(":foo").is_none()); // empty kind
    }

    #[test]
    fn permit_with_advice_emits_obligation_on_allow() {
        let plugin = build(
            &[r#"@advice("audit.emit:{\"level\":\"info\"}")
                permit(
                    principal == User::"alice",
                    action == Action::"read",
                    resource == Tool::"orders"
                );"#],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
        assert_eq!(dec.obligations.len(), 1);
        assert_eq!(dec.obligations[0].kind, "audit.emit");
        assert_eq!(dec.obligations[0].args, json!({ "level": "info" }));
        assert!(dec.redactions.is_empty());
    }

    #[test]
    fn permit_with_redact_emits_redaction_on_allow() {
        let plugin = build(
            &[r#"@redact("/result/credit_card")
                permit(
                    principal == User::"alice",
                    action == Action::"read",
                    resource == Tool::"orders"
                );"#],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
        assert_eq!(dec.redactions.len(), 1);
        assert_eq!(dec.redactions[0].json_pointer, "/result/credit_card");
        assert_eq!(dec.redactions[0].replacement, Value::String("***".into()));
    }

    #[test]
    fn matched_permits_stack_their_advice() {
        // Two matching permits, each carrying one obligation +
        // one redaction. The decision stacks both.
        let plugin = build(
            &[
                r#"@advice("audit.emit:{\"level\":\"info\"}")
                @redact("/result/email")
                permit(
                    principal == User::"alice",
                    action == Action::"read",
                    resource == Tool::"orders"
                );"#,
                r#"@advice("notify.operator:{\"channel\":\"sec-ops\"}")
                @redact("/result/ssn")
                permit(
                    principal,
                    action == Action::"read",
                    resource
                );"#,
            ],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
        assert_eq!(
            dec.obligations.len(),
            2,
            "both matched permits' @advice annotations should stack"
        );
        let kinds: std::collections::BTreeSet<_> =
            dec.obligations.iter().map(|o| o.kind.as_str()).collect();
        assert!(kinds.contains("audit.emit"));
        assert!(kinds.contains("notify.operator"));
        assert_eq!(dec.redactions.len(), 2);
        let pointers: std::collections::BTreeSet<_> = dec
            .redactions
            .iter()
            .map(|r| r.json_pointer.as_str())
            .collect();
        assert!(pointers.contains("/result/email"));
        assert!(pointers.contains("/result/ssn"));
    }

    #[test]
    fn forbid_with_advice_emits_obligation_on_deny() {
        // Forbids may carry @advice (e.g. a rejection-audit
        // obligation). Redactions do NOT apply on Deny — the
        // payload is blocked entirely.
        let plugin = build(
            &[
                r#"permit(principal, action, resource);"#,
                r#"@policy_id("forbid-write")
                @advice("audit.emit:{\"level\":\"warn\",\"event\":\"forbidden_write\"}")
                @redact("/result/secret")
                forbid(
                    principal,
                    action == Action::"write",
                    resource
                );"#,
            ],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "write",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Deny);
        assert_eq!(dec.obligations.len(), 1);
        assert_eq!(dec.obligations[0].kind, "audit.emit");
        assert_eq!(
            dec.obligations[0].args,
            json!({ "level": "warn", "event": "forbidden_write" })
        );
        assert!(
            dec.redactions.is_empty(),
            "@redact MUST NOT apply on Deny — payload is blocked"
        );
    }

    #[test]
    fn permits_without_annotations_emit_no_obligations_or_redactions() {
        // Annotation handling is additive — operators with
        // un-annotated policies see the same behaviour.
        let plugin = build(
            &[r#"permit(
                principal == User::"alice",
                action == Action::"read",
                resource == Tool::"orders"
            );"#],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
        assert!(dec.obligations.is_empty());
        assert!(dec.redactions.is_empty());
    }

    #[test]
    fn unknown_annotations_are_ignored() {
        // Annotations the plugin doesn't recognise (Cedar's
        // `@policy_id`, operator-defined keys) MUST NOT
        // contribute to obligations / redactions.
        let plugin = build(
            &[r#"@policy_id("readonly-orders")
                @description("anyone can read orders")
                @owner("sec-team")
                permit(
                    principal,
                    action == Action::"read",
                    resource == Tool::"orders"
                );"#],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("alice"),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
        assert!(dec.obligations.is_empty());
        assert!(dec.redactions.is_empty());
    }

    #[test]
    fn redact_only_extracts_when_decision_allow() {
        // Sanity: a permit with @redact + a forbid that wins
        // produces Deny with no redactions (forbid blocks
        // everything; redact wouldn't apply anyway).
        let plugin = build(
            &[
                r#"@redact("/result/private")
                permit(
                    principal,
                    action == Action::"read",
                    resource
                );"#,
                r#"forbid(
                    principal == User::"banned",
                    action,
                    resource
                );"#,
            ],
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "tool": "orders" }),
            &ctx("banned"),
        );
        assert_eq!(dec.effect, PolicyEffect::Deny);
        assert!(dec.redactions.is_empty());
    }
}
