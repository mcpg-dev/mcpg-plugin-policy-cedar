# Cedar Policy Engine — `dev.mcpg.policy.cedar`

> class `policy_engine` · `native` · package `mcpg-plugin-policy-cedar` · artifact `libmcpg_plugin_policy_cedar.so`

Embedded AWS Cedar authorization engine. Operators supply a directory
of `.cedar` policy files; the plugin builds a Cedar `PolicySet` at boot and
evaluates per-request envelopes sub-millisecond in-process — no external policy
server. Reach for it for typed `principal × action × resource` authz with
`permit` / `forbid` policies and `when` / `unless` conditions (~3MB cdylib).

## What it does
- Loads + aggregates every `.cedar` file under `policy_dir` at boot.
  `policy_version()` is the SHA-256 over policy + schema + entities bytes.
- Translates the MCPG `(decision_point, input, context)` envelope into Cedar's
  typed `Request`: principal `principal_type::"<subject_id|anonymous_id>"`,
  action `action_namespace::"<decision_point>"`, resource per the matching
  `resource_types` entry (with `*` catch-all and an `input` JSON-pointer for the
  resource id).
- Decision mapping: matching `permit` (no `forbid`) → `Allow`; matching `forbid`
  → `Deny` (reason `cedar forbid: <ids>`); default-deny → `NotApplicable`
  (default) or `Deny` per `evaluation.on_default_deny`.
- Optional schema validation (`schema_path`), static entities store
  (`entities_path`), `input`-as-Context translation, and bundle hot-reload.
- Cedar `@advice` / `@redact` annotations on matched policies surface as
  obligations / redactions on the `PolicyDecision`.
- Pure offline; no required capabilities.

## Configuration
Selected via the gateway's policy-engine binding and loaded via the top-level
`plugins:` list:

```yaml
plugins:
  - id: dev.mcpg.policy.cedar
    class: policy_engine
    source: { path: ./plugins/libmcpg_plugin_policy_cedar.so }
    config:
      policy_dir: /etc/mcpg/cedar/policies     # required; .cedar files
      schema_path: /etc/mcpg/cedar/schema.cedarschema     # optional
      entities_path: /etc/mcpg/cedar/entities.json        # optional
      translation:
        principal_type: User
        action_namespace: Action
        anonymous_principal_id: anonymous
        resource_types:
          - { decision_point: "tool.call.pre", resource_type: Tool, resource_id_path: "/tool" }
          - { decision_point: "*", resource_type: Resource, resource_id_path: "/id" }
      evaluation:
        on_default_deny: not_applicable        # "not_applicable" | "deny"
        # include_input_as_context is a top-level config field (see table)
      include_input_as_context: false
      reload:
        enabled: true
        check_interval_sec: 60
```

| Field | Type | Default | Description |
|---|---|---|---|
| `policy_dir` | string | — | Directory of `.cedar` files (walked recursively). Required. |
| `schema_path` | string? | `null` | Cedar schema (`.cedarschema` or `.cedarschema.json`); type-checks policies. |
| `entities_path` | string? | `null` | Cedar entities JSON (principals/groups/resources + attrs). |
| `include_input_as_context` | bool | `false` | Map request `input` JSON to Cedar's `Context`. |
| `translation.principal_type` | string | — | Cedar entity type for the principal. |
| `translation.action_namespace` | string | — | Cedar action namespace. |
| `translation.resource_types` | type[] | — | Per-decision-point `{ decision_point, resource_type, resource_id_path }`; non-empty, `*` catch-all allowed. |
| `translation.anonymous_principal_id` | string | `"anonymous"` | Principal id when `subject_id` is absent. |
| `evaluation.on_default_deny` | enum | `not_applicable` | `not_applicable` (compose) or `deny` (strict). |
| `reload.enabled` | bool | `false` | Poll `policy_dir` and hot-swap the PolicySet. |
| `reload.check_interval_sec` | u64 | `60` | Poll interval (must be > 0 when reload enabled). |

Schema + entities are part of the reload bundle. Unknown config fields are
rejected at parse time.

### Obligations + redactions
`@advice("kind[:json_args]")` on a matched policy yields an `Obligation`;
`@redact("/json/pointer")` yields a `Redaction` (replacement `"***"`). Matched
`permit`s contribute on `Allow`; matched `forbid`s contribute `@advice` on
`Deny`. Un-annotated policies emit nothing.

## Build
```bash
cargo build -p mcpg-plugin-policy-cedar --features cdylib-export --release   # → target/release/libmcpg_plugin_policy_cedar.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
