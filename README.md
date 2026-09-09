# Crumbled

Local-first cookie behaviour discovery, explicit policy evaluation, and reviewed topology verification in Rust. Crumbled runs offline without executing repository code. The core is independent of Padagonia, Brandi, and web frameworks.

```bash
cargo build --workspace --locked
cargo run -p crumbled -- scan fixtures/browser --format json
cargo run -p crumbled -- audit fixtures/browser --format sarif
cargo run -p crumbled -- enforce fixtures/browser --dry-run --format json
```

`audit` in this example returns 1 because the fixtures contain unresolved behaviours. A policy decision of `block` describes the required permission boundary; it does not claim that application behaviour is already prevented.

## Commands

| Command | Current behaviour | Writes |
| --- | --- | --- |
| `scan [path]` | Token-aware lexical discovery, evidence, classification, and graph | None |
| `audit [path]` | Static scan plus unresolved policy violations | None |
| `explain ID_OR_NAME --root [path]` | All matching behaviours and their evidence chains | None |
| `enforce [path] [--dry-run]` | Abstract gate preview, explicitly marked uncompiled | None |
| `enforce [path] --apply` | Fails validation with exit 3: no execution-path compiler yet | None |
| `lock [path]` | Preview a reviewed topology lock | None |
| `lock [path] --approve` | Approve/update inventory and policy fingerprints | `crumbled.lock` only |
| `verify [path]` | Check lock integrity, topology drift, and unresolved policy boundaries | None |
| `observe [path]` | Explicit unsupported-analysis failure, exit 2 | None |

Every command supports `--format human|json|jsonl|sarif`, including structured errors. Use `--application NAME` consistently to distinguish applications. The default is `application`; root locations are excluded from identities so moving a checkout does not change its lock. `explain --why-blocked NAME` accepts an exact name, cookie ID, or behaviour ID and returns all matches. Unknown options fail instead of being ignored.

## Explicit policy

Cookie names, including `session_id`, `csrf`, and `_ga`, never grant permission automatically. Unmatched identities remain `unknown → block`. Add reviewed rules to `crumbled.policy.json` in the target root, or supply `--policy FILE` (relative to the invoking directory).

Copy the complete `finding.cookie` object from JSON output and provide a category and a nonempty review reason:

```json
{
  "schema_version": 1,
  "rules": [
    {
      "cookie": {
        "name": "session_id",
        "domain": "example.test",
        "path": "/",
        "origin": "repository:app.js",
        "application": "storefront",
        "attributes": {}
      },
      "category": "necessary",
      "reason": "Reviewed: required to maintain this application's authenticated session"
    }
  ]
}
```

The rule matches an exact identity, including attributes. `null` is an unresolved field, never a wildcard; unresolved names cannot be approved. Sources with unresolved runtime origins are scoped to their source module. Policy approval confirms the review decision, not runtime execution or detector certainty.

Default decisions are `necessary → allow`, `preferences/analytics/marketing → gate`, `unknown → block`. An optional `decisions` object must specify all five classes. Necessary behaviour may be restricted further; consent classes cannot become unconditional allow, and unknown must remain blocked. Duplicate identities, missing reasons, unknown fields, and unsupported versions are rejected.

For a runnable policy example:

```bash
cargo run -p crumbled -- scan fixtures/browser --policy policies/example.json --format json
```

## Inventory approval and CI

```bash
crumbled scan ./app --application storefront --format json
crumbled lock ./app --application storefront --format json
# After reviewing the inventory and policy:
crumbled lock ./app --application storefront --approve
crumbled verify ./app --application storefront --format sarif
```

Commit the policy and `crumbled.lock` through your normal review workflow. The lock includes complete identities, operations, purpose/permission decisions, and SHA-256 source and policy fingerprints. New, removed, changed, or moved behaviour requires review. Any change to a file containing a finding also triggers drift, including comments; this is intentionally conservative. Source timestamps are excluded from locks.

Lock writes are validated before a single-file atomic replacement. Repeating approval without changes preserves bytes and modification time. A checksum detects corruption, but the lock is not signed: repository review remains the approval trust boundary. Approval records the inventory; consent-required and blocked behaviour still fails verification because no compiler yet attests enforcement.

Exit codes: `0` successful command/static verification, `1` policy or topology violation, `2` analysis/argument failure, `3` lock-integrity or enforcement-validation failure. Missing lock returns 1; malformed or corrupt lock returns 3. A successful static verification means the reviewed topology matches and there are no unresolved policy violations **within the supported lexical scope**. It does not prove runtime consent enforcement or absence of undiscovered behaviour.

## Scope and evidence

Discovery recognises direct browser cookie access (including literal bracket properties), reads versus assignments, Cookie Store methods, selected server cookie functions, and explicit HTTP cookie header contexts. It supports multiple findings per line and whitespace/comments between API tokens. Cookie values and source lines are omitted from reports; source hashes, relative locations, rule methods, confidence, source modification timestamps, and review reasons remain available.

Findings have distinct `declared`, `observed`, and `correlated` flags. Static findings never claim runtime observation. All lexical findings are `possible`; no production source transformation is automatically generated from them. Graphs contain application, module, storage operation, cookie, domain, permission, and evidence nodes with resolvable edges. The graph is Crumbled's native schema; Padagonia compatibility is not yet claimed.

Scanning is sorted, read-only and bounded to 4 MiB per source, 100,000 entries, and 128 directory levels. Unsupported text encodings, oversized sources, symlinks, and special files produce analysis failures. Recognised source suffixes and excluded dependency/build directories are documented in [implementation status](docs/status.md). Repeated scans of unchanged content and source metadata are deterministic; source modification timestamps are provenance, not runtime observation times.

AST/data-flow analysis, aliases and wrappers, dependency/vendor intelligence, runtime browsers, production enforcement, signed locks, incremental caching, and ELCI adapters remain future work. This build does not install a banner or treat generated metadata as an enforcement gate.

## Development

```bash
cargo test --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
deliver --spec deliver.toml --strict
```

The six crates separate the domain model, discovery, policy, plans/locks, reporting, and CLI. Serde/serde_json provide validated structured interchange, and SHA-256 provides stable content/identity fingerprints. Dependency downloads are needed only if the build cache is empty; scanning has no network dependency.
# crumbled
