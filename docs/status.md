<p align="center">
  <img src="crumbled-logo.jpeg" alt="Crumbled logo" width="900">
</p>

# Implementation status

This increment supplies the static graph, explicit policy, inventory approval, and CI integrity foundation of the enterprise directive. It does not fulfil the complete runtime/enforcement product contract yet.

## Implemented boundaries

- Sorted, non-executing lexical discovery; direct document.cookie and literal bracket access, Cookie Store get/getAll/set/delete, selected server function calls, and exact HTTP cookie header argument contexts.
- Independent cookie/behaviour identities. Cookie identities cover name, domain, path, source-scoped origin, application, and attributes. Unknown names are additionally scoped by source offset. Behaviour identities include module, byte offset, API and cookie identity.
- Technical mechanism is separate from evidence-backed policy classification. No name heuristic grants necessary status. Explicit reviewed policy rules match full identities.
- Native graph with canonical entity IDs and source/policy evidence. Static-only declared/observed/correlated flags accurately reflect the available evidence.
- Human, JSON, JSONL and SARIF reports, including analysis failures. JSONL emits start, findings, diagnostics and a final report. SARIF includes source locations and the complete report in run properties.
- Abstract permission gates with blocked defaults. Compilation explicitly reports unsupported execution paths. Applying enforcement fails before any repository mutation.
- Reviewed topology locks, checksum validation, atomic replacement, no-op/idempotent approval, and CI drift diagnostics. A baseline does not assert gate coverage.

## Scanner scope

Supported extensions: js, jsx, ts, tsx, mjs, cjs, rs, py, php, go, java, conf, yaml, yml, toml, html, vue, svelte, astro. HTML and component files use the lexical layer, not a full HTML parser. Source values are never copied into evidence.

Excluded directory names: .git, .agents, .codex, target, node_modules, .crumbled, .amber, .next, dist, build, .venv, vendor. crumbled.lock is reserved for integrity validation, not source analysis. Other file extensions are not analysed. There is no gitignore interpretation, dependency traversal, environment-file enrichment, AST, alias tracking, reachability proof, or framework semantics yet.

The tokenizer ignores ordinary comments and quoted prose, distinguishes assignments from equality comparisons, and treats concatenated/interpolated/escaped names as unresolved. It is not a full language parser: regular-expression literals, embedded template expressions, language-specific quoting, object-form cookie options and server framework semantics are not fully understood. Conservative lexical findings can be false positives; dynamically generated access can be missed. There is no claim of language-complete detection.

Symlinks in traversed source are rejected rather than followed. Budgets fail the analysis instead of silently returning a clean partial inventory. Filesystem scanning assumes the repository is stable during a command; it is not a hardened sandbox against another process changing filesystem entries concurrently. Scans never launch builds, hooks, package managers, repository scripts, or network clients.

## Output and migration notes

Structured output now uses schema_version 1 and nested assessments, graph, diagnostics, exit_code, and artifact fields. This replaces the initial prototype's flat summary JSON. The initial prototype's name-based classification and inventory-only enforcement file generation have been removed.

Bare enforce is now a preview. --apply is explicit mutation authority but cannot pass validation until a complete execution-path adapter exists. The previous .crumbled/enforcement.json inventory does not count as enforcement. --strict is accepted for enforce/verify; unknown always blocks in this build.

Evidence timestamps are source file modification seconds since Unix epoch (null if unavailable), not scan execution times. They are excluded from topology digests. Locks include source content hashes, so source edits can require approval even when the cookie name is unchanged. Checksums are not signatures or protection against an attacker authorised to change both source and approved locks.

## Next layers

1. AST and data-flow adapters, canonical source scope, and a larger framework fixture corpus.
2. Bounded browser observation and correlation of cookie identity with actual origins and execution paths.
3. A narrowly supported execution-path compiler with refusal for every uncontrolled path, generated-artifact hashes, and browser-backed non-bypass tests.
4. Padagonia and Brandi adapters validated against their actual integration contracts; Vamos events and the remaining ELCI integrations follow those boundaries.
5. Incremental/parallel scanning, signed knowledge and lock approval, framework/browser/fuzz/property test expansion.

The critical enforcement invariant remains a release gate for any future compiler. This version refuses to apply enforcement rather than claiming that an abstract permission plan controls behaviour.
