# AGENTS.md

Windows-only ETW recorder and reporter in Rust. Workspace: `crates/etw` (safe wrappers over Win32 ETW) and `crates/etwtrace` (the CLI).

## Rules

- All `unsafe` lives in `crates/etw`. Every other crate forbids it.
- No `unwrap`, `expect`, `panic!`, indexing, unchecked arithmetic, `todo!`, `unimplemented!` or `unreachable!` in production code (clippy denies them). Tests may.
- In `etw`: one unsafe operation per block, each with a `// SAFETY:` comment.
- Return `Result`; surface errors with `AppError`. Never swallow them.
- Few dependencies. `windows-sys` only; don't add more without a strong reason.
- Comments explain why, not what. Keep them short.
- Keep changes small and surgical. No drive-by refactors.
- Rustfmt max width is 240; don't reflow.

## Check before finishing

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

`record` and `probe` need an elevated prompt. Parity tests in `parity_tests.rs` are `#[ignore]`d and need `ETWTRACE_TEST_INPUT` / `ETWTRACE_TEST_OUTPUT`.
