# Implementer Briefing — Milestone M10

## Task Overview
Milestone M10: Directory & Multi-File Manifest Packing (`src/archive.rs`).
- R1: Implement `src/archive.rs` with SVAR binary format, relative path canonicalization, path traversal prevention, zip bomb defense, SHA-256 per-file digests, permissions, and zeroize.
- R2: Wire CLI subcommands `pack-dir` and `unpack-dir` in `src/cli.rs` and `src/main.rs`, supporting `--list`, `--verify-only`, `--overwrite`, `--json`, `--dpapi`, and stego/armor transparent carriers.
- R3: Add unit tests in `src/archive.rs` and integration tests in `tests/integration.rs`.
- R4: Update Cargo.toml (v0.10.0), README.md, CHANGELOG.md, ROADMAP.md, and TASK_BACKLOG.md.

## Engineering Guidelines & Invariants
- Zero AI attribution anywhere.
- Production-grade Rust with strict error handling, no unwraps in core code, bounds checks, and zeroize memory hardening.
- 100% pass on `node scripts/check.mjs`.
