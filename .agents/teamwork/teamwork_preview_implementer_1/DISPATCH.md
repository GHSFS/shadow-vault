# Dispatch for teamwork_preview_implementer_1

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault\.agents\teamwork\teamwork_preview_implementer_1
Project root: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault

<original_task>
This is a single self-contained fix; keep it small and focused.

Working directory: c:\Users\Administrator\Desktop\github_WORK\GHSFS_workspace\shadow-vault
Integrity mode: development

Requirements:
R1: Implement 24-bit uncompressed BMP pixel LSB steganography engine in src/bmp.rs with Apache-2.0 and GHSFS NOTICE headers. Support embedding and extracting encrypted SVLT containers with 12-byte envelope ([magic svLt: 4B][len: 4B LE][payload: NB][crc32: 4B LE]) and constant-time CRC-32 validation. Respect row padding by only modulating R/G/B pixel channel bytes.
R2: Provide capacity estimation in src/bmp.rs (get_bmp_capacity) and universal carrier capacity command `svault capacity <carrier>` (with `--json` support). Integrate `embed-bmp` and `extract-bmp` in src/cli.rs and src/main.rs, with `--clip` and `--clip-ttl` clipboard integration, and wire BMP detection into `inspect` and `audit`.
R3: Update Cargo.toml version to 0.8.0. Write unit tests in src/bmp.rs and integration tests in tests/integration.rs.
R4: Update README.md, CHANGELOG.md, TASK_BACKLOG.md (mark M08 completed and proactively add M45/M46).

Acceptance Criteria:
- All unit and integration tests pass with zero warnings in cargo fmt, cargo clippy, and cargo test.
- Zero AI attribution anywhere.
- Pure Rust, zero external image codec dependencies.
</original_task>
