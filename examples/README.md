# Historical examples

This crate is explicitly excluded from the workspace. It preserves experiments
against older rpkt and smoltcp APIs and is not supported by current releases.
Use `rpkt-dpdk/examples` for maintained examples checked in CI. Do not use this
crate as a dependency/version template for a new application.

Workspace release builds use Cargo defaults. Use `--profile performance` for
opt-in fat LTO and one codegen unit; benchmark builds use the same settings.
These profiles apply to the entire workspace so the setting is never silently
ignored in a member manifest.
