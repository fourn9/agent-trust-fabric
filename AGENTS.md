# AGENTS.md

Cross-tool agent instruction file (Codex / Cursor / Claude Code / etc.).
For Claude Code specific instructions, see [`CLAUDE.md`](./CLAUDE.md).

## Project context

`agent-trust-fabric` is an OSS protocol + reference implementation. The
specification is the source of truth; the code follows. See
[`docs/specs/2026-05-23-atf-design.md`](./docs/specs/2026-05-23-atf-design.md).

## Decision criteria

Always honor [`decisions/0001-design-criteria.md`](./decisions/0001-design-criteria.md)
when making trade-offs. Cite the relevant criterion number when explaining
a decision.

## Stop conditions

Stop and ask the human before:
- Making a git commit or push
- Adding a dependency to the reference implementation
- Changing a layer's wire format after v0.1
- Modifying ADR-0001 (decision criteria)

## Style

- Specs are written in plain Markdown.
- Code follows the language's standard style (Black / Ruff for Python).
- Tests precede implementation for protocol logic.
- Every cross-layer change requires updating both `docs/specs/` and `spec/`.
