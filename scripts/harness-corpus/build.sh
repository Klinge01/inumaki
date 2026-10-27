#!/usr/bin/env bash
# Build crates/inumaki-eval/harness/harness-static.jsonl, the harness-static
# corpus: text an agent harness sends with every request (model instructions,
# permission fragments, tool descriptions, environment and git status blocks,
# turn metadata). Build time only (curl, python3); the result is committed.
#
# Sources:
#   OpenAI Codex, https://github.com/openai/codex, tag rust-v0.159.2
#   (commit pinned below), Apache-2.0, Copyright 2025 OpenAI: the prompt
#   templates and the model catalog's instruction strings. Attribution in NOTICE.
#   crates/inumaki-eval/harness/synthetic/*.txt: Claude Code-shaped texts written
#   for inumaki, part of inumaki (Apache-2.0). They paraphrase the structure and
#   the kind of content of a Claude Code system prompt, tool list, reminders,
#   and agent descriptions in inumaki's own words; nothing is copied from an
#   installed harness or its published prompts. They approximate Claude Code
#   text, so the re-test with the real harness remains the check.
#   A seeded generator in build.py: environment, git status, turn metadata.
#
# Refresh when a harness release changes its prompts: set CODEX_TAG and
# CODEX_COMMIT to the new release (`gh api repos/openai/codex/git/refs/tags/<tag>`,
# then the tag object's commit), update PATHS when files moved, re-run, then
# run the corpus gate (engine spec §11.4, the harness-static corpus; with
# `--origin harness-static`) and list what is left with
# scripts/harness-corpus/person-spans.sh.
CODEX_TAG=rust-v0.159.2
CODEX_COMMIT=ff6aec96948b70d94983af2641a6b67c94faeff5
PATHS=(
  codex-rs/models-manager/models.json
  codex-rs/models-manager/prompt.md
  codex-rs/core/templates/agents/orchestrator.md
  codex-rs/core/templates/collab/experimental_prompt.md
  codex-rs/core/templates/model_instructions/gpt-5.2-codex_instructions_template.md
  codex-rs/core/templates/personalities/gpt-5.2-codex_friendly.md
  codex-rs/core/templates/personalities/gpt-5.2-codex_pragmatic.md
  codex-rs/core/templates/review/history_message_completed.md
  codex-rs/core/templates/review/history_message_interrupted.md
  codex-rs/core/templates/search_tool/request_plugin_install_description.md
  codex-rs/core/templates/search_tool/tool_description.md
  codex-rs/prompts/templates/compact/prompt.md
  codex-rs/prompts/templates/compact/summary_prefix.md
  codex-rs/prompts/templates/guardian/classifier_instructions.md
  codex-rs/prompts/templates/guardian/node_repl_policy.md
  codex-rs/prompts/templates/guardian/policy.md
  codex-rs/prompts/templates/guardian/policy_template.md
  codex-rs/prompts/templates/permissions/approval_policy/never.md
  codex-rs/prompts/templates/permissions/approval_policy/on_request.md
  codex-rs/prompts/templates/permissions/approval_policy/on_request_rule_request_permission.md
  codex-rs/prompts/templates/permissions/approval_policy/unless_trusted.md
  codex-rs/prompts/templates/permissions/sandbox_mode/danger_full_access.md
  codex-rs/prompts/templates/permissions/sandbox_mode/read_only.md
  codex-rs/prompts/templates/permissions/sandbox_mode/workspace_write.md
  codex-rs/prompts/templates/persistent_mode.md
  codex-rs/prompts/templates/realtime/backend_prompt.md
  codex-rs/prompts/templates/realtime/realtime_end.md
  codex-rs/prompts/templates/realtime/realtime_start.md
  codex-rs/prompts/templates/review/exit_interrupted.xml
  codex-rs/prompts/templates/review/exit_success.xml
  codex-rs/prompts/templates/review/rubric.md
)
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=scripts/harness-corpus
OUT=crates/inumaki-eval/harness/harness-static.jsonl
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for p in "${PATHS[@]}"; do
  mkdir -p "$TMP/$(dirname "$p")"
  curl -fsSL "https://raw.githubusercontent.com/openai/codex/$CODEX_COMMIT/$p" -o "$TMP/$p"
done
python3 "$HERE/build.py" "$TMP" crates/inumaki-eval/harness/synthetic "$OUT" "$CODEX_TAG" "$CODEX_COMMIT"
