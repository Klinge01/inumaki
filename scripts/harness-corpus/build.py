#!/usr/bin/env python3
"""Assemble crates/inumaki-eval/harness/harness-static.jsonl.

Build time only (see build.sh). Inputs: the Codex files fetched by build.sh
into argv[1] (a directory mirroring the repository paths), the hand-written
synthetic files in argv[2], and a seeded generator for environment blocks,
git status blocks, and turn metadata. Output argv[3]: one JSON object per
line, {"id","lang","text","spans","why"}, sorted by id, NFC, no gold
spans (the corpus holds no identifying value; every PERSON span in it is a
false positive).
"""
import json
import os
import random
import re
import sys
import unicodedata

SRC, SYNTHETIC, OUT, TAG, COMMIT = sys.argv[1:6]
SEED = 20261012
MIN_MODEL_STRING = 80

# Template variables in the Codex files and their substitutes. A variable
# not listed here stops the build: decide its value, add it, re-run.
# `user_first_name` is removed: the corpus is negative-only, and a real
# first name there would be a correct PERSON span.
VARS = {
    "network_access": "restricted",
    "personality": "",
    "approval_request_channel": "the request_permissions tool",
    "extra_policy": "",
    "tenant_policy_config": "",
    "user_first_name": "",
    "app_descriptions": "",
    "discoverable_tools": "",
    "results": "",
    "connector_id": "github",
}
VAR = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")


def substitute(text, where):
    def repl(m):
        name = m.group(1)
        if name not in VARS:
            sys.exit(f"unknown template variable {name!r} in {where}; add it to VARS")
        return VARS[name]
    if "{%" in text:
        sys.exit(f"template control block in {where}; extend build.py")
    return VAR.sub(repl, text)


docs = {}
texts = set()
codex_why = (f"OpenAI Codex {TAG} ({COMMIT}), Apache-2.0, Copyright 2025 OpenAI; "
             "template variables substituted")


def add(doc_id, text, why):
    text = unicodedata.normalize("NFC", text).strip("\n") + "\n"
    if text.strip() and doc_id not in docs and text not in texts:
        texts.add(text)
        docs[doc_id] = {"id": doc_id, "lang": "en", "text": text, "spans": [], "why": why}


# 1. Codex templates, one document per file.
for root, dirs, files in os.walk(SRC):
    dirs.sort()
    for f in sorted(files):
        path = os.path.join(root, f)
        rel = os.path.relpath(path, SRC)
        if rel.endswith("models.json"):
            continue
        with open(path, encoding="utf-8") as fh:
            add("codex/" + rel, substitute(fh.read(), rel), codex_why)

# 2. Every distinct string of at least MIN_MODEL_STRING characters under
#    model_messages in models.json (instructions, persistent instructions,
#    policies, mode texts), from the first model that carries it.
with open(os.path.join(SRC, "codex-rs/models-manager/models.json"), encoding="utf-8") as fh:
    catalog = json.load(fh)


def walk(value, path):
    if isinstance(value, str):
        if len(value) >= MIN_MODEL_STRING:
            yield path, value
    elif isinstance(value, dict):
        for k in value:
            yield from walk(value[k], f"{path}/{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}/{i}")


for model in catalog["models"]:
    for path, text in walk(model.get("model_messages"), f"codex/models.json/{model['slug']}"):
        add(path, substitute(text, path), codex_why)

# 3. Hand-written Claude Code-shaped texts (synthetic, written for this corpus).
for f in sorted(os.listdir(SYNTHETIC)):
    with open(os.path.join(SYNTHETIC, f), encoding="utf-8") as fh:
        add("synthetic/" + f, fh.read(), "synthetic, written for inumaki; Apache-2.0")

# 4. Generated environment, git status, and turn-metadata blocks: random temp
#    suffixes, plausible project paths with non-personal logins, commit
#    hashes, UUIDs, millisecond timestamps, model ids.
rng = random.Random(SEED)
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
LOWER_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
HEX = "0123456789abcdef"
LOGINS = ["deploy", "build", "runner", "ci", "admin", "ubuntu", "work", "office"]
PROJECTS = ["acme-webshop", "inventory-service", "billing-api", "docs-site", "data-pipeline",
            "mobile-app", "infra-terraform", "ml-experiments", "payments-gateway", "cli-tools"]
SLUGS = ["checkout-retry", "cache-headers", "login-timeout", "csv-export", "dark-mode",
         "rate-limit", "upgrade-deps", "flaky-test", "pdf-render", "search-index"]
FILES = ["src/main.rs", "src/lib.rs", "src/server/handlers.ts", "src/web/App.tsx", "README.md",
         "package.json", "Cargo.toml", "tests/api.test.ts", "docs/setup.md", ".github/workflows/ci.yml",
         "src/checkout/payment.ts", "migrations/0042_add_index.sql", "pyproject.toml", "src/utils/date.py"]
SUBJECTS = ["fix(api): retry once on a 503", "feat(cart): keep the cart in localStorage",
            "chore: bump vite to 7.1.2", "refactor: move the fetch wrapper to src/lib/http.ts",
            "test: cover the empty search result", "docs: explain the release steps",
            "fix(ui): keep focus after closing the dialog", "perf: cache the parsed config",
            "ci: run the linter on pull requests", "build: pin the toolchain to 1.92"]
MODELS = [m["slug"] for m in catalog["models"]] + ["claude-opus-5-5-20261001", "claude-sonnet-5-20260815"]


def r(chars, n):
    return "".join(rng.choice(chars) for _ in range(n))


def uuid7():
    h = r(HEX, 32)
    return f"{h[:8]}-{h[8:12]}-7{h[13:16]}-{rng.choice('89ab')}{h[17:20]}-{h[20:]}"


for i in range(30):
    login, proj, slug = rng.choice(LOGINS), rng.choice(PROJECTS), rng.choice(SLUGS)
    home = rng.choice([f"/Users/{login}", f"/home/{login}"])
    cwd = f"{home}/{rng.choice(['projects', 'code', 'src', 'work'])}/{proj}"
    tmp = rng.choice([
        f"/private/tmp/claude-{rng.randint(500, 520)}/{cwd.replace('/', '-')}/{uuid7()}",
        f"/var/folders/{r(LOWER_ALNUM, 2)}/{r(LOWER_ALNUM, 22)}/T/codex-{r(ALNUM, 8)}",
        f"/tmp/scratch-{r(LOWER_ALNUM, 8)}",
    ])
    day = f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
    branch = rng.choice([f"feature/{slug}", f"fix/{slug}", "main", f"release/2026.{rng.randint(1, 12)}"])
    status = "\n".join(f"{rng.choice([' M', '??', ' D', 'A '])} {rng.choice(FILES)}"
                       for _ in range(rng.randint(1, 5)))
    commits = "\n".join(f"{r(HEX, 7)} {rng.choice(SUBJECTS)}" for _ in range(5))
    model = rng.choice(MODELS)
    if i % 2 == 0:
        text = (f"<env>\nWorking directory: {cwd}\nIs directory a git repo: Yes\n"
                f"Additional working directories: {tmp}\nPlatform: {rng.choice(['darwin', 'linux'])}\n"
                f"OS Version: {rng.choice(['Darwin 25.0.0', 'Darwin 26.1.0', 'Linux 6.8.0-49-generic'])}\n"
                f"Shell: {rng.choice(['zsh', 'bash', 'fish'])}\nToday's date: {day}\n</env>\n"
                f"You are powered by the model {model}.\n\n"
                f"gitStatus: This is the git status at the start of the conversation.\n"
                f"Current branch: {branch}\nMain branch (you will usually use this for PRs): main\n"
                f"Status:\n{status}\n\nRecent commits:\n{commits}\n")
    else:
        text = (f"<environment_context>\n  <cwd>{cwd}</cwd>\n"
                f"  <approval_policy>{rng.choice(['on-request', 'never', 'untrusted'])}</approval_policy>\n"
                f"  <sandbox_mode>{rng.choice(['read-only', 'workspace-write', 'danger-full-access'])}</sandbox_mode>\n"
                f"  <network_access>{rng.choice(['restricted', 'enabled'])}</network_access>\n"
                f"  <writable_roots>\n    <root>{tmp}</root>\n  </writable_roots>\n"
                f"  <shell>{rng.choice(['zsh', 'bash'])}</shell>\n  <current_date>{day}</current_date>\n"
                f"</environment_context>\n")
    add(f"generated/env-{i:02d}", text, f"generated by scripts/harness-corpus/build.py, seed {SEED}")

for i in range(10):
    meta = {
        "turn_id": uuid7(), "session_id": uuid7(), "agent_name": "default",
        "sandbox": rng.choice(["seatbelt", "landlock", "none"]),
        "sandbox_mode": rng.choice(["read-only", "workspace-write"]),
        "model": rng.choice(MODELS), "node_repl_auto_review_required": rng.choice([True, False]),
        "node_repl_disabled": rng.choice([True, False]),
        "started_at_ms": rng.randint(1_760_000_000_000, 1_790_000_000_000), "git_head": r(HEX, 40),
    }
    body = {"client_metadata": {"x-codex-turn-metadata": json.dumps(meta, separators=(",", ":"))},
            "metadata": {"user_id": f"user_{r(HEX, 16)}_account_{uuid7()}_session_{uuid7()}"}}
    add(f"generated/turn-metadata-{i:02d}", json.dumps(body, separators=(",", ":")),
        f"generated by scripts/harness-corpus/build.py, seed {SEED}")

with open(OUT, "w", encoding="utf-8") as out:
    for doc_id in sorted(docs):
        out.write(json.dumps(docs[doc_id], ensure_ascii=False, separators=(",", ":")) + "\n")
print(f"{len(docs)} documents written to {OUT}", file=sys.stderr)
