# inumaki

**Keep identity local. Send semantics to the AI. Verify before anything leaves.**

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Status: pre-1.0, experimental](https://img.shields.io/badge/status-pre--1.0%2C%20experimental-orange)
![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-informational)
![Tested on macOS](https://img.shields.io/badge/tested%20on-macOS%20(Apple%20Silicon)-lightgrey)

inumaki is a local privacy boundary between your AI agents and cloud LLM providers. It finds identifying information in text (names, addresses, account numbers, customer IDs, secrets), replaces it with opaque tokens, has an independent second pass check the result, sends that to the model, and puts the real values back into the answer on your machine.

```text
"Hi, I'm Sarah Leitner, contract 8439271, moved to Neubaugasse 22. LG Sarah"
        │  inumaki (local, CPU only)
        ▼
"Hi, I'm <PERSON_a7f2>, contract <CONTRACT_ID_b41c>, moved to <STREET_ADDRESS_84d1>. LG <PERSON_a7f2_3e>"
        │  cloud LLM
        ▼
"Hello <PERSON_a7f2_3e>, we updated <CONTRACT_ID_b41c> to <STREET_ADDRESS_84d1>."
        │  inumaki restores the values locally
        ▼
"Hello Sarah, we updated 8439271 to Neubaugasse 22."
```

The model still understands the request: it knows a person moved and a contract changed. The provider sees tokens in place of the identifiers inumaki detected. **What the detectors miss is sent as is.** inumaki reduces what a provider sees; it does not make text anonymous. The [threat model](docs/threat-model.md) says exactly where the boundary is.

> **inumaki is a classifier, and it makes mistakes.** Its detectors are pattern rules and small statistical models. For every piece of text they decide whether something looks like a name, an address, or an account number, and they get it wrong in both directions: they miss identifiers, which are then sent to the provider, and they take ordinary words for names, which costs an unneeded token or a refused request. Treat it as a layer that lowers what a provider sees, not as a guarantee, and do not rely on it alone for data you cannot afford to leak.

## Why

Coding agents and assistants like Claude Code and Codex now read your mail, your documents, and your tool output, and send all of it to a cloud model. For anyone who works with customer data, that is the problem: the agent needs the meaning of the text, not the identity of the people in it.

The private alternative is to run the model yourself, and that takes inference hardware many people and small businesses cannot pay for. inumaki is a passion project for them: keep using the cloud models you can afford, on the machine you already have, and send less of the people in your data along with every request.

inumaki sits in that path. Its design goals:

- **Recall first.** A missed identifier crosses the boundary; a false positive costs a retry. When they conflict, recall wins.
- **The sanitizer never checks itself.** A separate verifier re-scans every candidate before it leaves.
- **Fast enough to sit inline.** It runs inside agent loops, so latency is a requirement: single-digit milliseconds for the deterministic detectors, tens of milliseconds warm end to end.
- **Ordinary hardware.** CPU only, on a laptop, mini PC, NAS, or small VM. No GPU, no Python at runtime.
- **Tokens, not redaction.** `<PERSON_a7f2>` is random, per context, and shows its category; the same person keeps the same token, so the model can still reason about who did what.
- **Nothing sensitive in logs.** Original text and token mappings never reach logs, errors, metrics, or crash reports.

German and English business text and Austrian and DACH identifiers come first.

## How it works

```text
text from your agent
  ├── deterministic recognizers   regex + checksums: email, phone, IBAN, cards, IPs, national IDs
  ├── NER                          small multilingual ONNX models, names and addresses
  ├── position detectors           names in paths, URLs, home folders, file names
  ├── domain rules + dictionaries  your customer-ID formats and known names
  └── secret scanner               API keys, JWTs, connection strings (removed, never restored)
        ↓
policy (per profile)               tokenize, keep, or refuse
        ↓
token vault                        encrypted, per dataset, rotating
        ↓
verifier                           independent second pass: leak check, regex and name re-scan
        ↓
cloud LLM  →  answer  →  values restored locally
```

It all runs in `inumakid`, one local service with the models loaded once. Around it:

| Component | What it does |
|---|---|
| **MCP gateway** | Wraps your MCP servers: results come back sanitized, and tool arguments are restored before they reach the real server. |
| **Folder mirror** | Keeps a sanitized copy of a folder for agents to read, and restores what they write into its outbox. |
| **Model-API proxy** | A local endpoint for Anthropic Messages, OpenAI Responses and Chat Completions, streaming included: an agent's chat goes through sanitization and the answer comes back restored. |
| **Mailbox datasets** | An IMAP mailbox as a dataset with list, search, read, and draft-reply tools. inumaki never sends mail. |
| **Tool-result hook** | For Claude Code and Codex, sanitizes tool output that touches a connected folder or a known value. |
| **Desktop app** | macOS app (Tauri) that installs the service, downloads the models, and connects your agents with one click and a clean Revert. |

[docs/architecture.md](docs/architecture.md) has the details.

## Status

**Pre-1.0 and experimental. A passion project, not a product, and not a compliance tool.** It works end to end on the maintainer's machine and is about to get its first full hands-on test round. Expect rough edges and breaking changes.

- **Platforms:** tested on macOS (Apple Silicon). Linux builds and a `.deb` exist but have not been verified on a real install. Windows is not supported yet.
- **Agents:** Claude Code and Codex are measured end to end; Hermes Agent and OpenClaw adapters were built from their published source and have not been run.
- **Quality:** measured on synthetic corpora only, so the numbers are no claim about your data. With the default `support-email` profile on 2 106 tuning documents, 0.53% of the documents that passed the checks still held a labelled identifier, and PERSON recall was 93.7%. On 200 held-out documents from a second generator it was 0% and 85.6%. **No profile meets the project's own targets yet** (PERSON recall 95%), and `inumaki status` reports every profile as `unqualified`. Reports and method: [docs/quality/](docs/quality/).
- **MVP:** the exit criteria and what has been verified are in [docs/mvp-checklist.md](docs/mvp-checklist.md).

## Known limits

The full list is in the [threat model](docs/threat-model.md) and the [MVP checklist](docs/mvp-checklist.md). The ones to know first:

- **It protects only the traffic that goes through it.** An agent that deliberately goes around inumaki can succeed, and so can another process running as your user. Re-identification from context alone is out of scope.
- **Detection misses are sent.** The verifier is a second deterministic pass, not a proof.
- **Attachments are not read.** By default they are replaced by a placeholder; there is no OCR.
- **Chat through the proxy is new.** Since 2026-10-20 the proxy reads an agent's own system prompt as harness text, so it no longer refuses those requests on the recorded harness prompts. Real Claude Code and Codex runs under the default profile are the next test round. Codex with a ChatGPT login is unverified.
- **Ad hoc signing.** The macOS app is not Developer-ID signed: every upgrade asks for folder access and Keychain approval again.

## Quick start

**Build from source** (Rust 1.85 or newer):

```bash
cargo build --release -p inumaki-cli -p inumakid -p inumaki-mcp -p inumaki-hook
alias inumaki=target/release/inumaki
inumaki models pull                    # once, about 370 MB from Hugging Face
inumaki daemon &
inumaki dataset add demo --name Demo   # default profile support-email
echo "Sarah Leitner, Neubaugasse 22, IBAN AT61 1904 3002 3457 3201" \
  | inumaki sanitize --dataset demo - | tee /tmp/out.txt
# <PERSON_566c8a>, <STREET_ADDRESS_40c49d>, IBAN <IBAN_bf4b3a>
inumaki rehydrate --strict --dataset demo /tmp/out.txt
```

No models? `inumaki dataset add demo --name Demo --profile offline` uses only the deterministic detectors (much lower name recall), and `inumaki tokenize FILE` works without a daemon.

**The macOS app:** download the `.dmg` from [Releases](https://github.com/Klinge01/inumaki/releases) (Apple Silicon), or build it with `scripts/package-app.sh`, which writes `dist/Inumaki-<version>.dmg`. Open it (right-click → Open the first time), then "Install and start", "Download models", and Connect on each detected agent. "Run the check" sends a synthetic canary through every path and shows whether it left only as tokens.

**Homebrew and Debian packages** are built by `scripts/package.sh` and `scripts/package-deb.sh`; see [docs/packaging.md](docs/packaging.md).

**Connect an agent:** `inumaki connect status`, then `inumaki connect apply HARNESS --no-chat` (undo with `inumaki connect revert HARNESS`), or Connect in the app, where chat is a separate switch.

| Agent | Guide |
|---|---|
| Claude Code | [docs/harness/claude-code.md](docs/harness/claude-code.md) |
| Codex | [docs/harness/codex.md](docs/harness/codex.md) |
| Hermes Agent | [docs/harness/hermes.md](docs/harness/hermes.md) |
| OpenClaw | [docs/harness/openclaw.md](docs/harness/openclaw.md) |

All commands: [docs/cli.md](docs/cli.md). Every setting: [docs/configuration.md](docs/configuration.md). Keys, backup, and service management: [docs/runbook.md](docs/runbook.md).

## Contributing

inumaki is early, and that is the best time to shape it. Issues, ideas, bug reports, and pull requests are all welcome, and you don't need to be a privacy expert to help. That includes new functionality: improvements to what is there, and new integrations such as adapters for other agents and harnesses, MCP servers worth wrapping, and more model and mail providers. Some places where help would make a real difference:

- **Try it and tell us what broke.** Install it, connect your agent, and open an issue with what happened. Reports from Linux machines are especially valuable, because nobody has run it there yet.
- **Identifiers from your country.** Swiss, German, and other European ID numbers, tax numbers, license plates, and address formats. A recognizer with a checksum and a few synthetic test cases is a self-contained first contribution.
- **Synthetic test cases.** Every eval case is invented data. If you find a shape inumaki misses (a name in a CSV column, a typo'd label, an unusual address), a test case that shows it is as useful as the fix.
- **More integrations.** Adapters for other agents and harnesses, MCP servers and model APIs beyond the ones covered, and mail providers beyond the verified ones (Gmail and Microsoft 365 are open).
- **Platform work.** Linux verification, Windows support, signing and packaging.
- **Precision and speed.** Fewer false positives in code and technical text, and faster cold starts, without giving up recall.
- **Docs.** If something here confused you, it will confuse the next person too.

Start with [CONTRIBUTING.md](CONTRIBUTING.md): how to build, the test gate, and the privacy rules every change follows (synthetic data only, nothing sensitive in logs or errors, fail closed). For a larger change, such as a new detector or a new adapter, open an issue first so we can agree on the approach.

**Found a leak or a vulnerability? Please report it privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.**

## Documentation

| | |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Crates, pipeline, vault, gateway, mirror, proxy |
| [docs/threat-model.md](docs/threat-model.md) | What is and is not protected |
| [docs/cli.md](docs/cli.md) | Commands, profiles, exit codes, eval and bench |
| [docs/configuration.md](docs/configuration.md) | Every setting and its default |
| [docs/harness/](docs/harness/) | Per-agent connection guides |
| [docs/packaging.md](docs/packaging.md) | The app, Homebrew, and Debian packages |
| [docs/runbook.md](docs/runbook.md) | Key custody, backup and restore, service management |
| [docs/quality/](docs/quality/) | Measured, experimental quality reports |
| [docs/mvp-checklist.md](docs/mvp-checklist.md) | MVP exit criteria and known limits |
| [docs/mail-providers.md](docs/mail-providers.md) | Mail provider notes |
| [apps/inumaki-app/README.md](apps/inumaki-app/README.md) | The desktop app |
| [local_privacy_proxy_design.md](local_privacy_proxy_design.md) | The original concept and rationale |

## License

Apache-2.0, see [LICENSE](LICENSE). [NOTICE](NOTICE) lists third-party material. The models are not distributed with inumaki: `inumaki models pull` downloads `knowledgator/gliner-x-small` (Apache-2.0) and an ONNX export of `Davlan/bert-base-multilingual-cased-ner-hrl` (AFL-3.0) from Hugging Face under their own licences. The built-in first-name list derives from Statistik Austria (CC BY 4.0) and Berlin open data (CC BY 3.0 DE).
