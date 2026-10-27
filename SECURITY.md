# Security policy

inumaki is a local privacy boundary: it replaces the identifying information it detects before text reaches a cloud AI provider; what it misses is sent. A flaw in that boundary is a security bug, and this page says how to report one and what the project does and does not claim. The full statement, with every known gap, is the [threat model](docs/threat-model.md).

## Reporting a vulnerability

Report privately. Do not open a public issue, a pull request, or a discussion for a security problem.

Use GitHub's private vulnerability reporting: [report a vulnerability](https://github.com/Klinge01/inumaki/security/advisories/new) (the repository's Security tab, then "Report a vulnerability"). Only the maintainer sees the report.

Include what you did, what you expected, what happened, and the commit or version. Use synthetic data in the report: do not send real customer data, real keys, or a real transcript. If the report needs a sample, invent one.

## Supported versions

inumaki is pre-1.0 and experimental. Only the latest `main` is supported; there are no maintained release branches. A fix lands on `main`, and a report against an older commit is checked against `main` first.

## What counts as a security bug

**A leak across the boundary is a security bug.** That means any case where an original value, a token mapping, or a secret reaches a place it must not, for example:

- an identifier that inumaki's configured checks should have caught is sent to the provider, and the verifier reports `Pass`, in a case that the documented limits do not already cover;
- an original, token, secret, dataset name, file name, or upstream key appears in a log, error, `Debug` output, journal or activity record, metric, crash report, or telemetry;
- a request goes out unchecked when it should have been refused (a fail-open path: missing models, a detector error, an unreadable vault, a daemon that is down);
- a restored value or a vault key is exposed to a process, user, or web page that should not have it (the control socket, the proxy's `Origin` and `Host` guard, key and file permissions);
- the folder mirror, the tool-result hook, or the connect command writes or reads outside what it documents, or `connect revert` fails to restore what it changed;
- credentials for the provider are stored, logged, or sent anywhere but the configured upstream.

A missed name or address from the statistical detectors is not a security bug in itself; it is the known recall limit below. A report that shows a systematic miss, or a miss that the verifier or the documented profile should have caught, is welcome as an ordinary issue with synthetic text, or privately if you are unsure.

## What inumaki protects, and what it does not

inumaki reduces what a provider sees. It does not make text anonymous, and it is not a compliance tool. `docs/threat-model.md` is the full statement; the main residuals, each stated with its reason there:

- **Detection misses are sent as is.** Recall is measured on synthetic corpora only, and no profile is qualified against its targets. A `Pass` means the configured checks passed, not that the text holds no identifying information. See [What is not protected](docs/threat-model.md#what-is-not-protected) and [Engine follow-up residuals](docs/threat-model.md#engine-follow-up-residuals-l3-2026-10-10); the numbers are in `docs/quality/2026-10-09-4a-summary.md`.
- **Easy mode can be bypassed by an agent.** An agent that runs as your user and deliberately goes around inumaki can read the source folder, talk to the model directly, or call the control socket. A stronger mode is not built. See [the folder mirror](docs/threat-model.md#folder-mirror-milestone-5), [what the hook does not guarantee](docs/threat-model.md#what-the-hook-does-not-guarantee), and [chat paths that go around the proxy](docs/threat-model.md#chat-paths-that-go-around-the-proxy).
- **A process running as the same user** can call the daemon, read the vault file, and read the key file when the key file source is used. The control socket is protected by its file mode only. See [What is not protected](docs/threat-model.md#what-is-not-protected).
- **Attachments are removed, not inspected.** By default non-text parts are replaced by a placeholder and not sent; with `[proxy] binary = "forward"` they cross unchecked. Nothing reads text inside an attachment (there is no OCR). See the attachment items in [Known limitations](docs/threat-model.md#known-limitations).
- **Text that cannot be rewritten is forwarded.** Signed, cited, and reasoning text, JSON numbers, and object keys outside tool inputs pass unchanged, because changing them would make the request invalid. See the items on signed, cited, and reasoning text, JSON numbers, object keys, and structural fields in [Known limitations](docs/threat-model.md#known-limitations).
- **Request headers pass by an allowlist, and local paths in harness text pass unless a detector catches them.** `User-Agent` and the `x-stainless-*` headers name the OS, architecture, and terminal; header values the user adds under `extra_headers` are not checked. See the request-header item in [Known limitations](docs/threat-model.md#known-limitations).
- **The rehydration oracle on loopback.** A process that can reach `127.0.0.1:8787`, holds a provider credential, and knows a token can read the restored original in the model's answer. The `Origin` and `Host` guard and the per-install client header limit it; a same-user process can still read the header. See [The rehydration oracle](docs/threat-model.md#the-rehydration-oracle).
- **Linkability and semantics.** Within a dataset and rotation epoch the same entity keeps the same token, so a provider can link requests about the same person. The text keeps its meaning by design: re-identification from context alone is out of scope. See [What is not protected](docs/threat-model.md#what-is-not-protected).
- **Memory.** Aho-Corasick matchers keep copies of known originals that cannot be wiped until they are dropped. See the memory-retention item in [Known limitations](docs/threat-model.md#known-limitations).
- **Tested on macOS only**, with ad hoc code signing. Packages are pre-release and not Developer-ID signed. See `docs/packaging.md`.

A report that falls inside one of these is still useful if it shows the residual is larger than the threat model says or that a documented mitigation does not hold.

## Handling

There is no service-level agreement; this is a personal project. Reports are acknowledged and handled on a best-effort basis, and a fix is described in the commit that makes it. Please give the maintainer reasonable time to fix a problem before you disclose it publicly.
