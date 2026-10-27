# Discovery metadata under the model-backed profiles (plan 2c Task 1)

- **Date:** 2026-09-29
- **Commit:** `6b924f7` plus the probe `crates/inumakid/tests/discovery_calibration.rs` (added by this task, no other change)
- **Platform:** macOS aarch64, release build
- **Models** (`models/manifest.toml`): `gliner-x-small` (knowledgator/gliner-x-small @ `d51a0984`, sanitizer NER of `support-email`/`strict`/`thorough`/`thorough-strict`, verifier NER of `thorough`/`thorough-strict` via `[ner.gliner_verifier]`, threshold 0.3) and `mbert-ner-hrl` (onnx-community/bert-base-multilingual-cased-ner-hrl-ONNX @ `cfe67b1c`, sanitizer NER of `fast`/`fast-strict`, verifier NER of `support-email`/`strict` via `[ner.token_classifier]`, threshold 0.5)
- **Command:**

  ```bash
  INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models" \
    cargo test --release -p inumakid --features models-tests \
    --test discovery_calibration -- --ignored --nocapture
  ```

  Result: `test result: ok. 1 passed` (the 2026-09-28 smoke refusal reproduces under `strict`), 45.4 s of test time.

Everything below is synthetic: the scripted upstream's texts (canary identity `Zyxwuria Quolnath`, IBAN `AT61 1904 3002 3457 3201`), the probe's benign descriptions, and the probe's invented people.

## What the probe measures

Three text sets:

- **benign:** every description, title, schema prose string and enum value the scripted upstream lists that does not carry the canary or its IBAN, plus 17 descriptions and enum values of the kind real MCP servers list. Each must come out `Pass` and unchanged; a changed enum value fails the listing.
- **scripted positives:** the scripted upstream's texts that carry the canary or its IBAN. Each must come out `Pass`, tokenized, with no word of four or more characters of the canary or the IBAN left in clear, or the smoke test cannot list the server.
- **probe positives:** five descriptions naming a person or holding an IBAN (`Rückfragen an Zyxwuria Quolnath`, `orders placed by Sarah Leitner`, `Ansprechpartnerin ist Maria Huber aus Wien`, `the account of Hans-Peter Gruber`, `pays to AT61 …`). Each must be refused or come out clean.

Path A extends each family member with PERSON `min_confidence` T and `escalate_below` E over the grid T ∈ {0.60, 0.65, 0.70, 0.75} × E ∈ {0.55, 0.60, 1.00 (no band)}, in that preference order, and takes the first candidate both members pass. Path B, tried only when no A candidate passes, removes all NER from the sanitizer and the verifier and emulates a verifier NER floor T_v ∈ {0.50 … 0.95} with the base's verifier NER: a text on which it scores PERSON or STREET_ADDRESS at or above T_v counts as refused.

## Base profiles as they ship

Only outcomes other than `Pass` are listed; a `Pass` whose text changed (for example `asc` tokenized as PERSON) is not listed here but fails the candidate rules below. Format: outcome, check ids, text, sanitizer spans as `KIND:confidence:"excerpt"`.

**`fast`, `fast-strict`:** nothing refused. Every benign text passes.

**`support-email`** and **`strict`** (identical lists):

```
blocked   [Policy, Policy] "a text of about `bytes` bytes naming the identity" | PERSON:0.58:"bytes" PERSON:0.58:"` bytes"
blocked   [Policy, Policy] "a tool whose name is a canary for log tests" | PERSON:0.52:"tool" PERSON:0.53:"canary"
blocked   [Policy, Policy] "counts keyed by customer name" | PERSON:0.57:"customer" PERSON:0.58:"name"
blocked   [Policy] "look a customer up by number" | PERSON:0.51:"customer"
blocked   [Policy] "lookup_description" | PERSON:0.50:"lookup_description"
blocked   [Policy] "Search for repositories by name or topic" | PERSON:0.55:"topic"
blocked   [Policy] "name of the customer to search for" | PERSON:0.60:"customer"
blocked   [Policy] "desc" | PERSON:0.57:"desc"
blocked   [Policy] "full_name" | PERSON:0.57:"full_name"
```

**`thorough`** and **`thorough-strict`** (identical lists; spans are the sanitizer's, the `Ner` check is the verifier's re-scan):

```
blocked   [Ner, Ner] "a text of about `bytes` bytes naming the identity" | PERSON:0.58:"bytes" PERSON:0.58:"` bytes"
blocked   [Ner, Ner] "a text plus a link to a resource that is not listed" |
blocked   [Ner, Ner] "a tool whose name is a canary for log tests" | PERSON:0.52:"tool" PERSON:0.53:"canary"
blocked   [Ner, Ner] "add the extra tool (default), or change lookup's schema or description, and notify" |
blocked   [Ner] "an error that echoes its argument" |
blocked   [Ner, Ner] "an image plus a caption" |
blocked   [Ner] "counts keyed by customer name" | PERSON:0.57:"customer" PERSON:0.58:"name"
blocked   [Ner] "customer number" |
blocked   [Ner, Ner] "echo nested arguments as structured content" |
blocked   [Ner] "echo the query" |
blocked   [Ner] "end the server" |
blocked   [Ner] "extra" |
blocked   [Ner, Ner] "free text" |
blocked   [Ner, Ner] "greet someone" |
blocked   [Ner, Ner] "look a customer up by number" | PERSON:0.51:"customer"
blocked   [Policy] "lookup_description" | PERSON:0.50:"lookup_description"
blocked   [Ner] "lookup_schema" |
blocked   [Ner] "note" |
blocked   [Ner, Ner, Ner] "sleep ms then answer" |
blocked   [Ner] "the value of a request header (HTTP only)" |
blocked   [Ner, Ner] "Read the complete contents of a file from the file system" |
blocked   [Ner, Ner] "List all files and directories in a path" |
blocked   [Ner, Ner] "Search for repositories by name or topic" | PERSON:0.55:"topic"
blocked   [Ner, Ner] "Create a new issue in a repository" |
blocked   [Ner] "Send a message to a channel" |
blocked   [Ner] "look up an order by its number" |
blocked   [Ner] "name of the customer to search for" | PERSON:0.60:"customer"
blocked   [Ner] "Termine eines Mitarbeiters für eine Woche anzeigen" |
blocked   [Ner, Ner] "sort order" |
blocked   [Policy] "desc" | PERSON:0.57:"desc"
blocked   [Ner] "created_at" |
blocked   [Policy] "full_name" | PERSON:0.57:"full_name"
```

## Family `support-email` (`support-email`, `strict`)

Path A candidates (a member is only tried when the one before it passed):

```
  support-email T=60 E=55 benign   blocked   [Policy, Policy] "a text of about `bytes` bytes naming the identity" -> "" | PERSON:0.58:"bytes" PERSON:0.58:"` bytes"
  support-email T=60 E=55 benign   blocked   [Policy, Policy] "counts keyed by customer name" -> "" | PERSON:0.57:"customer" PERSON:0.58:"name"
  support-email T=60 E=55 benign   blocked   [Policy] "name of the customer to search for" -> "" | PERSON:0.60:"customer"
  support-email T=60 E=55 benign   pass      [] "asc" -> "<PERSON_ded4>" | PERSON:0.63:"asc"
  support-email T=60 E=55 benign   blocked   [Policy] "desc" -> "" | PERSON:0.57:"desc"
  support-email T=60 E=55 benign   blocked   [Policy] "full_name" -> "" | PERSON:0.57:"full_name"
support-email T=60 E=55: fails
  support-email T=60 E=60 benign   pass      [] "asc" -> "<PERSON_6422>" | PERSON:0.63:"asc"
support-email T=60 E=60: fails
  support-email T=60 E=100 benign   pass      [] "asc" -> "<PERSON_490a>" | PERSON:0.63:"asc"
support-email T=60 E=100: fails
  support-email T=65 E=55 benign   (same five blocks as T=60 E=55, and "asc" blocked [Policy])
support-email T=65 E=55: fails
  support-email T=65 E=60 benign   blocked   [Policy] "asc" -> "" | PERSON:0.63:"asc"
support-email T=65 E=60: fails
support-email T=65 E=100: passes
  strict T=65 E=100 benign   pass      [] "Get the current weather for a city" -> "Get the current weather for a <CITY_c512>" | CITY:0.55:"city"
strict T=65 E=100: fails
  (T=70 and T=75 repeat T=65 line for line: E=55 and E=60 fail on the same texts, E=100 passes
   for support-email and fails for strict on "Get the current weather for a city" -> CITY token)
support-email T=70 E=100: passes
strict T=70 E=100: fails
support-email T=75 E=100: passes
strict T=75 E=100: fails
```

Path B candidates (every floor fails the same way):

```
  support-email B=50 positive pass      "Rückfragen an Zyxwuria Quolnath" -> "Rückfragen an Zyxwuria Quolnath"
  support-email B=50 scripted pass      fires false "the customer record of Zyxwuria Quolnath" -> "the customer record of Zyxwuria Quolnath" (needs a dictionary entry)
support-email B=50: fails
  (B=55 … B=95: the same two lines, then "fails")
```

## Family `thorough` (`thorough`, `thorough-strict`)

Path A: all twelve candidates fail on `thorough`, the first member, so `thorough-strict` is never tried. Every candidate fails the same 34 benign texts: 33 refused under all twelve, plus `asc`, which T=60 tokenizes (`Pass`, `<PERSON_…>`) and T ≥ 0.65 blocks. No positive fails any candidate. The T=75 E=100 lines:

```
  thorough T=75 E=100 benign   blocked   [Ner, Ner, Ner, Ner, Ner] "a text of about `bytes` bytes naming the identity" -> "" | PERSON:0.58:"bytes" PERSON:0.58:"` bytes"
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "a text plus a link to a resource that is not listed" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner, Ner, Ner] "a tool whose name is a canary for log tests" -> "" | PERSON:0.52:"tool" PERSON:0.53:"canary"
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "add the extra tool (default), or change lookup's schema or description, and notify" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "an error that echoes its argument" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "an image plus a caption" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner, Ner] "counts keyed by customer name" -> "" | PERSON:0.57:"customer" PERSON:0.58:"name"
  thorough T=75 E=100 benign   blocked   [Ner] "customer number" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "echo nested arguments as structured content" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "echo the query" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "end the server" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "extra" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "free text" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "greet someone" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "look a customer up by number" -> "" | PERSON:0.51:"customer"
  thorough T=75 E=100 benign   blocked   [Ner] "lookup_description" -> "" | PERSON:0.50:"lookup_description"
  thorough T=75 E=100 benign   blocked   [Ner] "lookup_schema" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "note" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner, Ner] "sleep ms then answer" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "the value of a request header (HTTP only)" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "Read the complete contents of a file from the file system" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "List all files and directories in a path" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner, Ner] "Search for repositories by name or topic" -> "" | PERSON:0.55:"topic"
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "Create a new issue in a repository" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "Get the current weather for a city" -> "" | CITY:0.55:"city"
  thorough T=75 E=100 benign   blocked   [Ner] "Send a message to a channel" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "look up an order by its number" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "name of the customer to search for" -> "" | PERSON:0.60:"customer"
  thorough T=75 E=100 benign   blocked   [Ner] "Termine eines Mitarbeiters für eine Woche anzeigen" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner, Ner] "sort order" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "asc" -> "" | PERSON:0.63:"asc"
  thorough T=75 E=100 benign   blocked   [Ner] "desc" -> "" | PERSON:0.57:"desc"
  thorough T=75 E=100 benign   blocked   [Ner] "created_at" -> "" |
  thorough T=75 E=100 benign   blocked   [Ner] "full_name" -> "" | PERSON:0.57:"full_name"
thorough T=75 E=100: fails
```

Path B candidates:

```
  thorough B=50 benign   pass      fires true "a text of about `bytes` bytes naming the identity"
  thorough B=50 benign   pass      fires true "a tool whose name is a canary for log tests"
  thorough B=50 benign   pass      fires true "counts keyed by customer name"
  thorough B=50 benign   pass      fires true "customer number"
  thorough B=50 benign   pass      fires true "greet someone"
  thorough B=50 benign   pass      fires true "look a customer up by number"
  thorough B=50 benign   pass      fires true "lookup_description"
  thorough B=50 benign   pass      fires true "lookup_schema"
  thorough B=50 benign   pass      fires true "sleep ms then answer"
  thorough B=50 benign   pass      fires true "the value of a request header (HTTP only)"
  thorough B=50 benign   pass      fires true "Search for repositories by name or topic"
  thorough B=50 benign   pass      fires true "name of the customer to search for"
  thorough B=50 benign   pass      fires true "Termine eines Mitarbeiters für eine Woche anzeigen"
  thorough B=50 benign   pass      fires true "asc"
  thorough B=50 benign   pass      fires true "desc"
  thorough B=50 benign   pass      fires true "created_at"
  thorough B=50 benign   pass      fires true "full_name"
  thorough B=50 scripted pass      fires true "the customer record of Zyxwuria Quolnath" -> "the customer record of Zyxwuria Quolnath" (needs a dictionary entry)
thorough B=50: fails
  thorough B=55 benign   pass      fires true "a text of about `bytes` bytes naming the identity"
  thorough B=55 benign   pass      fires true "a tool whose name is a canary for log tests"
  thorough B=55 benign   pass      fires true "counts keyed by customer name"
  thorough B=55 benign   pass      fires true "the value of a request header (HTTP only)"
  thorough B=55 benign   pass      fires true "asc"
  thorough B=55 benign   pass      fires true "desc"
  thorough B=55 benign   pass      fires true "full_name"
  thorough B=55 scripted pass      fires true "the customer record of Zyxwuria Quolnath" -> "the customer record of Zyxwuria Quolnath" (needs a dictionary entry)
thorough B=55: fails
  thorough B=60 benign   pass      fires true "a tool whose name is a canary for log tests"
  thorough B=60 benign   pass      fires true "counts keyed by customer name"
  thorough B=60 benign   pass      fires true "the value of a request header (HTTP only)"
  thorough B=60 benign   pass      fires true "asc"
  thorough B=60 benign   pass      fires true "full_name"
  thorough B=60 scripted pass      fires true "the customer record of Zyxwuria Quolnath" -> "the customer record of Zyxwuria Quolnath" (needs a dictionary entry)
thorough B=60: fails
  thorough B=65 benign   pass      fires true "the value of a request header (HTTP only)"
  thorough B=65 scripted pass      fires true "the customer record of Zyxwuria Quolnath" -> "the customer record of Zyxwuria Quolnath" (needs a dictionary entry)
thorough B=65: fails
  thorough B=70 scripted pass      fires true "the customer record of Zyxwuria Quolnath" -> "the customer record of Zyxwuria Quolnath" (needs a dictionary entry)
thorough B=70: passes
  thorough-strict B=70 scripted pass      fires true "the customer record of Zyxwuria Quolnath" -> "the customer record of Zyxwuria Quolnath" (needs a dictionary entry)
thorough-strict B=70: passes
```

## Margins and decisions

Margins are the highest PERSON score the family's first member's sanitizer gives a benign text and the lowest non-zero PERSON score it gives a positive. Both families share the `gliner-x-small` sanitizer, so the numbers match:

```
support-email: benign PERSON max 0.63, positive PERSON min 0.82
thorough: benign PERSON max 0.63, positive PERSON min 0.82
```

```
DECISION support-email: NONE -> BLOCKED, the integrator decides
DECISION thorough: B (verifier floor 0.70) -> BLOCKED, the integrator decides
```

## Reading

**Family `support-email`.** Both bases block nine benign texts, all on the `Policy` check: the GLiNER sanitizer scores common words (`customer`, `name`, `topic`, `bytes`, `desc`, `full_name`, `lookup_description`) as PERSON between 0.50 and 0.60 (printed rounded), just under PERSON's `min_confidence` 0.60, and the policy check refuses those spans as escalated (`support-email` and `strict` refuse the identical list; `support-email`'s verifier retry profile is `strict`); `asc` scores 0.63 and is silently tokenized, which breaks the enum. The PERSON margin is wide (benign max 0.63, positive min 0.82), and path A uses it: T ≥ 0.65 with no escalation band (E = 1.00) passes every text under `support-email`, positives included. Since no A candidate is chosen, the probe does not break down which positives only the verifier caught; its output lists failing texts only. It fails under `strict` on one text only, and not on PERSON: `strict` tokenizes CITY from 0.40, and the probe's benign `Get the current weather for a city` has `city` scored CITY 0.55, so the description changes. The grid varies PERSON and the band only, so no A candidate can pass `strict`. Path B cannot work for this family: its verifier NER (`mbert-ner-hrl`) does not score the synthetic canary `Zyxwuria Quolnath` at 0.50 or above, so with the sanitizer's NER removed `Rückfragen an Zyxwuria Quolnath` would leave in clear at every floor. Hence `NONE`. The measurement suggests a path A variant that also keeps CITY (and the other kinds `strict` promotes) unchanged in metadata, with T = 0.65 and no band, but that is outside the probe's grid and for the integrator to decide.

**Family `thorough`.** The bases block 32 benign texts, 29 of them on the `Ner` check: the `gliner_verifier` re-scan (threshold 0.3) reports PERSON or STREET_ADDRESS on ordinary tool prose (`echo the query`, `sort order`, `created_at`, `Send a message to a channel`) where the sanitizer found nothing. The other three (`lookup_description`, `desc`, `full_name`) are sanitizer PERSON spans in the 0.50–0.60 band blocked by `Policy`, as in `support-email`. Path A changes only the sanitizer's policy, so the verifier keeps refusing the same texts under every candidate. Path B passes at a verifier floor of 0.70: the highest verifier score on a benign text lies between 0.65 and 0.70 (`the value of a request header (HTTP only)` still fires at 0.65), and every probe positive is refused or comes out clean. The cost of B shows in the scripted positive: without sanitizer NER, `the customer record of Zyxwuria Quolnath` is not tokenized; the verifier refuses it at 0.70, so the smoke listing would still fail unless a dictionary lists the canary. The margin between the 0.70 floor and the highest benign verifier score is under 0.05.

**`fast`, `fast-strict`.** Neither refuses any text in the set (the probe lists non-`Pass` outcomes only, so a benign text they alter is not shown); they run the `mbert-ner-hrl` sanitizer and no verifier NER. They get no metadata profile, and nothing stays refused in this set. That is a property of this text set, not a guarantee: these profiles keep their verifier-less threat model.

## Shipped values (2026-09-29, integrator ruling)

The integrator ruled on the measurement above (plan 2c Task 3):

- Only two metadata profiles ship: `support-email-metadata` and `strict-metadata`. `thorough`, `thorough-strict`, `fast`, `fast-strict`, `offline`, `offline-strict` get none.
- Both ship as path A: PERSON `min_confidence` 0.65, `escalate_below` 1.00 (no escalation band), `verifier.retry_profile` naming the metadata profile itself.
- `strict-metadata` additionally raises `strict`'s five promoted kinds (CITY, POSTAL_CODE, ORGANIZATION, URL, DATE, tokenized from 0.40 in `strict`) to 0.60 in metadata, same action (`tokenize`) — a raised threshold on the same action never weakens a profile, so `check_metadata_profile` allows it. `support-email` preserves these kinds outright (`action = "preserve"`, inherited from `offline`), so `support-email-metadata` needs no equivalent change; `strict-metadata` needs one because `strict` tokenizes them from 0.40, and the measurement's only benign hit on any of the five was CITY 0.55 on the probe's `Get the current weather for a city`. 0.60 is the smallest multiple of 0.05 above that measured 0.55, so it is the value shipped.
- `thorough` and `thorough-strict` ship with no metadata profile: their `gliner_verifier` re-scan blocks benign descriptions outright (the measurement's 29 `Ner`-check blocks above are unreachable from a path A change to the sanitizer's policy), and path B's cost — the scripted canary is not tokenized without a dictionary entry, so the smoke listing would still need one — was judged not worth shipping until the quality lane recalibrates `gliner_verifier`.

**Confirmation** (addendum point 6): the two shipped profiles, loaded unchanged from `configs/default.toml` (no probe candidates), against the same texts as the calibration above.

```bash
INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models" \
  cargo test --release -p inumakid --features models-tests \
  --test discovery_calibration shipped_metadata_profiles_pass_the_rule -- --ignored --nocapture
```

```
support-email-metadata: benign PERSON max 0.63, positive PERSON min 0.82
support-email-metadata: passes
strict-metadata: benign PERSON max 0.63, positive PERSON min 0.82
strict-metadata: passes
test shipped_metadata_profiles_pass_the_rule ... ok
```

`test result: ok. 1 passed; 0 failed`, exit code 0. Both profiles pass with a 0.19 margin between the highest benign PERSON score and the lowest positive PERSON score (0.63 vs. 0.82) — the same margin `support-email`'s own path A candidate measured above, since both ship at the same T/E and share the `gliner-x-small` sanitizer; this text set does not probe CITY/POSTAL_CODE/ORGANIZATION/URL/DATE, so it does not re-confirm `strict-metadata`'s 0.60 kinds.

The model-backed smoke-flow test (`crates/inumakid/tests/gateway_models.rs`) surfaced a separate, unrelated result-path false positive: the scripted upstream's `record` result carried the free-text tag `"vip"`, which the GLiNER sanitizer scored PERSON at 0.55 — inside `strict`'s escalation band for ordinary (non-metadata) content — so `strict`'s policy blocked the call instead of tokenizing it. The integrator ruled to change the fixture's benign tag from `"vip"` to `"tier-2"`, which scores no span under `strict` or `support-email`; `strict`'s result semantics (the escalation band, the policy check) are unchanged, and the broader false positive on short single tokens in results went to the quality lane.

Synthetic data only: the scripted upstream's canary identity, IBAN, and tag, and the probe's invented people.
