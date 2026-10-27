# Local Privacy Proxy for Cloud AI
## Design Concept for Privacy-Preserving AI Processing in EU Business Workflows

**Status:** Early concept / technical exploration  
**Initial use case:** Customer-support email processing  
**Primary objective:** Allow businesses to use capable cloud-hosted AI models without transmitting directly identifying customer information to the remote AI provider.

---

## 1. Problem

Cloud AI is attractive to small and medium-sized businesses because it avoids the cost and operational complexity of running capable inference infrastructure locally.

This creates a problem when AI systems are integrated into workflows containing customer or third-party data, such as:

- customer-support inboxes
- sales emails
- CRM notes
- contact forms
- support tickets
- documents
- internal communications

These inputs are typically unstructured.

An email might contain:

> Hello, my name is Thomas Müller.  
> My contract number is 12345678.  
> I recently moved to Hauptstraße 12, 1010 Vienna.  
> Can you please update my account?

A cloud LLM does not necessarily need to know that the customer is **Thomas Müller** or lives at a particular address in order to understand the actual request:

> A customer has moved and wants their account details updated.

The proposed system therefore introduces a local privacy boundary between the business application and the external AI provider.

---

# 2. High-Level Architecture

The general flow is:

```text
Original business data
        │
        ▼
┌──────────────────────────┐
│ Local Privacy Proxy      │
│                          │
│ Detect identifiers       │
│ Replace identifiers      │
│ Store local mapping      │
└────────────┬─────────────┘
             │
             ▼
     Sanitized candidate
             │
             ▼
┌──────────────────────────┐
│ Local Privacy Classifier │
│                          │
│ "Still identifiable?"    │
└────────────┬─────────────┘
             │
      ┌──────┴──────┐
      ▼             ▼
   Allow         Escalate /
      │          block / retry
      ▼
┌──────────────────────┐
│   Remote AI Model    │
│                      │
│ No direct access to  │
│ original identifiers │
└──────────┬───────────┘
           │
           ▼
   Sanitized response
           │
           ▼
┌──────────────────────┐
│ Local Privacy Proxy  │
│                      │
│ Restore identifiers  │
└──────────┬───────────┘
           │
           ▼
      Final output
```

The remote model operates on the semantics of the message while the identifying information remains local.

The new architectural principle is that **the component which performs sanitization should not be the only component trusted to validate it**. A separate local classifier acts as an independent privacy gate before data is transmitted.

---

# 3. Example

Original email:

> Hi, I'm Sarah Leitner and I'm calling regarding contract 8439271.  
> I moved from Berggasse 14 to Neubaugasse 22 last week.  
> Could you update my account and let me know if you need anything else?

The local proxy transforms it into:

> Hi, I'm {{PERSON_A7F2}} and I'm calling regarding contract
> {{CUSTOMER_ID_B41C}}.
>
> I moved from {{ADDRESS_84D1}} to {{ADDRESS_112F}} last week.
>
> Could you update my account and let me know if you need anything else?

Before this text leaves the local trust boundary, a local privacy classifier evaluates the sanitized candidate:

```text
SAFE / NOT IDENTIFIABLE       0.9981
UNSAFE / IDENTIFIABLE         0.0019
```

If the result passes the configured threshold, it is transmitted to the remote model.

The cloud model might return:

> Hello {{PERSON_A7F2}},
>
> thank you for letting us know about your change of address.
> We can update your account from {{ADDRESS_84D1}} to
> {{ADDRESS_112F}}.
>
> Please provide confirmation of the address change if required.

The local proxy then performs token substitution:

> Hello Sarah Leitner,
>
> thank you for letting us know about your change of address.
> We can update your account from Berggasse 14 to Neubaugasse 22.
>
> Please provide confirmation of the address change if required.

The cloud model never needs to receive the original values.

---

# 4. Important Distinction: Anonymization vs. Tokenization

The initial idea was to hash personal information using a per-request salt.

That is probably not the right primitive.

A cryptographic hash is normally one-way:

```text
plaintext → hash
```

It is not intended to support:

```text
hash → plaintext
```

Instead, the system should use **random opaque tokens with a local lookup table**.

Example:

```text
Sarah Leitner
      ↓
PERSON_A7F2C1
```

Locally:

```text
PERSON_A7F2C1 → Sarah Leitner
```

The mapping never needs to leave the local environment.

---

# 5. Per-Request Tokenization

Tokens should ideally be generated independently for every processing context.

For request A:

```text
Sarah Leitner → PERSON_6F91
```

For request B:

```text
Sarah Leitner → PERSON_D284
```

Even if both requests are sent to the same AI provider, the provider cannot trivially establish:

```text
PERSON_6F91 == PERSON_D284
```

This prevents the pseudonyms themselves from becoming persistent identifiers.

## Desired properties

Tokens should be:

- random
- opaque
- non-semantic
- generated using a cryptographically secure RNG
- scoped to a single processing context where possible
- short-lived
- destroyed after the request is completed

For example:

```text
<PERSON_f93a7c>
<EMAIL_81ab42>
<IBAN_a91e35>
```

The category can optionally remain visible because it helps the LLM reason correctly.

For example:

```text
Please send the refund to <IBAN_A71C>
```

is more useful than:

```text
Please send the refund to <TOKEN_A71C>
```

---

# 6. The Core Technical Problem

The difficult part of the system is not token generation.

It is:

> Reliably detecting information that can identify a natural person while preserving enough semantic information for the AI system to perform useful work.

The local anonymization engine is therefore the central technical component.

A second, separate problem is:

> Reliably detecting whether the anonymization step failed before the sanitized payload leaves the local system.

This is where a small specialized classifier becomes particularly valuable.

---

# 7. Proposed Local Detection and Verification Stack

A layered approach is preferable to relying on a single model.

```text
Input
  │
  ├── Structured pattern detection
  │
  ├── Named Entity Recognition
  │
  ├── Domain-specific detection
  │
  ├── Contextual / heuristic detection
  │
  └── Policy engine
  │
  ▼
Tokenization
  │
  ▼
Sanitized candidate
  │
  ▼
Independent local privacy classifier
  │
  ├── Safe → remote AI allowed
  │
  └── Unsafe / uncertain → block, retry, or escalate
```

Each layer serves a different role:

- **detectors** identify where potentially identifying information exists
- **tokenization** removes the original values
- **the classifier** independently decides whether the resulting text still appears identifying

This separation is important.

A binary or probabilistic classifier can determine whether a payload is safe enough to transmit, but it does not tell the system which exact spans should be replaced. That makes it ideal as a verification layer, not as the sole redaction mechanism.

---

# 8. Layer 1 — Deterministic Pattern Recognition

The cheapest and most reliable identifiers should be detected without machine learning.

Typical examples include:

- email addresses
- telephone numbers
- IBANs
- credit-card-like numbers
- IP addresses
- URLs containing identifiers
- postal codes in specific contexts
- customer numbers
- account numbers
- contract numbers
- invoice numbers
- VAT identifiers
- social-security-number-like formats
- license plate formats
- dates where business rules identify them as DOB fields

Implementation can largely use:

- regular expressions
- parsers
- checksums
- validation algorithms

Examples:

```text
IBAN:
AT61 1904 3002 3457 3201

Email:
sarah@example.com

Phone:
+43 660 1234567
```

This layer has several advantages:

- extremely fast
- deterministic
- explainable
- tiny resource requirements
- easy to test
- easy to audit

For known structured identifiers, this should generally be preferred over AI.

---

# 9. Layer 2 — Named Entity Recognition

Regex cannot reliably detect names such as:

> Sarah Leitner

or:

> Dr. Maximilian Gruber

This is where Named Entity Recognition (NER) becomes useful.

NER models classify sections of text into entity categories such as:

- PERSON
- LOCATION
- ORGANIZATION
- DATE

For example:

```text
"Sarah Leitner lives in Vienna."

Sarah Leitner → PERSON
Vienna         → LOCATION
```

## Potential technologies

### spaCy

spaCy is an obvious candidate for an initial prototype.

Advantages:

- mature
- fast
- CPU-friendly
- production-oriented
- Python ecosystem
- pretrained language pipelines
- relatively straightforward customization

It is orders of magnitude smaller and cheaper than running a general-purpose LLM.

### Transformer-based NER models

A small BERT-derived model could provide better recognition accuracy.

Potential families include:

- BERT
- DistilBERT
- MiniLM-derived models
- ModernBERT-style encoders
- multilingual transformer models
- German-specific transformer models

These can still run locally on ordinary CPUs.

The relevant comparison is not:

> local AI vs. no local AI

but rather:

> specialist encoder model

versus

> multi-billion-parameter generative model.

For this application, the specialist model may be sufficient.

---

# 10. Layer 3 — Domain-Specific Rules

A generic NER model cannot know the internal semantics of every business.

For example:

```text
K-928174
```

might be meaningless to a generic model.

Inside a company, however, it might represent:

```text
Customer ID
```

The system therefore needs configurable domain-specific detectors.

Example rules:

```text
^K-[0-9]{6}$ → CUSTOMER_ID
```

or contextual recognizers triggered by labels such as:

```text
Vertragsnummer:
Kundennummer:
Customer ID:
Zählpunkt:
```

This layer is particularly important because business systems frequently contain identifiers that are highly identifying but linguistically meaningless.

---

# 11. Layer 4 — Dictionaries and Business Data

The local proxy can potentially use known local data as an additional detection source.

For example, if the CRM already contains:

```text
Customer:
Sarah Leitner
```

then an occurrence of:

```text
Sarah
```

or:

```text
Ms. Leitner
```

inside the message can be recognized with much higher confidence.

Potential local dictionaries could contain:

- customer names
- employee names
- supplier contacts
- known addresses
- company-specific identifiers

This is especially interesting because the privacy proxy sits inside the organization's trusted boundary.

It can use information that should never be exposed to the cloud provider.

---

# 12. Layer 5 — Independent Local Privacy Classifier

A small local classifier should evaluate the **sanitized candidate**, not necessarily the raw input.

Its narrow task is:

> Does this payload still contain enough information to identify or reasonably re-identify a natural person?

A minimal formulation would be:

```text
SAFE
UNSAFE
```

A more useful formulation is probabilistic:

```text
P(SAFE)   = 0.9987
P(UNSAFE) = 0.0013
```

This allows policy thresholds.

For example:

```text
P(UNSAFE) < 0.01
    → allow cloud processing

0.01 ≤ P(UNSAFE) < 0.10
    → run stronger local analysis

P(UNSAFE) ≥ 0.10
    → block / retry / human review
```

The exact thresholds would need to be calibrated empirically.

## Why this task is a good fit for a specialist classifier

The model does not need to:

- generate prose
- produce arbitrary JSON
- follow complex instructions
- reason over open-ended tasks
- preserve conversational state
- perform business logic

It only needs to map text to a constrained decision.

Conceptually:

\[
f(\text{text}) \rightarrow P(\text{identifiable})
\]

This is exactly the kind of workload for which non-autoregressive or encoder-based classifiers are attractive.

---

# 13. Jev-, Laya-, and Encoder-Style Models

Models such as Jev or an open-weights alternative such as Laya are interesting because they are built around constrained decision outputs rather than free-form language generation.

For this architecture, however, the important question is not whether a particular "decision model" paradigm is novel.

The important engineering question is:

> Which local classifier gives the lowest false-negative rate at acceptable latency and resource cost?

A serious evaluation should therefore compare approaches such as:

- fine-tuned Laya-style classifier
- ModernBERT / BERT / DeBERTa-style encoder classifier
- multilingual encoder classifier
- NLI / zero-shot classifier
- cross-encoder
- embedding model + logistic regression
- lightweight domain-specific classifier

Jev-like systems may fit the use case well, but they should be benchmarked against conventional classifiers rather than assumed to be superior.

---

# 14. Why "Yes / No PII" Is Easy — and Also Not Enough

Training a model to distinguish:

```text
PII
NO_PII
```

is comparatively straightforward.

Example:

```text
"My tariff expires next month."
→ NO_PII
```

```text
"My tariff expires next month. My name is Thomas Müller."
→ PII
```

However, this alone cannot drive redaction.

The classifier tells us:

```text
PII exists
```

but not:

```text
Thomas Müller → PERSON
```

Therefore:

- **NER / recognizers perform localization**
- **the classifier performs verification**

This division of responsibilities keeps each component narrow and testable.

---

# 15. Train the Classifier on Failed Anonymizations

A particularly promising training strategy is to train the classifier on **successful and failed privacy transformations**.

Example:

Original:

```text
Hi, I'm Thomas Müller and my customer number is 382910.
```

Correct sanitized result:

```text
Hi, I'm <PERSON_1> and my customer number is <CUSTOMER_ID_1>.
```

Generate deliberately broken variants:

```text
Hi, I'm Thomas Müller and my customer number is <CUSTOMER_ID_1>.
```

Label:

```text
UNSAFE
```

Another:

```text
Hi, I'm <PERSON_1> and my customer number is 382910.
```

Label:

```text
UNSAFE
```

Correct result:

```text
Hi, I'm <PERSON_1> and my customer number is <CUSTOMER_ID_1>.
```

Label:

```text
SAFE
```

This changes the ML problem from:

> What is personal data?

into the much narrower:

> Did the anonymization transformation succeed?

That is likely an easier and more operationally useful task.

---

# 16. Synthetic Training Data

This verification classifier is unusually suitable for synthetic training.

The system can generate:

- clean messages
- messages with injected names
- messages with injected addresses
- messages with customer numbers
- partially anonymized messages
- incorrectly anonymized messages
- combinations of indirect identifiers

Because the original structured entities are known, ground truth is available.

Training data could include increasingly difficult cases.

## Simple cases

```text
"My contract expires next month."
→ SAFE
```

```text
"My name is Thomas Müller."
→ UNSAFE
```

## Partial sanitization

```text
"<PERSON_1> can be reached at thomas@example.at."
→ UNSAFE
```

## Semantically sensitive but non-identifying content

```text
"My daughter had an accident last week."
→ SAFE
```

assuming no surrounding information makes the daughter identifiable.

## Combination risk

```text
"The only electrician working at Example GmbH's Vienna office."
→ potentially UNSAFE
```

This allows the classifier to learn that identifiability may emerge from combinations rather than obvious names alone.

---

# 17. Re-Identification Risk, Not Just PII Pattern Matching

A weak classifier may simply learn:

```text
name / email / address present → PII
```

The desired classifier is more sophisticated.

Its target concept should be closer to:

> Could the recipient reasonably identify a natural person from the information contained in this payload?

This matters because individual facts may not identify someone, while combinations may.

For example:

```text
Vienna
```

has little identifying value.

```text
Thomas
```

may still have little identifying value.

```text
Thomas, electrician, Vienna
```

may remain insufficient.

But:

```text
Thomas, the only electrician working at Example GmbH's Vienna office
```

could create meaningful re-identification risk.

The classifier should therefore eventually learn **combination risk**, not merely entity presence.

---

# 18. What Probably Should NOT Be the Primary Detection Technique

## Dictionary-based "unknown word" detection

One initial intuition is similar to spell checking:

> A name such as "Leitner" is not in the dictionary, therefore it might be personal information.

This can help as a weak signal, but it is unsuitable as a primary classifier.

Problems include:

- surnames may also be normal words
- technical terms may not exist in dictionaries
- product names generate false positives
- common first names can be dictionary words
- multilingual emails complicate the approach
- names such as "May", "Rose", or "Hunter" are ordinary English words

It could be included as one weak heuristic, but not as the main mechanism.

---

# 19. Why a Local LLM Is Probably Overkill Initially

A small local generative LLM could be asked:

> Find all personally identifying information in this text.

However, this introduces several disadvantages:

- higher RAM usage
- higher latency
- greater CPU/GPU requirements
- nondeterministic output
- harder auditing
- harder benchmarking
- hallucination risk
- considerably larger deployment footprint

For SMB deployments, these disadvantages directly undermine one of the project's main goals:

> Allow the privacy layer to run cheaply on ordinary hardware.

A deterministic + NER + specialist-classifier architecture is therefore a much more attractive starting point.

A local LLM might later become an optional escalation layer for ambiguous cases.

---

# 20. Microsoft Presidio

Microsoft Presidio is particularly relevant to evaluate.

It already implements many primitives required by this project:

```text
text
  ↓
PII analyzers
  ↓
detected entities
  ↓
anonymization operators
```

It supports combining:

- NER
- regex
- custom recognizers
- confidence scores
- anonymization strategies

This makes it useful as:

1. an initial implementation,
2. a baseline against which a custom system is benchmarked, or
3. a component inside the broader privacy proxy.

The main question is how well it performs on:

- German
- Austrian identifiers
- DACH addresses
- Austrian telephone numbers
- Austrian IBANs
- company-specific identifiers
- mixed German/English business communication

---

# 21. Context-Aware Detection

Individual pieces of information are not equally identifying.

For example:

```text
Vienna
```

alone is clearly insufficient.

However:

```text
Sarah Leitner, Vienna
```

is more identifying.

And:

```text
Sarah Leitner, Neubaugasse 22, Vienna
```

is stronger still.

A future detection engine could therefore reason about **identifier combinations** rather than treating every entity independently.

Example:

```text
PERSON + STREET_ADDRESS
          ↓
high re-identification risk
```

whereas:

```text
CITY
 ↓
low risk
```

This could improve utility because the proxy would not need to remove every location, date, or organization indiscriminately.

---

# 22. Data Minimization Instead of "Delete Everything Personal"

An important design principle should be:

> Remove what enables identification, rather than removing every piece of information relating to a person.

For AI utility, this distinction matters enormously.

Consider:

> My daughter had an accident last week and I need to postpone the appointment.

Removing:

```text
daughter
accident
last week
```

would substantially damage the semantics of the request.

But without any reasonable mechanism to associate that statement with an identified or identifiable person, those words do not inherently identify someone.

The proxy should therefore avoid becoming a crude "sensitive words filter."

Its purpose is to break the connection between:

```text
information
```

and:

```text
identity
```

---

# 23. Semantic Preservation

The sanitized prompt should preserve as much structure as possible.

Bad:

```text
[REDACTED] wants [REDACTED] changed because [REDACTED].
```

Better:

```text
<PERSON_1> wants their <CONTRACT_ID_1> updated because they moved
from <ADDRESS_1> to <ADDRESS_2>.
```

The second form preserves:

- entity type
- entity relationships
- grammar
- intent
- referential consistency

while withholding the values themselves.

---

# 24. Referential Consistency

Within a single processing context, identical entities should generally use the same token.

Original:

> Sarah called yesterday.  
> Sarah now wants her contract updated.

Sanitized:

> <PERSON_1> called yesterday.  
> <PERSON_1> now wants her contract updated.

Not:

> <PERSON_1> called yesterday.  
> <PERSON_2> now wants her contract updated.

Otherwise the AI model may infer that two different people are involved.

---

# 25. Request Scope

A "request" may need to mean more than one HTTP call.

For an agentic workflow, the privacy context could live for:

```text
conversation / task lifetime
```

rather than:

```text
single API invocation
```

Example:

```text
Customer support ticket
   ├─ model call 1
   ├─ model call 2
   ├─ tool call
   └─ model call 3
```

All of these might require:

```text
<PERSON_A>
```

to refer to the same person.

Once the workflow finishes, the mapping can be destroyed.

This provides a useful compromise between:

- semantic consistency
- cross-request unlinkability

---

# 26. Local Mapping Store

Example transient mapping:

```json
{
  "<PERSON_A7F2>": "Sarah Leitner",
  "<CONTRACT_B192>": "8439271",
  "<ADDRESS_91AC>": "Berggasse 14",
  "<ADDRESS_727B>": "Neubaugasse 22"
}
```

This mapping should ideally:

- exist only locally
- live in memory where possible
- have a short TTL
- never appear in application logs
- never enter observability tooling
- never be transmitted to the AI provider
- be securely destroyed when no longer required

---

# 27. Logging Is a Major Attack Surface

One easy way to accidentally defeat the architecture would be:

```text
logger.debug(originalMessage)
```

or:

```text
error.captureException(request)
```

The privacy proxy therefore needs explicit rules around:

- application logs
- tracing
- crash reporting
- metrics
- debugging
- telemetry
- backups

The architecture is only meaningful if the privacy boundary applies to the entire local processing pipeline.

---

# 28. Confidence-Based Processing

Detection systems will never be perfect.

Each detected entity could receive a confidence score.

Example:

```text
"Sarah Leitner"     PERSON      0.997
"Vienna"            LOCATION    0.998
"Apple"             ORG         0.64
"Hunter"            PERSON      0.55
```

Policies can then determine what happens.

Example:

```text
confidence > 0.90
    automatically tokenize

confidence 0.60–0.90
    apply additional classifier

confidence < 0.60
    leave unchanged or escalate
```

A high-security deployment could instead choose:

```text
uncertain → block cloud processing
```

The post-tokenization privacy classifier should have its own independently calibrated threshold.

---

# 29. Detection Policy Should Be Configurable

Different workflows require different privacy thresholds.

For example:

### Customer support

Tokenize:

- person
- email
- phone
- street address
- customer number
- IBAN

Preserve where appropriate:

- city
- product name
- company name
- dates
- issue description

### Medical workflow

Much more aggressive detection would likely be appropriate.

### Internal software ticket

Potentially only employee identifiers and credentials need removal.

The detection engine should therefore separate:

```text
entity detection
```

from:

```text
privacy policy
```

---

# 30. Credentials and Secrets

The same architecture can protect more than personal data.

The local scanner could also recognize:

- API keys
- passwords
- JWTs
- OAuth tokens
- AWS credentials
- private keys
- database connection strings
- access tokens

These should usually be completely removed rather than restored into model-generated output.

This introduces a broader use case:

> AI Data-Loss-Prevention Proxy

rather than merely:

> GDPR anonymization proxy.

---

# 31. Potential Architecture

A practical implementation might look like:

```text
Application
    │
    ▼
Privacy Proxy
    │
    ├── Regex Recognizers
    │
    ├── NER Engine
    │
    ├── Domain Recognizers
    │
    ├── Secret Scanner
    │
    ├── Policy Engine
    │
    ├── Token Manager
    │
    └── Privacy Verification Classifier
    │
    ▼
AI Provider Adapter
    │
    ├── OpenAI
    ├── Anthropic
    ├── Mistral
    ├── Azure AI
    └── other providers
```

This keeps the privacy layer provider-agnostic.

---

# 32. Deployment Model

The proxy could potentially be distributed as:

### Local daemon

```text
localhost:PORT
```

Applications send AI requests through it.

### Docker container

```text
application
    ↓
privacy-proxy
    ↓
cloud-LLM
```

This would be particularly attractive for SMBs.

### SDK

Example:

```java
AiResponse response =
    privacyProxy.process(request);
```

### Network gateway

```text
company network
      ↓
AI privacy gateway
      ↓
external AI providers
```

This would allow multiple internal applications to share the same privacy infrastructure.

---

# 33. Hardware Requirements

One of the core product goals should be:

> No dedicated GPU required.

A stack consisting of:

- regex
- deterministic parsers
- small NER models
- local dictionaries
- lightweight classification

should realistically run on ordinary office hardware.

Potential environments include:

- mini PCs
- NAS devices
- ordinary servers
- developer machines
- small customer-operated VMs

This is fundamentally different from deploying a capable local generative model.

---

# 34. Testing Strategy

The project lives or dies based on detection and verification quality.

The most important metric is not generic model accuracy.

It is closer to:

> Probability that identifying information escapes the privacy boundary.

A test corpus should include:

- German emails
- English emails
- mixed-language emails
- Austrian names
- international names
- addresses
- malformed phone numbers
- forwarded email chains
- signatures
- quoted emails
- customer IDs
- invoices
- typos
- unusual formatting
- successful anonymizations
- deliberately broken anonymizations
- indirect identifier combinations

Metrics should separately measure:

## False negatives

Identifying information that survives sanitization and is classified as safe.

This is the dangerous category.

## False positives

Safe payloads that are classified as unsafe.

This reduces usability and may cause unnecessary escalation.

The engineering objective is therefore:

```text
minimize false negatives
```

while maintaining acceptable:

```text
semantic preservation
latency
false-positive rate
```

---

# 35. Classifier Benchmarking

For the verification classifier, **overall accuracy is not a sufficient metric**.

A model with:

```text
99.8% accuracy
```

could still be unsuitable if the remaining failures are disproportionately privacy leaks.

More relevant metrics include:

- PII / identifiability recall
- false-negative rate
- precision
- false-positive rate
- AUROC / PR-AUC
- calibration quality
- latency
- RAM consumption
- CPU utilization
- German-language performance
- robustness to malformed text
- robustness to domain shift

The desired profile may look more like:

```text
PII recall:               extremely high
false-negative rate:      extremely low
false-positive rate:      tolerable
CPU latency:              low
RAM:                      modest
```

For this application, false positives are generally less damaging than false negatives.

A false positive may cause:

- another local pass
- human review
- unnecessary redaction

A false negative may cause identifying information to cross the privacy boundary.

---

# 36. Potential Failures

Important examples include:

## Signature blocks

```text
Best regards,
Sarah Leitner
Managing Director
Example GmbH
+43 660 ...
```

Very dense PII.

## Forwarded emails

Multiple people may appear in one message.

## Quoted correspondence

Historical identifiers may remain far below the newest email.

## Names that are normal words

Examples:

```text
Rose
Summer
Hunter
May
```

## Addresses without obvious syntax

> I live opposite the church on Hauptstraße.

## Public figures

A name may be recognizable from public data even without additional identifiers.

## Rare combinations

A profession + tiny municipality + organization may sometimes make somebody identifiable even after their name is removed.

These edge cases are where a contextual re-identification classifier may become especially valuable.

---

# 37. Optional Escalation Layer: Small Local Semantic Model

If deterministic detection + NER + specialist verification prove insufficient, a small local semantic model could act as an escalation layer.

Its task would not be:

> understand and answer the customer email.

Its task would only be:

> Does this sanitized text still contain information that could reasonably identify a natural person?

This is a much narrower ML problem than general-purpose language generation.

A specialist classifier or compact encoder is preferable if it performs well enough.

---

# 38. Re-Identification Testing

A particularly interesting defensive technique is to explicitly test the sanitized result.

The proxy could ask a local classifier:

> Given only this sanitized text, how much identifying information remains?

This creates a second-stage privacy check:

```text
Detection
    ↓
Tokenization
    ↓
Re-identification-risk analysis
    ↓
Cloud transmission
```

High-risk outputs could be:

- further sanitized
- rejected
- escalated for human review
- routed through a stronger local model

This turns the privacy layer into a measurable risk pipeline rather than simply trusting one NER pass.

---

# 39. Product-Level Insight

The email agent itself may not ultimately be the interesting product.

The more general architecture is:

> A local privacy boundary between enterprise data and external AI systems.

Applications would communicate with:

```text
Privacy Proxy API
```

instead of directly communicating with:

```text
AI Provider API
```

The proxy could eventually handle:

- PII detection
- pseudonymization
- secret detection
- post-sanitization verification
- policy enforcement
- provider routing
- audit logging
- request classification
- data-residency rules
- model allowlists
- retention policies

That potentially turns it into a lightweight **AI privacy gateway**.

---

# 40. Initial Prototype Recommendation

The first prototype should deliberately remain small.

Suggested stack:

```text
Input
  ↓
Regex recognizers
  ↓
Microsoft Presidio / spaCy NER
  ↓
Austrian/DACH custom recognizers
  ↓
Ephemeral token mapper
  ↓
Local privacy verification classifier
  ↓
Cloud LLM
  ↓
Local rehydration
```

The verification classifier should initially be benchmarked across several model families rather than committing prematurely to one architecture.

Candidates:

- Laya fine-tune
- ModernBERT / DeBERTa classifier
- multilingual BERT-style classifier
- NLI classifier
- embedding + logistic regression
- cross-encoder

Do not initially build:

- a large local generative LLM
- elaborate cryptography
- distributed architecture
- persistent identity mappings
- complex admin interfaces
- generalized workflow orchestration

The important hypotheses to test first are:

> Can identifying information be reliably removed from real-world German-language customer-support emails while preserving enough semantic information for a cloud LLM to perform useful work?

and:

> Can an independent lightweight local classifier reliably detect when that privacy transformation has failed?

If both answers are yes, the architecture becomes substantially more robust.

---

# 41. Key Open Questions

1. How accurately can lightweight NER detect German and Austrian names and addresses?

2. How much does anonymization degrade downstream LLM performance?

3. Which identifiers require deterministic recognizers rather than NER?

4. How should entity relationships be preserved across multi-step agent workflows?

5. At what point does contextual information itself create meaningful re-identification risk?

6. Which classifier architecture provides the lowest false-negative rate on sanitized German business text?

7. How well can a verifier trained on deliberately broken anonymizations generalize to real-world failures?

8. How should the system behave when the verifier is uncertain?

9. How should forwarded messages, signatures, attachments, and quoted email history be processed?

10. Can the entire system remain performant on ordinary CPU-only SMB hardware?

11. How should thresholds differ by workflow risk level?

12. How much synthetic training data is required before real-world data becomes the limiting factor?

13. Can "safe vs unsafe after sanitization" be learned more reliably than generic "PII vs no PII"?

---

# 42. Working Principle

The core idea can be summarized as:

> **Keep identity local. Send semantics to the AI. Verify before anything leaves.**

Instead of attempting to run the entire AI workload locally, the system locally performs only the privacy-sensitive operations for which deterministic algorithms and small specialist models may be sufficient:

- detection
- tokenization
- verification

The computationally expensive reasoning can then remain with cloud AI providers.

That asymmetry is potentially the central advantage of the architecture.
