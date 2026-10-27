//! Persistent-dataset sequences (M4 spec §13.1): repeated first names across
//! different people, long threads, growing known-entity state, cache hits,
//! restart, rotation, and grace expiry, with labeled ambiguity cases and the
//! "zero wrong-person restoration" metric (plan 4a Task 6).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use inumaki_core::token::{normalize, parse_token};
use serde::{Deserialize, Serialize};

use crate::corpus::Doc;
use crate::data;
use crate::generate::{Builder, Lists, Person, de_neutral_body, values_for};
use crate::metrics::{EvalOptions, EvalOutcome, Report, Sanitizer, doc_stats, latency};
use crate::rng::Rng;

/// Something the runner does to the daemon state before a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SeqEvent {
    /// Drop the state and reopen the same data directory.
    Restart,
    /// Rotate the dataset's epoch.
    Rotate,
    /// Move the vault clock forward.
    AdvanceClock {
        /// Seconds.
        secs: u64,
    },
    /// One sweeper pass.
    Sweep,
}

/// What a step tests; see the plan's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum SeqLabel {
    /// A full name in the body, the bare first name in the closing: linked in the document.
    FullThenBare,
    /// Only the bare first name of a recent, unambiguous person.
    BareRecentSame,
    /// Only the bare first name of a person never seen in full, who shares
    /// the first name with exactly one recent person.
    BareRecentOther,
    /// Only a bare first name, after the recency window has passed.
    BareBeyondWindow,
    /// Only a bare first name shared by two or more recent persons.
    Ambiguous,
    /// A bare surname of a recent person whose surname no other recent person has.
    SurnameRecentSame,
    /// A bare surname of a person who is not recent but shares it with one who is.
    SurnameRecentOther,
    /// `Frau {LAST}` of a recent person: the NER reads the title and the
    /// surname as one two-word PERSON span, which the linker never joins to
    /// an entity (it links single-word mentions). Expected: own entity in
    /// every setting; measured next to the bare-surname labels so the
    /// surname gates are not vacuous and the titled form stays visible.
    SurnameTitled,
    /// A document without person mentions.
    Plain,
    /// An earlier step's text again.
    Repeat,
    /// The first full-name document after a rotation.
    AfterRotation,
}

/// One document of a sequence.
pub struct SeqStep {
    /// The document; PERSON gold spans carry `entity = "p<i>"`.
    pub doc: Doc,
    /// Expected linker behaviour.
    pub label: SeqLabel,
    /// Events applied before this step, in order.
    pub before: Vec<SeqEvent>,
    /// For `Repeat`: the step whose text is sent again.
    pub repeat_of: Option<usize>,
    /// For `Repeat`: the repeated step ran in this process lifetime and
    /// epoch (no `Restart`/`Rotate` in between), so a cache hit is expected.
    pub expect_cached: bool,
}

impl std::fmt::Debug for SeqStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeqStep")
            .field("id", &self.doc.id)
            .field("label", &self.label)
            .field("before", &self.before)
            .finish()
    }
}

/// Generator options.
#[derive(Debug, Clone)]
pub struct SequenceOptions {
    /// Seed (default 777; never the tuning or held-out seeds).
    pub seed: u64,
    /// Distinct persons (default 40) drawn from 12 first names and 30 surnames.
    pub persons: usize,
    /// Steps (default 300).
    pub steps: usize,
    /// Grace period the dataset was created with (default 7).
    pub grace_days: u32,
    /// Steps a `Restart` precedes (default 100 and 200).
    pub restart_at: Vec<usize>,
    /// The step a `Rotate` precedes (default 150; `None` for no rotation).
    pub rotate_at: Option<usize>,
    /// A `Repeat` every this many steps (default 20).
    pub repeat_every: usize,
}

impl Default for SequenceOptions {
    fn default() -> Self {
        SequenceOptions {
            seed: 777,
            persons: 40,
            steps: 300,
            grace_days: 7,
            restart_at: vec![100, 200],
            rotate_at: Some(150),
            repeat_every: 20,
        }
    }
}

impl SequenceOptions {
    /// The default shape scaled to `steps`: restarts at a third and two
    /// thirds, the rotation in the middle, a repeat every fifteenth step.
    /// For 300 steps this is exactly [`SequenceOptions::default`]; the short
    /// runs of the CLI tests keep every event.
    pub fn scaled(steps: usize) -> Self {
        SequenceOptions {
            steps,
            restart_at: vec![steps / 3, 2 * steps / 3],
            rotate_at: Some(steps / 2),
            repeat_every: (steps / 15).max(2),
            ..SequenceOptions::default()
        }
    }
}

const FIRST_POOL: usize = 12;
const LAST_POOL: usize = 30;
const WINDOW_SECS: u64 = 31 * 60;

const BODY_WITH_PERSON: &[&str] = &[
    "mein Name ist {PERSON}, Kundennummer {CUSTOMER_ID}. Bitte prüfen Sie die Rechnung {INVOICE_ID}.",
    "ich bin {PERSON} und habe eine Frage zum Vertrag {CONTRACT_ID} vom {DATE}.",
    "hier schreibt {PERSON}. Die Lieferung an {STREET}, {ZIP_CITY} ist nicht angekommen.",
];
/// The surname stands alone. The NER profiles read `Frau Leitner` as one
/// two-word PERSON span, which the linker never joins to an entity (it links
/// single-word mentions), so a titled body alone would make the surname labels
/// vacuous: these bodies exercise the cross-request surname path.
const BODY_SURNAME: &[&str] = &[
    "wie mit {LAST} besprochen, geht es um die Rechnung {INVOICE_ID}.",
    "Rückfrage zu {LAST} bezüglich des Vertrags {CONTRACT_ID}.",
];
/// The titled form (`SeqLabel::SurnameTitled`): measured, never linked.
const BODY_TITLED: &[&str] = &[
    "Frau {LAST} hat mich gebeten, Ihnen das weiterzuleiten. Es geht um die Rechnung {INVOICE_ID}.",
    "Herr {LAST} bittet um Rückruf wegen des Vertrags {CONTRACT_ID}.",
];
const CLOSING_FIRST: &[&str] = &[
    "LG {FIRST}",
    "Viele Grüße\n{FIRST}",
    "Danke und liebe Grüße\n{FIRST}",
];
const CLOSING_NONE: &[&str] = &["Vielen Dank im Voraus.", "Danke für Ihre Hilfe."];

struct Cast {
    persons: Vec<Person>,
}

impl Cast {
    /// `n` persons with pairwise different full names (two people with one
    /// full name would share a token legitimately and read as a wrong link).
    fn build(rng: &mut Rng, l: &Lists, n: usize) -> Cast {
        let firsts: Vec<&str> = (0..FIRST_POOL).map(|_| *rng.pick(l.first)).collect();
        let lasts: Vec<&str> = (0..LAST_POOL).map(|_| *rng.pick(l.last)).collect();
        let mut persons: Vec<Person> = Vec::with_capacity(n);
        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut tries = 0;
        while persons.len() < n && tries < 100 * n {
            tries += 1;
            let first = *rng.pick(&firsts);
            let last = *rng.pick(&lasts);
            let domain = *rng.pick(l.domains);
            if seen.insert((
                normalize(first).as_str().to_string(),
                normalize(last).as_str().to_string(),
            )) {
                persons.push(Person::new(first, last, domain));
            }
        }
        Cast { persons }
    }
    fn first(&self, i: usize) -> &str {
        &self.persons[i].first
    }
    fn last(&self, i: usize) -> &str {
        &self.persons[i].last
    }
}

fn build(
    rng: &mut Rng,
    l: &Lists,
    cast: &Cast,
    i: usize,
    idx: usize,
    body: &str,
    closing: &str,
) -> Doc {
    let n = cast.persons.len();
    let domain = *rng.pick(l.domains);
    let p = Person::new(cast.first(i), cast.last(i), domain);
    let domain2 = *rng.pick(l.domains);
    let p2 = Person::new(cast.first((i + 1) % n), cast.last((i + 1) % n), domain2);
    let v = values_for(rng, l, p, p2);
    let mut b = Builder::new(false);
    b.fill(rng.pick::<&str>(data::DE_GREETINGS), &v);
    b.lit("\n\n");
    b.fill(body, &v);
    b.lit("\n\n");
    b.fill(closing, &v);
    let mut doc = b.into_doc(format!("seq-{idx:05}"), "de");
    for g in doc.spans.iter_mut().filter(|g| g.kind == "PERSON") {
        g.entity = Some(format!("p{i}"));
    }
    doc
}

/// Deterministic sequence corpus.
pub fn generate_sequence(o: &SequenceOptions) -> Vec<SeqStep> {
    let mut rng = Rng::new(o.seed);
    let l = Lists::tuning();
    let cast = Cast::build(&mut rng, &l, o.persons.max(4));
    let n = cast.persons.len();
    let mut steps: Vec<SeqStep> = Vec::with_capacity(o.steps);
    // the person whose full name a step's document carries (repeats inherit it)
    let mut full_person: Vec<Option<usize>> = Vec::with_capacity(o.steps);
    // persons whose full name was sanitized since the last clock advance,
    // restart or rotation (the daemon's recency window), in order of first
    // appearance. A step that goes through the engine puts its persons back
    // in the window; a cache hit does not.
    let mut recent: Vec<usize> = Vec::new();
    let by_first = |recent: &[usize], first: &str| -> Vec<usize> {
        recent
            .iter()
            .copied()
            .filter(|&j| normalize(cast.first(j)) == normalize(first))
            .collect()
    };
    let by_last = |recent: &[usize], last: &str| -> Vec<usize> {
        recent
            .iter()
            .copied()
            .filter(|&j| normalize(cast.last(j)) == normalize(last))
            .collect()
    };
    // first step of the current process lifetime and epoch (cache scope)
    let mut cache_epoch_start = 0usize;
    for idx in 0..o.steps {
        let mut before = Vec::new();
        if o.restart_at.contains(&idx) {
            before.push(SeqEvent::Restart);
            recent.clear(); // the working set is gone with the process
            cache_epoch_start = idx;
        }
        let rotation = o.rotate_at == Some(idx);
        if rotation {
            before.push(SeqEvent::Rotate);
            recent.clear();
            cache_epoch_start = idx;
        }
        if idx + 1 == o.steps {
            before.push(SeqEvent::AdvanceClock {
                secs: u64::from(o.grace_days) * 86_400 + 60,
            });
            before.push(SeqEvent::Sweep);
            recent.clear();
        }
        // persons a bare-first-name step can honestly be about
        let unique_first: Vec<usize> = recent
            .iter()
            .copied()
            .filter(|&j| by_first(&recent, cast.first(j)).len() == 1)
            .collect();
        let unique_last: Vec<usize> = recent
            .iter()
            .copied()
            .filter(|&j| by_last(&recent, cast.last(j)).len() == 1)
            .collect();
        let first_other: Vec<usize> = (0..n)
            .filter(|&j| !recent.contains(&j) && by_first(&recent, cast.first(j)).len() == 1)
            .collect();
        let last_other: Vec<usize> = (0..n)
            .filter(|&j| !recent.contains(&j) && by_last(&recent, cast.last(j)).len() == 1)
            .collect();
        let sharers: Vec<usize> = recent
            .iter()
            .copied()
            .filter(|&j| by_first(&recent, cast.first(j)).len() >= 2)
            .collect();
        let mut choices: Vec<SeqLabel> = vec![
            SeqLabel::FullThenBare,
            SeqLabel::FullThenBare,
            SeqLabel::Plain,
        ];
        if rotation {
            choices = vec![SeqLabel::AfterRotation];
        } else if o.repeat_every > 0 && idx >= o.repeat_every && idx % o.repeat_every == 0 {
            choices = vec![SeqLabel::Repeat];
        } else {
            if !unique_first.is_empty() {
                choices.push(SeqLabel::BareRecentSame);
            }
            if !unique_last.is_empty() {
                choices.push(SeqLabel::SurnameRecentSame);
                choices.push(SeqLabel::SurnameTitled);
            }
            // a window advance forgets every recent person: rare, so the
            // recent set can grow enough for first names to collide
            if !recent.is_empty() && rng.chance(0.3) {
                choices.push(SeqLabel::BareBeyondWindow);
            }
            if !first_other.is_empty() {
                choices.push(SeqLabel::BareRecentOther);
            }
            if !last_other.is_empty() {
                choices.push(SeqLabel::SurnameRecentOther);
            }
            if !sharers.is_empty() {
                choices.push(SeqLabel::Ambiguous);
                choices.push(SeqLabel::Ambiguous);
            }
        }
        let label = *rng.pick(&choices);
        let (i, body, closing): (usize, &str, &str) = match label {
            SeqLabel::FullThenBare | SeqLabel::AfterRotation => {
                // half the time a person who shares a first name with a recent
                // one, so ambiguity cases arise without a hand-built script
                let sharing: Vec<usize> = (0..n)
                    .filter(|&j| {
                        !recent.contains(&j) && !by_first(&recent, cast.first(j)).is_empty()
                    })
                    .collect();
                let i = if !sharing.is_empty() && rng.chance(0.5) {
                    *rng.pick(&sharing)
                } else {
                    rng.below(n)
                };
                (i, *rng.pick(BODY_WITH_PERSON), *rng.pick(CLOSING_FIRST))
            }
            SeqLabel::BareRecentSame => (
                *rng.pick(&unique_first),
                de_neutral_body(&mut rng, &l),
                *rng.pick(CLOSING_FIRST),
            ),
            SeqLabel::BareRecentOther => (
                *rng.pick(&first_other),
                de_neutral_body(&mut rng, &l),
                *rng.pick(CLOSING_FIRST),
            ),
            SeqLabel::BareBeyondWindow => {
                let i = *rng.pick(&recent);
                before.push(SeqEvent::AdvanceClock { secs: WINDOW_SECS });
                recent.clear();
                (i, de_neutral_body(&mut rng, &l), *rng.pick(CLOSING_FIRST))
            }
            SeqLabel::Ambiguous => (
                // any sharer: the evaluator counts every surface token of this
                // label as a link, so which candidate a tie-break would prefer
                // (newest, oldest) does not matter
                *rng.pick(&sharers),
                de_neutral_body(&mut rng, &l),
                *rng.pick(CLOSING_FIRST),
            ),
            SeqLabel::SurnameTitled => (
                *rng.pick(&unique_last),
                *rng.pick(BODY_TITLED),
                *rng.pick(CLOSING_NONE),
            ),
            SeqLabel::SurnameRecentSame => (
                *rng.pick(&unique_last),
                *rng.pick(BODY_SURNAME),
                *rng.pick(CLOSING_NONE),
            ),
            SeqLabel::SurnameRecentOther => (
                *rng.pick(&last_other),
                *rng.pick(BODY_SURNAME),
                *rng.pick(CLOSING_NONE),
            ),
            SeqLabel::Plain => {
                let i = rng.below(n);
                (i, de_neutral_body(&mut rng, &l), *rng.pick(CLOSING_NONE))
            }
            SeqLabel::Repeat => {
                let of = rng.below(idx);
                let mut doc = steps[of].doc.clone();
                doc.id = format!("seq-{idx:05}");
                // the repeated step (itself a repeat or not) sanitized this text in
                // the current process lifetime and epoch
                let expect_cached = of >= cache_epoch_start;
                // A repeat the cache does not answer goes through the engine
                // again and puts its person back in the recency window (after
                // a restart or rotation: right away). A cache hit does not
                // touch the namespace's recency.
                let person = full_person[of];
                if !expect_cached {
                    if let Some(i) = person {
                        if !recent.contains(&i) {
                            recent.push(i);
                        }
                    }
                }
                full_person.push(person);
                steps.push(SeqStep {
                    doc,
                    label,
                    before,
                    repeat_of: Some(of),
                    expect_cached,
                });
                continue;
            }
        };
        let doc = build(&mut rng, &l, &cast, i, idx, body, closing);
        let full = matches!(label, SeqLabel::FullThenBare | SeqLabel::AfterRotation);
        full_person.push(full.then_some(i));
        if full && !recent.contains(&i) {
            recent.push(i);
        }
        steps.push(SeqStep {
            doc,
            label,
            before,
            repeat_of: None,
            expect_cached: false,
        });
    }
    steps
}

/// Per-label counts of a sequence run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LabelStats {
    /// Steps with this label.
    pub docs: usize,
    /// Released without reservation.
    pub accepted: usize,
    /// Released with an unconfirmed check.
    pub uncertain: usize,
    /// Withheld. A blocked step contributes no links: nothing crossed.
    pub blocked: usize,
    /// Accepted steps with residue.
    pub accepted_leak: usize,
    /// Surface tokens of PERSON mentions whose suffix was already known for
    /// the same gold entity: the linker joined a mention to an entity.
    pub links: usize,
    /// … for a *different* gold entity.
    pub wrong_links: usize,
    /// Entity tokens (no surface component) of PERSON mentions whose suffix
    /// was first minted for a different gold entity with the *same* mention
    /// text: two people with one bare first name share the text-keyed token,
    /// which is how tokens always worked and restores correctly. Reported,
    /// not gated.
    #[serde(default)]
    pub same_text_reuse: usize,
}

/// Sequence-level counts, next to the ordinary `Report`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SequenceStats {
    /// Steps run.
    pub steps: usize,
    /// `Restart` events applied.
    pub restarts: usize,
    /// `Rotate` events applied.
    pub rotations: usize,
    /// Cache hits over the whole run.
    pub cache_hits: u64,
    /// `Repeat` steps.
    pub repeats: usize,
    /// Repeats within one process lifetime and epoch (the only ones that can hit).
    pub repeats_expected_cached: usize,
    /// Repeats that raised the cache-hit counter.
    pub repeats_cached: usize,
    /// Per-label counts, keyed by the label's name.
    pub per_label: BTreeMap<String, LabelStats>,
    /// Wrong links in steps labeled `Ambiguous` (gate: zero).
    pub wrong_links_ambiguous: usize,
    /// Wrong links in steps labeled `SurnameRecentOther` (gate: zero; only
    /// reachable with `surnames_across_requests`).
    pub wrong_links_surname_other: usize,
    /// Wrong links over every label and across steps (a suffix first seen
    /// for another entity); includes the two gated counts above. Kept apart
    /// from `Report::links.wrong_links`, which sees one document at a time.
    #[serde(default)]
    pub wrong_links_cross_step: usize,
    /// Distinct tokens minted before the rotation, checked twice: during
    /// grace and after expiry.
    pub pre_rotation_tokens: usize,
    /// … of which still resolve during the grace period, checked on the warm
    /// handle just before the final clock advance (expected: all of them; a
    /// failure here breaks rehydration after a rotation).
    #[serde(default)]
    pub resolved_within_grace: usize,
    /// … of which no longer resolve after expiry and the sweep (expected:
    /// all of them).
    pub unresolved_after_grace: usize,
    /// Distinct tokens issued before the rotation that a document released
    /// after it carried again: the rotation did not give fresh tokens
    /// (expected: none).
    #[serde(default)]
    pub reused_after_rotation: usize,
    /// Events the runner could not apply (a failed restart invalidates the
    /// run), including a sweep that errored or expired no epoch after a
    /// rotation and a grace advance.
    #[serde(default)]
    pub event_failures: usize,
    /// Token lookups that failed with a vault error rather than finding
    /// nothing (filled by the runner that owns the store).
    #[serde(default)]
    pub restore_errors: usize,
}

/// Run `steps` in order through `s`, applying events through `on_event` and
/// reading the cache-hit counter through `cached`. The suffix → entity map
/// persists across steps (a stale link is a wrong link) and resets on
/// `Rotate`.
///
/// What counts as a link, and why (plan 4a Task 6):
///
/// * A token is keyed by its text: the same normalized text is the same
///   *entity* token whatever the linker does, so two people with the identical
///   bare first name share one. That is `same_text_reuse`, not a wrong link.
///   A *link* is the linker joining a mention to an entity, which it
///   emits as a surface token (`_xx` component) on the entity's suffix.
///   A surface token whose suffix was first seen for another entity is a wrong
///   link, and so is the same suffix behind two entity tokens with different
///   mention text.
/// * `Ambiguous`, `BareRecentOther` and `SurnameRecentOther` steps carry exactly
///   one bare mention and, under the default configuration, must not link at
///   all: *every* surface PERSON token in such a step is a link and counts as
///   wrong whatever the suffix history. A suffix-history rule alone would miss a
///   linker that breaks a tie by newest candidate (the token then matches the
///   gold entity) and a link to a suffix minted in a blocked step (a blocked
///   step releases nothing, so its suffixes are never recorded; the
///   vault minted them anyway).
/// * A blocked step contributes no link: nothing crossed.
///
/// Grace: right before the last step's events (a clock advance past the grace
/// period, then a sweep) every token minted before the rotation is restored
/// on the warm handle and must resolve; after the events it must not.
pub fn evaluate_sequence(
    s: &mut dyn Sanitizer,
    steps: &[SeqStep],
    opts: &EvalOptions,
    on_event: &mut dyn FnMut(&SeqEvent) -> Result<(), String>,
    cached: &mut dyn FnMut() -> u64,
) -> Report {
    let mut r = Report {
        profile: String::new(),
        docs: steps.len(),
        ..Default::default()
    };
    let mut seq = SequenceStats {
        steps: steps.len(),
        ..Default::default()
    };
    // suffix -> (gold entity, normalized text) of the first mention seen with it
    let mut suffix_entity: HashMap<String, (String, String)> = HashMap::new();
    let mut pre_rotation: BTreeSet<String> = BTreeSet::new();
    let mut reused: BTreeSet<String> = BTreeSet::new();
    let mut rotated = false;
    let mut rng = Rng::new(opts.seed);
    let mut times = Vec::with_capacity(steps.len());
    let last = steps.len().saturating_sub(1);
    for (idx, step) in steps.iter().enumerate() {
        // warm-handle grace check, before the events that expire the epoch
        if idx == last
            && rotated
            && step
                .before
                .iter()
                .any(|e| matches!(e, SeqEvent::AdvanceClock { .. }))
        {
            seq.resolved_within_grace = pre_rotation
                .iter()
                .filter(|t| s.restore(t).is_some())
                .count();
        }
        for e in &step.before {
            match e {
                SeqEvent::Restart => seq.restarts += 1,
                SeqEvent::Rotate => {
                    seq.rotations += 1;
                    suffix_entity.clear();
                    rotated = true;
                }
                _ => {}
            }
            if on_event(e).is_err() {
                seq.event_failures += 1;
            }
        }
        let hits_before = cached();
        let t = std::time::Instant::now();
        let outcome = s.process(&step.doc);
        times.push(t.elapsed().as_secs_f64() * 1000.0);
        // the counter restarts with the process: sum what each step added
        let step_hits = cached().saturating_sub(hits_before);
        seq.cache_hits += step_hits;
        let label = seq
            .per_label
            .entry(format!("{:?}", step.label))
            .or_default();
        label.docs += 1;
        if step.label == SeqLabel::Repeat {
            seq.repeats += 1;
            seq.repeats_expected_cached += usize::from(step.expect_cached);
            seq.repeats_cached += usize::from(step_hits > 0);
        }
        let ds = doc_stats(&mut r, s, &step.doc, &outcome, opts, &mut rng);
        label.accepted += usize::from(ds.accepted);
        label.uncertain += usize::from(ds.uncertain);
        label.blocked += usize::from(ds.blocked);
        label.accepted_leak += usize::from(ds.accepted && ds.leaked);
        // Only released text carries tokens; a blocked step has none.
        let (EvalOutcome::Pass { text, replaced } | EvalOutcome::PassUncertain { text, replaced }) =
            &outcome
        else {
            continue;
        };
        let single_bare_mention = matches!(
            step.label,
            SeqLabel::Ambiguous | SeqLabel::BareRecentOther | SeqLabel::SurnameRecentOther
        );
        for rp in replaced.iter().filter(|x| x.tokenized) {
            let Some(token) = text.get(rp.out_start..rp.out_end) else {
                continue;
            };
            if rotated {
                if pre_rotation.contains(token) {
                    reused.insert(token.to_string());
                }
            } else {
                pre_rotation.insert(token.to_string());
            }
            if rp.kind != "PERSON" {
                continue;
            }
            let Some(p) = parse_token(s.token_settings(), token) else {
                continue;
            };
            let Some(e) = step
                .doc
                .spans
                .iter()
                .find(|g| g.kind == "PERSON" && rp.start <= g.start && g.end <= rp.end)
                .and_then(|g| g.entity.as_ref())
            else {
                continue;
            };
            let surface = p.variant.is_some();
            let text_key = normalize(&step.doc.text[rp.start..rp.end])
                .as_str()
                .to_string();
            let wrong = if surface && single_bare_mention {
                label.links += 1;
                true
            } else {
                match suffix_entity.get(p.suffix) {
                    Some((prev, _)) if prev == e => {
                        label.links += usize::from(surface);
                        false
                    }
                    // an entity token is keyed by its text: the same text for
                    // two people is one token and restores correctly, not a link
                    Some((_, prev_text)) if !surface && *prev_text == text_key => {
                        label.same_text_reuse += 1;
                        false
                    }
                    Some(_) => {
                        label.links += usize::from(surface);
                        true
                    }
                    // A surface token whose parent was never seen released (its
                    // document was blocked) says nothing about who owns the
                    // suffix: registering this mention would make the parent's
                    // own later, correct mentions read as wrong links.
                    None if surface => false,
                    None => {
                        suffix_entity.insert(p.suffix.to_string(), (e.clone(), text_key));
                        false
                    }
                }
            };
            if wrong {
                label.wrong_links += 1;
                seq.wrong_links_cross_step += 1;
                match step.label {
                    SeqLabel::Ambiguous => seq.wrong_links_ambiguous += 1,
                    SeqLabel::SurnameRecentOther => seq.wrong_links_surname_other += 1,
                    _ => {}
                }
            }
        }
    }
    // Grace expiry: the last step's events advanced past the grace period and
    // swept, so a token of the closed epoch must no longer resolve.
    if rotated {
        seq.pre_rotation_tokens = pre_rotation.len();
        seq.unresolved_after_grace = pre_rotation
            .iter()
            .filter(|t| s.restore(t).is_none())
            .count();
        seq.reused_after_rotation = reused.len();
    }
    r.latency_ms = latency(&times);
    r.sequence = Some(seq);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_deterministic_and_covers_every_label() {
        let o = SequenceOptions::default();
        let a = generate_sequence(&o);
        let b = generate_sequence(&o);
        assert_eq!(a.len(), 300);
        assert_eq!(
            a.iter().map(|s| s.doc.text.clone()).collect::<Vec<_>>(),
            b.iter().map(|s| s.doc.text.clone()).collect::<Vec<_>>()
        );
        let mut labels: std::collections::BTreeSet<SeqLabel> = a.iter().map(|s| s.label).collect();
        for l in [
            SeqLabel::FullThenBare,
            SeqLabel::BareRecentSame,
            SeqLabel::BareRecentOther,
            SeqLabel::BareBeyondWindow,
            SeqLabel::Ambiguous,
            SeqLabel::SurnameRecentSame,
            SeqLabel::SurnameRecentOther,
            SeqLabel::SurnameTitled,
            SeqLabel::Plain,
            SeqLabel::Repeat,
            SeqLabel::AfterRotation,
        ] {
            assert!(labels.remove(&l), "missing {l:?}");
        }
        assert!(labels.is_empty());
        for s in &a {
            s.doc.validate().unwrap_or_else(|e| panic!("{e}"));
            for g in s.doc.spans.iter().filter(|g| g.kind == "PERSON") {
                assert!(
                    g.entity.as_deref().is_some_and(|e| e.starts_with('p')),
                    "{}",
                    s.doc.id
                );
            }
        }
        assert_eq!(
            a.iter()
                .filter(|s| s.before.contains(&SeqEvent::Restart))
                .count(),
            2
        );
        assert_eq!(
            a.iter()
                .filter(|s| s.before.contains(&SeqEvent::Rotate))
                .count(),
            1
        );
        assert!(
            a.last()
                .unwrap()
                .before
                .iter()
                .any(|e| matches!(e, SeqEvent::AdvanceClock { secs } if *secs > 7 * 86400))
        );
        assert_eq!(a.last().unwrap().before.last(), Some(&SeqEvent::Sweep));
        let rep = a.iter().find(|s| s.label == SeqLabel::Repeat).unwrap();
        assert_eq!(rep.doc.text, a[rep.repeat_of.unwrap()].doc.text);
        // a repeat across a restart or rotation is not expected to hit the cache
        let r100 = &a[100];
        assert_eq!(r100.label, SeqLabel::Repeat);
        assert!(!r100.expect_cached, "step 100 restarts first");
        assert!(
            a.iter()
                .any(|s| s.label == SeqLabel::Repeat && s.expect_cached)
        );
        // the recent set resets on restart: no BareRecentSame right after one
        assert_ne!(a[101].label, SeqLabel::BareRecentSame);
        // an ambiguous step really has two recent persons with the first name
        let amb = a
            .iter()
            .position(|s| s.label == SeqLabel::Ambiguous)
            .unwrap();
        let first = a[amb]
            .doc
            .spans
            .iter()
            .find(|g| g.kind == "PERSON")
            .map(|g| a[amb].doc.text[g.start..g.end].to_string())
            .unwrap();
        let recent_full: Vec<&str> = a[..amb]
            .iter()
            .rev()
            .take_while(|s| {
                !s.before
                    .iter()
                    .any(|e| matches!(e, SeqEvent::AdvanceClock { .. }))
            })
            .flat_map(|s| {
                s.doc
                    .spans
                    .iter()
                    .filter(|g| g.kind == "PERSON")
                    .map(|g| &s.doc.text[g.start..g.end])
            })
            .filter(|t| t.split_whitespace().count() == 2)
            .collect();
        let mut entities: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for t in recent_full.iter().filter(|t| t.starts_with(&first)) {
            entities.insert(t);
        }
        assert!(entities.len() >= 2, "{first}: {entities:?}");
    }

    /// The labels are honest by construction: a BareRecentSame names a
    /// recent person with a first name no other recent person has, a
    /// BareRecentOther or SurnameRecentOther names a person who is not
    /// recent but shares the part with exactly one who is, and an Ambiguous
    /// step names a first name two recent persons have. A repeat the cache
    /// does not answer puts its person back in the recency window.
    #[test]
    fn labels_are_honest_about_who_is_recent() {
        let a = generate_sequence(&SequenceOptions::default());
        // (entity, full name) of the persons in the window since the last reset
        let mut recent: Vec<(String, String)> = Vec::new();
        let (mut same, mut other, mut amb, mut repeat_back) = (0, 0, 0, 0);
        for s in &a {
            if s.before.iter().any(|e| {
                matches!(
                    e,
                    SeqEvent::Restart | SeqEvent::Rotate | SeqEvent::AdvanceClock { .. }
                )
            }) {
                recent.clear();
            }
            let spans: Vec<&crate::corpus::GoldSpan> =
                s.doc.spans.iter().filter(|g| g.kind == "PERSON").collect();
            let entity = spans.first().and_then(|g| g.entity.clone());
            let mention = spans
                .first()
                .map(|g| s.doc.text[g.start..g.end].to_string());
            let with_first = |first: &str| {
                recent
                    .iter()
                    .filter(|(_, full)| full.split(' ').next() == Some(first))
                    .count()
            };
            let with_last = |last: &str| {
                recent
                    .iter()
                    .filter(|(_, full)| full.split(' ').nth(1) == Some(last))
                    .count()
            };
            let is_recent = |e: &str| recent.iter().any(|(r, _)| r == e);
            match (s.label, entity, mention) {
                (SeqLabel::BareRecentSame, Some(e), Some(first)) => {
                    same += 1;
                    assert!(is_recent(&e), "{}", s.doc.id);
                    assert_eq!(with_first(&first), 1, "{}", s.doc.id);
                }
                (SeqLabel::BareRecentOther, Some(e), Some(first)) => {
                    other += 1;
                    assert!(!is_recent(&e), "{}", s.doc.id);
                    assert_eq!(with_first(&first), 1, "{}", s.doc.id);
                }
                (SeqLabel::Ambiguous, _, Some(first)) => {
                    amb += 1;
                    assert!(with_first(&first) >= 2, "{}", s.doc.id);
                }
                (SeqLabel::SurnameRecentSame | SeqLabel::SurnameTitled, Some(e), Some(last)) => {
                    assert!(is_recent(&e), "{}", s.doc.id);
                    assert_eq!(with_last(&last), 1, "{}", s.doc.id);
                }
                (SeqLabel::SurnameRecentOther, Some(e), Some(last)) => {
                    assert!(!is_recent(&e), "{}", s.doc.id);
                    assert_eq!(with_last(&last), 1, "{}", s.doc.id);
                }
                (SeqLabel::FullThenBare | SeqLabel::AfterRotation, Some(e), Some(full)) => {
                    assert_eq!(spans.len(), 2, "full name, then the bare first name");
                    assert!(full.contains(' '));
                    if !is_recent(&e) {
                        recent.push((e, full));
                    }
                }
                (SeqLabel::Repeat, Some(e), Some(full))
                    if !s.expect_cached && full.contains(' ') && !is_recent(&e) =>
                {
                    repeat_back += 1;
                    recent.push((e, full));
                }
                _ => {}
            }
        }
        assert!(same > 0 && other > 0 && amb > 0);
        assert!(
            repeat_back > 0,
            "an uncached repeat must put its person back in the window at least once"
        );
    }

    /// How the scripted store mints tokens for PERSON mentions.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        /// Entity token per distinct mention text; a bare first name after the
        /// same person's full name in one document is a surface token of the
        /// full name's suffix. What a correct linker with every cross-request
        /// flag off emits.
        Correct,
        /// One suffix per first name (persons sharing a first name share it).
        ByFirst,
        /// A bare mention is always a surface token of the true person's
        /// suffix: a linker that breaks ties by "newest candidate" and happens
        /// to pick the right person.
        AlwaysLink,
    }

    /// A scripted store: mints per `mode`, remembers what restores, and can
    /// forget like an expired (or prematurely dropped) epoch.
    struct Scripted {
        settings: inumaki_core::config::TokenSettings,
        /// token -> (original, epoch it was minted in)
        restore: std::collections::HashMap<String, (String, u32)>,
        mode: Mode,
        /// Block every document that mentions a full name (two words).
        block_full: bool,
        /// Put the epoch in the token key (fresh tokens after a rotation).
        epoch_in_key: bool,
        /// Epoch counter and grace flag the test's event hook drives.
        epoch: std::rc::Rc<std::cell::Cell<u32>>,
        expired: std::rc::Rc<std::cell::Cell<bool>>,
        /// Forget tokens of closed epochs once `expired` is set (what the
        /// vault's sweep does after the grace period).
        forget_closed: bool,
        /// Forget tokens of closed epochs as soon as the epoch changes (a
        /// vault that drops them before the grace period ends).
        forget_on_rotate: bool,
        blocked_every: usize,
        seen: usize,
    }

    impl Scripted {
        fn new(mode: Mode) -> Self {
            Scripted {
                settings: inumaki_core::config::TokenSettings::default(),
                restore: Default::default(),
                mode,
                block_full: false,
                epoch_in_key: true,
                epoch: Default::default(),
                expired: Default::default(),
                forget_closed: false,
                forget_on_rotate: false,
                blocked_every: 0,
                seen: 0,
            }
        }
        fn suffix(&self, key: &str) -> String {
            let key = if self.epoch_in_key {
                format!("{key}@{}", self.epoch.get())
            } else {
                key.to_string()
            };
            format!(
                "{:06x}",
                key.bytes()
                    .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)))
                    & 0xff_ffff
            )
        }
        /// The event hook the sequence runner calls: drives epoch and expiry.
        fn on_event(&self) -> impl FnMut(&SeqEvent) -> Result<(), String> + use<> {
            let (epoch, expired) = (self.epoch.clone(), self.expired.clone());
            move |e: &SeqEvent| {
                match e {
                    SeqEvent::Rotate => epoch.set(epoch.get() + 1),
                    SeqEvent::AdvanceClock { secs } if *secs > 7 * 86_400 => expired.set(true),
                    _ => {}
                }
                Ok(())
            }
        }
    }

    impl Sanitizer for Scripted {
        fn detect(
            &mut self,
            _: &str,
        ) -> Result<Vec<inumaki_core::span::Span>, crate::metrics::DetectFailed> {
            Ok(Vec::new())
        }
        fn process(&mut self, doc: &Doc) -> EvalOutcome {
            use crate::metrics::Replaced;
            self.seen += 1;
            let has_full = doc
                .spans
                .iter()
                .any(|g| g.kind == "PERSON" && doc.text[g.start..g.end].contains(' '));
            if (self.block_full && has_full)
                || (self.blocked_every > 0 && self.seen % self.blocked_every == 0)
            {
                return EvalOutcome::Blocked;
            }
            let mut text = String::new();
            let mut replaced = Vec::new();
            let mut cur = 0;
            let mut full_suffix: Option<(String, String)> = None; // (entity, suffix)
            for g in &doc.spans {
                if g.kind != "PERSON" {
                    continue;
                }
                text.push_str(&doc.text[cur..g.start]);
                let mention = &doc.text[g.start..g.end];
                let entity = g.entity.clone().unwrap();
                let full = mention.contains(' ');
                let tok = match self.mode {
                    Mode::ByFirst => {
                        let first = mention.split_whitespace().next().unwrap().to_lowercase();
                        let suffix = self.suffix(&first);
                        if full {
                            format!("<PERSON_{suffix}>")
                        } else {
                            format!("<PERSON_{suffix}_3e>")
                        }
                    }
                    Mode::AlwaysLink => {
                        let suffix = self.suffix(&entity);
                        if full {
                            format!("<PERSON_{suffix}>")
                        } else {
                            format!("<PERSON_{suffix}_3e>")
                        }
                    }
                    Mode::Correct => {
                        if full {
                            let suffix = self.suffix(&entity);
                            full_suffix = Some((entity.clone(), suffix.clone()));
                            format!("<PERSON_{suffix}>")
                        } else if let Some((e, suffix)) = &full_suffix {
                            assert_eq!(*e, entity);
                            format!("<PERSON_{suffix}_3e>")
                        } else {
                            // text-keyed entity token: the same bare text is the same token
                            format!("<PERSON_{}>", self.suffix(&mention.to_lowercase()))
                        }
                    }
                };
                self.restore
                    .insert(tok.clone(), (mention.to_string(), self.epoch.get()));
                let s = text.len();
                text.push_str(&tok);
                replaced.push(Replaced {
                    start: g.start,
                    end: g.end,
                    out_start: s,
                    out_end: text.len(),
                    kind: "PERSON".into(),
                    tokenized: true,
                });
                cur = g.end;
            }
            text.push_str(&doc.text[cur..]);
            EvalOutcome::Pass { text, replaced }
        }
        fn restore(&mut self, token: &str) -> Option<String> {
            let (original, epoch) = self.restore.get(token)?;
            let closed = *epoch < self.epoch.get();
            if closed && (self.forget_on_rotate || (self.forget_closed && self.expired.get())) {
                return None;
            }
            Some(original.clone())
        }
        fn token_settings(&self) -> &inumaki_core::config::TokenSettings {
            &self.settings
        }
        fn verifier(&self) -> Option<std::sync::Arc<dyn inumaki_core::verify::Verifier>> {
            None
        }
    }

    fn quiet() -> EvalOptions {
        EvalOptions {
            verifier_trials: false,
            ..EvalOptions::default()
        }
    }

    #[test]
    fn evaluate_sequence_counts_labels_events_and_wrong_links() {
        // Tokens keyed by first name: persons sharing a first name share a
        // suffix, which is exactly the mistake the ambiguity gate catches.
        let steps = generate_sequence(&SequenceOptions {
            steps: 120,
            ..SequenceOptions::default()
        });
        let mut s = Scripted::new(Mode::ByFirst);
        let mut events = Vec::new();
        let mut hits = 0u64;
        let r = evaluate_sequence(
            &mut s,
            &steps,
            &quiet(),
            &mut |e| {
                events.push(e.clone());
                Ok(())
            },
            &mut || {
                hits += 1;
                hits
            },
        );
        let seq = r.sequence.as_ref().unwrap();
        assert_eq!(seq.steps, 120);
        assert_eq!(seq.restarts, 1, "{events:?}");
        assert!(seq.per_label.contains_key("FullThenBare"));
        assert_eq!(
            r.links.wrong_restorations, 0,
            "the scripted store restores every mention exactly"
        );
        assert!(
            seq.wrong_links_ambiguous > 0,
            "sharing a suffix by first name is exactly the mistake the gate catches: {seq:?}"
        );
        assert!(
            seq.wrong_links_cross_step >= seq.wrong_links_ambiguous + seq.wrong_links_surname_other
        );
        assert_eq!(
            seq.repeats_expected_cached,
            steps.iter().filter(|s| s.expect_cached).count()
        );
        assert_eq!(seq.per_label.values().map(|l| l.docs).sum::<usize>(), 120);
    }

    /// A correct store (own entity for bare mentions, an in-document link for
    /// full name then bare first name) has no wrong link anywhere, and the
    /// legitimate link is counted.
    #[test]
    fn correct_store_has_no_wrong_links_and_counts_real_links() {
        let steps = generate_sequence(&SequenceOptions::default());
        let mut s = Scripted::new(Mode::Correct);
        let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut |_| Ok(()), &mut || 0);
        let seq = r.sequence.unwrap();
        assert_eq!(seq.wrong_links_ambiguous, 0, "{seq:?}");
        assert_eq!(seq.wrong_links_surname_other, 0);
        assert_eq!(seq.wrong_links_cross_step, 0);
        assert_eq!(r.links.wrong_restorations, 0);
        assert!(seq.per_label["FullThenBare"].links > 0);
        assert!(seq.per_label["Ambiguous"].docs > 0);
    }

    /// A linker that breaks a tie by newest candidate and happens to name the
    /// true person emits a token whose suffix matches the map. It is still a
    /// link in an ambiguity case, so the gate must trip on every released one.
    #[test]
    fn tie_break_by_newest_trips_the_ambiguity_gate() {
        let steps = generate_sequence(&SequenceOptions::default());
        let mut s = Scripted::new(Mode::AlwaysLink);
        let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut |_| Ok(()), &mut || 0);
        let seq = r.sequence.unwrap();
        let amb = &seq.per_label["Ambiguous"];
        assert!(amb.accepted > 0);
        assert_eq!(seq.wrong_links_ambiguous, amb.accepted, "{seq:?}");
        assert_eq!(r.links.wrong_restorations, 0, "every restoration is exact");
        // BareRecentOther and SurnameRecentOther follow the same rule
        assert!(seq.per_label["BareRecentOther"].wrong_links > 0);
        assert!(seq.wrong_links_surname_other > 0);
    }

    /// A blocked step minted its tokens in the vault but released nothing, so
    /// the evaluator never saw its suffixes. A later ambiguity step that links
    /// to one of them must still trip the gate.
    #[test]
    fn link_to_a_suffix_minted_in_a_blocked_step_trips_the_gate() {
        let steps = generate_sequence(&SequenceOptions::default());
        let mut s = Scripted::new(Mode::AlwaysLink);
        s.block_full = true; // every full-name document is withheld
        let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut |_| Ok(()), &mut || 0);
        let seq = r.sequence.unwrap();
        assert_eq!(seq.per_label["FullThenBare"].accepted, 0);
        let amb = &seq.per_label["Ambiguous"];
        assert!(amb.accepted > 0 && amb.links == amb.accepted);
        assert_eq!(seq.wrong_links_ambiguous, amb.accepted, "{seq:?}");
    }

    /// Two different people with identical bare first-name text share a
    /// text-keyed entity token. That is not a linker mistake (the token
    /// restores to the right text); it is reported separately and must not
    /// trip the ambiguity gate.
    #[test]
    fn identical_text_reuse_is_not_a_wrong_link() {
        use crate::corpus::GoldSpan;
        use crate::metrics::Replaced;
        struct TextKeyed(Scripted);
        impl Sanitizer for TextKeyed {
            fn detect(
                &mut self,
                t: &str,
            ) -> Result<Vec<inumaki_core::span::Span>, crate::metrics::DetectFailed> {
                self.0.detect(t)
            }
            fn process(&mut self, doc: &Doc) -> EvalOutcome {
                // entity token (no surface component) per distinct text
                let g = &doc.spans[0];
                let mention = &doc.text[g.start..g.end];
                let tok = "<PERSON_abcd>".to_string();
                self.0.restore.insert(tok.clone(), (mention.to_string(), 0));
                EvalOutcome::Pass {
                    replaced: vec![Replaced {
                        start: g.start,
                        end: g.end,
                        out_start: 0,
                        out_end: tok.len(),
                        kind: "PERSON".into(),
                        tokenized: true,
                    }],
                    text: tok,
                }
            }
            fn restore(&mut self, t: &str) -> Option<String> {
                self.0.restore(t)
            }
            fn token_settings(&self) -> &inumaki_core::config::TokenSettings {
                self.0.token_settings()
            }
            fn verifier(&self) -> Option<std::sync::Arc<dyn inumaki_core::verify::Verifier>> {
                None
            }
        }
        let step = |i: usize, entity: &str, label| SeqStep {
            doc: Doc {
                id: format!("t{i}"),
                lang: "de".into(),
                text: "Sarah".into(),
                spans: vec![GoldSpan {
                    start: 0,
                    end: 5,
                    kind: "PERSON".into(),
                    sensitive: true,
                    entity: Some(entity.into()),
                }],
                why: None,
            },
            label,
            before: Vec::new(),
            repeat_of: None,
            expect_cached: false,
        };
        let steps = vec![
            step(0, "p1", SeqLabel::BareRecentSame),
            step(1, "p2", SeqLabel::Ambiguous),
        ];
        let mut s = TextKeyed(Scripted::new(Mode::Correct));
        let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut |_| Ok(()), &mut || 0);
        let seq = r.sequence.unwrap();
        assert_eq!(seq.wrong_links_ambiguous, 0, "{seq:?}");
        assert_eq!(seq.per_label["Ambiguous"].same_text_reuse, 1);
        assert_eq!(r.links.wrong_restorations, 0);
    }

    /// The first sighting of a suffix is a surface token (its parent's own
    /// document was blocked): that mention must not become the suffix's
    /// recorded owner, or the parent's later, correct mentions read as wrong
    /// links (seen with `surnames_across_requests` on).
    #[test]
    fn a_surface_token_with_an_unseen_parent_does_not_claim_the_suffix() {
        use crate::corpus::GoldSpan;
        use crate::metrics::Replaced;
        struct Fixed(Scripted, std::collections::HashMap<String, String>);
        impl Sanitizer for Fixed {
            fn detect(
                &mut self,
                t: &str,
            ) -> Result<Vec<inumaki_core::span::Span>, crate::metrics::DetectFailed> {
                self.0.detect(t)
            }
            fn process(&mut self, doc: &Doc) -> EvalOutcome {
                let g = &doc.spans[0];
                let tok = self.1[&doc.id].clone();
                EvalOutcome::Pass {
                    replaced: vec![Replaced {
                        start: g.start,
                        end: g.end,
                        out_start: 0,
                        out_end: tok.len(),
                        kind: "PERSON".into(),
                        tokenized: true,
                    }],
                    text: tok,
                }
            }
            fn restore(&mut self, _: &str) -> Option<String> {
                None
            }
            fn token_settings(&self) -> &inumaki_core::config::TokenSettings {
                self.0.token_settings()
            }
            fn verifier(&self) -> Option<std::sync::Arc<dyn inumaki_core::verify::Verifier>> {
                None
            }
        }
        let step = |i: usize, text: &str, entity: &str, label| SeqStep {
            doc: Doc {
                id: format!("t{i}"),
                lang: "de".into(),
                text: text.into(),
                spans: vec![GoldSpan {
                    start: 0,
                    end: text.len(),
                    kind: "PERSON".into(),
                    sensitive: true,
                    entity: Some(entity.into()),
                }],
                why: None,
            },
            label,
            before: Vec::new(),
            repeat_of: None,
            expect_cached: false,
        };
        let steps = vec![
            // p2's bare surname linked to p1's (unseen) parent: a wrong link by label
            step(0, "Okonkwo", "p2", SeqLabel::SurnameRecentOther),
            // p1's own full name later: the suffix is p1's, not p2's
            step(1, "Hannah Okonkwo", "p1", SeqLabel::FullThenBare),
        ];
        let tokens = [
            ("t0".to_string(), "<PERSON_07a775_d7>".to_string()),
            ("t1".to_string(), "<PERSON_07a775>".to_string()),
        ]
        .into_iter()
        .collect();
        let mut s = Fixed(Scripted::new(Mode::Correct), tokens);
        let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut |_| Ok(()), &mut || 0);
        let seq = r.sequence.unwrap();
        assert_eq!(seq.wrong_links_surname_other, 1, "gated by the label rule");
        assert_eq!(seq.per_label["FullThenBare"].wrong_links, 0, "{seq:?}");
        assert_eq!(seq.wrong_links_cross_step, 1);
    }

    /// A blocked step released nothing: it contributes no link and no
    /// wrong link.
    #[test]
    fn blocked_steps_count_no_links() {
        let steps = generate_sequence(&SequenceOptions {
            steps: 60,
            ..SequenceOptions::default()
        });
        let mut s = Scripted::new(Mode::AlwaysLink);
        s.blocked_every = 1;
        let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut |_| Ok(()), &mut || 0);
        let seq = r.sequence.unwrap();
        assert_eq!(r.blocked_docs, 60);
        assert!(seq.per_label.values().all(|l| l.links == 0
            && l.wrong_links == 0
            && l.same_text_reuse == 0
            && l.blocked == l.docs));
        assert_eq!(r.links.tokens_total, 0);
    }

    /// Grace, both directions, on a warm store: tokens minted before the
    /// rotation must resolve during grace and must not resolve after expiry
    /// plus the sweep. A store that fails either way shows up in the counts.
    #[test]
    fn closed_epoch_tokens_resolve_during_grace_and_not_after() {
        let steps = generate_sequence(&SequenceOptions::scaled(45));
        assert!(steps.iter().any(|s| s.before.contains(&SeqEvent::Rotate)));
        // (forget_on_rotate, forget_closed) -> (resolved within grace, unresolved after)
        for (early, late) in [(false, true), (false, false), (true, true)] {
            let mut s = Scripted::new(Mode::Correct);
            s.forget_on_rotate = early;
            s.forget_closed = late;
            let mut hook = s.on_event();
            let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut hook, &mut || 0);
            let seq = r.sequence.unwrap();
            assert_eq!(seq.rotations, 1);
            let pre = seq.pre_rotation_tokens;
            assert!(pre > 0, "{seq:?}");
            assert_eq!(seq.reused_after_rotation, 0, "{seq:?}");
            if early {
                assert_eq!(
                    seq.resolved_within_grace, 0,
                    "dropped before grace ended: {seq:?}"
                );
            } else {
                assert_eq!(seq.resolved_within_grace, pre, "{seq:?}");
            }
            if late {
                assert_eq!(seq.unresolved_after_grace, pre, "{seq:?}");
            } else {
                assert_eq!(
                    seq.unresolved_after_grace, 0,
                    "still resolves after expiry: {seq:?}"
                );
            }
        }
    }

    /// A token issued before the rotation that a document released after it
    /// carries again is counted, not silently excluded.
    #[test]
    fn tokens_reappearing_after_rotation_are_counted() {
        let steps = generate_sequence(&SequenceOptions::scaled(45));
        let mut s = Scripted::new(Mode::Correct);
        s.epoch_in_key = false; // the same person gets the same token in the new epoch
        let mut hook = s.on_event();
        let r = evaluate_sequence(&mut s, &steps, &quiet(), &mut hook, &mut || 0);
        assert!(r.sequence.unwrap().reused_after_rotation > 0);
    }

    /// An event the runner cannot apply (a failed restart) is counted, so a
    /// run on a closed state cannot pass for a measurement.
    #[test]
    fn failed_events_are_counted() {
        let steps = generate_sequence(&SequenceOptions::scaled(30));
        let mut s = Scripted::new(Mode::Correct);
        let r = evaluate_sequence(
            &mut s,
            &steps,
            &quiet(),
            &mut |e| {
                if *e == SeqEvent::Restart {
                    Err("closed".into())
                } else {
                    Ok(())
                }
            },
            &mut || 0,
        );
        assert_eq!(r.sequence.unwrap().event_failures, 2);
    }
}
