//! No technical- or document-vocabulary word is a name of either generator
//! family, unless it is marked as a surname (plan 2026-10-12 Task 3, review 1
//! C2; document vocabulary: plan 2026-10-20 Task 2).
use inumaki_core::detect::technical::{document_vocabulary, vocabulary};
use inumaki_eval::{data, data_held_out};

#[test]
fn unmarked_vocabulary_shares_no_word_with_generator_names() {
    let names: std::collections::HashSet<String> = [
        data::FIRST_NAMES,
        data::LAST_NAMES,
        data_held_out::FIRST_NAMES,
        data_held_out::LAST_NAMES,
    ]
    .into_iter()
    .flatten()
    .flat_map(|n| {
        n.split(|c: char| !c.is_alphabetic())
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
    })
    .collect();
    let clash: Vec<&str> = vocabulary()
        .chain(document_vocabulary())
        .filter(|(w, surname)| !surname && names.contains(*w))
        .map(|(w, _)| w)
        .collect();
    assert!(
        clash.is_empty(),
        "unmarked vocabulary words that are generator names: {clash:?}"
    );
}
