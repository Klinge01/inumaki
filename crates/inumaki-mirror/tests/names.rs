//! M5 spec §4.3: validity, opaque fallback, collisions, ignored names; and
//! the block size cap the pipeline enforces (spec §5.1).

mod common;

use common::MemManifest;
use inumaki_mirror::MirrorConfig;
use inumaki_mirror::formats::{Format, oversized, prepare};
use inumaki_mirror::names::{
    casefold, collision_suffix, ignored, opaque_name, valid_component, with_suffix,
};

#[test]
fn invalid_results_are_refused() {
    for bad in ["", ".", "..", "a/b", "a\0b", &"x".repeat(256)] {
        assert!(!valid_component(bad), "{bad:?}");
    }
    assert!(valid_component("Brief an <PERSON_a1b2c3>.md"));
}

#[test]
fn opaque_names_and_collision_suffixes_are_stable_and_keyed() {
    let m = MemManifest::default();
    let a = opaque_name(&m, "ds", 1, b"Kunden/Quolnath.txt", Some("txt"));
    assert_eq!(
        a,
        opaque_name(&m, "ds", 1, b"Kunden/Quolnath.txt", Some("txt"))
    );
    assert_ne!(
        a,
        opaque_name(&m, "ds", 2, b"Kunden/Quolnath.txt", Some("txt")),
        "per epoch"
    );
    assert!(a.starts_with("f-") && a.ends_with(".txt") && a.len() == 2 + 10 + 4);
    assert!(!a.contains("Quolnath"));
    let s = collision_suffix(&m, "ds", 1, b"angebot.txt");
    assert_eq!(s.len(), 5);
    assert_eq!(
        with_suffix("Angebot.txt", &s, Some("txt")),
        format!("Angebot{s}.txt")
    );
    assert_eq!(casefold("ANGEBOT.txt"), casefold("angebot.TXT"));
}

#[test]
fn editor_and_system_files_are_ignored() {
    for n in [
        ".git",
        ".env",
        ".DS_Store",
        "._x",
        "a.txt~",
        "#a#",
        "a.swp",
        "~$Angebot.docx",
        ".~lock.a.odt#",
        "a.part",
        "a.crdownload",
        "a.tmp",
        "Thumbs.db",
        "desktop.ini",
    ] {
        assert!(ignored(n.as_bytes()), "{n}");
    }
    for n in ["Angebot.txt", "notes", "a#b"] {
        assert!(!ignored(n.as_bytes()), "{n}");
    }
}

/// Blocks of non-text formats are not bounded by the format: a CSV
/// record whose quote never closes swallows the rest of the file, a JSON
/// string value can be megabytes. `oversized` is what the pipeline checks
/// before the engine sees them (it withholds the whole file).
#[test]
fn degenerate_blocks_exceed_the_cap_and_ordinary_ones_do_not() {
    let cap = MirrorConfig::MAX_BLOCK_BYTES;
    let big = "x".repeat(cap + 1);

    let csv = format!("name;note\nQwxzvk;\"{big}\nnext;row\n");
    let doc = prepare(Format::Delimited(b';'), csv.as_bytes()).unwrap();
    assert!(
        oversized(doc.blocks()),
        "unterminated quote swallows the file"
    );

    let json = format!("{{\"note\": \"{big}\"}}");
    let doc = prepare(Format::Json, json.as_bytes()).unwrap();
    assert!(oversized(doc.blocks()), "one huge string value");

    let ok = prepare(Format::Delimited(b';'), b"name;note\nQwxzvk;hello\n").unwrap();
    assert!(!oversized(ok.blocks()));
    assert!(!oversized(&["x".repeat(cap)]), "the cap itself is allowed");
}
