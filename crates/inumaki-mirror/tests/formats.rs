//! M5 spec §5.2–§5.3: the allow-list, decoding, block splitting that
//! reassembles byte-exactly, CSV record fallback, JSON keys and numbers,
//! the object-level verification blocks, and alias key merges.

use inumaki_mirror::formats::{Format, Redo, classify, decode, prepare};

fn identity(doc: &inumaki_mirror::formats::Doc) -> String {
    doc.assemble(doc.blocks())
        .map(|a| a.text)
        .unwrap_or_default()
}

#[test]
fn classify_is_an_allow_list() {
    assert_eq!(classify(b"a.TXT"), Format::Text);
    assert_eq!(classify(b"README"), Format::Text);
    assert_eq!(classify(b"k.csv"), Format::Delimited(b','));
    assert_eq!(classify(b"k.tsv"), Format::Delimited(b'\t'));
    assert_eq!(classify(b"k.ndjson"), Format::JsonLines);
    for n in [
        "a.rtf",
        "a.xml",
        "a.vcf",
        "a.mbox",
        "a.pdf",
        "a.docx",
        "Brief.Zyxwuria",
    ] {
        assert_eq!(classify(n.as_bytes()), Format::Unsupported, "{n}");
    }
}

#[test]
fn decoding_handles_boms_cp1252_and_binary() {
    assert_eq!(decode(b"\xEF\xBB\xBFHallo").unwrap(), "Hallo");
    assert_eq!(decode(b"\xFF\xFEH\x00i\x00").unwrap(), "Hi");
    assert_eq!(decode(b"M\xFCller;Wien").unwrap(), "Müller;Wien");
    assert!(decode(b"PK\x03\x04\x00\x00binary").is_err());
}

#[test]
fn text_blocks_reassemble_byte_exactly() {
    let text = format!(
        "Sehr geehrter Herr Quolnath,\n\n{}\n\nMit Grüßen\r\n",
        "x ".repeat(5000)
    );
    let doc = prepare(Format::Text, text.as_bytes()).unwrap();
    assert!(doc.blocks().len() >= 3);
    assert!(doc.blocks().iter().all(|b| b.len() <= 4096));
    assert_eq!(identity(&doc), text);
}

#[test]
fn a_csv_record_whose_shape_changes_is_redone_per_field_and_verified() {
    let csv = "name,city\n\"Quolnath, Zyxwuria\",Wien\nQwxzvk,Graz\n";
    let doc = prepare(Format::Delimited(b','), csv.as_bytes()).unwrap();
    assert_eq!(doc.blocks().len(), 3, "one block per record");
    let mut out: Vec<String> = doc.blocks().to_vec();
    out[1] = "<PERSON_000001>Wien\n".into(); // a span that swallowed the delimiter
    match doc.assemble(&out) {
        Err(Redo::Records(fields)) => {
            let fields_out: Vec<String> = fields.blocks().to_vec();
            let a = fields.assemble(&fields_out).unwrap();
            assert!(a.text.contains("Wien"));
            assert!(
                !a.verify.is_empty(),
                "per-field records are verified as a whole"
            );
        }
        other => panic!("expected a per-field redo, got {:?}", other.is_ok()),
    }
}

#[test]
fn json_keys_values_and_numbers_are_blocks_and_objects_are_verified() {
    let json = r#"{"zyxwuria@example.invalid": {"first": "Zyxwuria", "last": "Quolnath", "phone": 4366012345678}, "n": 1}"#;
    let doc = prepare(Format::Json, json.as_bytes()).unwrap();
    let blocks = doc.blocks();
    for b in [
        "zyxwuria@example.invalid",
        "first",
        "Zyxwuria",
        "last",
        "Quolnath",
        "4366012345678",
    ] {
        assert!(blocks.iter().any(|x| x == b), "{b} is a block");
    }
    let mut out = blocks.to_vec();
    let i = out.iter().position(|b| b == "4366012345678").unwrap();
    out[i] = "<PHONE_000002>".into();
    let a = doc.assemble(&out).unwrap();
    assert!(
        a.text.contains("\"<PHONE_000002>\""),
        "a changed number becomes a string"
    );
    assert!(
        a.verify
            .iter()
            .any(|v| v.contains("Zyxwuria") && v.contains("Quolnath")),
        "the inner object is one verify block"
    );
    let pos_first = a.text.find("first").unwrap();
    assert!(pos_first < a.text.find("last").unwrap(), "key order kept");
}

#[test]
fn two_keys_merged_into_one_token_redo_as_text() {
    let json = r#"{"Zyxwuria Quolnath": 1, "Z. Quolnath": 2}"#;
    let doc = prepare(Format::Json, json.as_bytes()).unwrap();
    let out: Vec<String> = doc
        .blocks()
        .iter()
        .map(|b| {
            if b.contains("Quolnath") {
                "<PERSON_000001>".into()
            } else {
                b.clone()
            }
        })
        .collect();
    assert!(matches!(doc.assemble(&out), Err(Redo::AsText(_))));
}

#[test]
fn invalid_json_falls_back_to_text() {
    let doc = prepare(Format::Json, b"{not json, Zyxwuria").unwrap();
    assert_eq!(identity(&doc), "{not json, Zyxwuria");
}

#[test]
fn nested_keys_are_verified_numbers_are_lossless_and_jsonl_keeps_crlf() {
    // Review minor: a key whose value is an object or array is verified with
    // its siblings; numbers beyond u64 keep every digit; JSON Lines keep CRLF.
    let json = r#"{"Zyxwuria": {"a": 1}, "id": 123456789012345678901234567890, "f": 1.50}"#;
    let doc = prepare(Format::Json, json.as_bytes()).unwrap();
    let a = doc.assemble(doc.blocks()).unwrap();
    assert!(
        a.text.contains("123456789012345678901234567890") && a.text.contains("1.50"),
        "{}",
        a.text
    );
    assert!(
        a.verify
            .iter()
            .any(|v| v.contains("\"Zyxwuria\":{}") && v.contains("\"id\"")),
        "{:?}",
        a.verify.len()
    );
    let lines = "{\"a\":\"Zyxwuria\"}\r\n\r\n{\"b\":2}\r\n";
    let doc = prepare(Format::JsonLines, lines.as_bytes()).unwrap();
    assert_eq!(identity(&doc), lines);
}

#[test]
fn delimited_files_reassemble_byte_exactly() {
    // CRLF is Excel's DACH default; lone CR, quoted newlines, blank lines, a
    // missing final newline, and non-ASCII must all survive the round trip.
    let cases = [
        "a,b\r\nc,d\r\n",
        "a,b\rc,d\r",
        "a,\"x\ny\",c\nd,e,f\n",
        "a,\"x\r\ny\",c\r\nd,e,f\r\n",
        "a,b\n\n\nc,d\n",
        "a,b\r\n\r\nc,d\r\n",
        "\n\na,b\n",
        "\n\n",
        "a,b\nc,d",
        "Müller,Wien\r\nGrüß,Graz\r\n",
        "",
    ];
    for csv in cases {
        let doc = prepare(Format::Delimited(b','), csv.as_bytes()).unwrap();
        assert_eq!(identity(&doc), csv, "{csv:?}");
        assert_eq!(doc.blocks().concat(), csv, "{csv:?}");
    }
    let tsv = "a\tb\r\nM\u{fc}ller\tWien\r\n";
    let doc = prepare(Format::Delimited(b'\t'), tsv.as_bytes()).unwrap();
    assert_eq!(identity(&doc), tsv);
}

#[test]
fn redone_adjacent_crlf_records_keep_rows_and_endings() {
    let cases = [
        "h1,h2\r\n\"Quolnath, Zyxwuria\",Wien\r\n\"Qwxzvk, Anna\",Graz\r\nlast,row\r\n",
        "h1,h2\r\"Quolnath, Zyxwuria\",Wien\r\"Qwxzvk, Anna\",Graz\rlast,row\r",
        "h1,h2\r\n\r\n\"Quolnath, Zyxwuria\",Wien\r\n\r\n\"Qwxzvk, Anna\",Graz\r\nlast,row",
    ];
    for csv in cases {
        let doc = prepare(Format::Delimited(b','), csv.as_bytes()).unwrap();
        let mut out = doc.blocks().to_vec();
        for (i, b) in doc.blocks().iter().enumerate() {
            if b.contains("Wien") || b.contains("Graz") {
                // The span swallowed the delimiter; the line break stays.
                let tail = b
                    .trim_start_matches(['\r', '\n'])
                    .rsplit_once(',')
                    .unwrap()
                    .1;
                let lead = &b[..b.len() - b.trim_start_matches(['\r', '\n']).len()];
                out[i] = format!("{lead}<PERSON_000001>{tail}");
            }
        }
        let Err(Redo::Records(fields)) = doc.assemble(&out) else {
            panic!("expected a per-field redo for {csv:?}");
        };
        let a = fields.assemble(fields.blocks()).unwrap();
        assert_eq!(a.text, csv, "rows and endings survive");
        assert_eq!(a.verify.len(), 2, "both redone records are verified");
    }
}

#[test]
fn unchanged_or_blank_records_do_not_force_a_redo() {
    let doc = prepare(Format::Delimited(b','), b"\n\n").unwrap();
    assert!(doc.assemble(doc.blocks()).is_ok());
    // A sanitizer that dropped the line break fails closed into a redo.
    let doc = prepare(Format::Delimited(b','), b"a,b\r\nc,d\r\n").unwrap();
    let mut out = doc.blocks().to_vec();
    out[0] = "a,b".into();
    assert!(matches!(doc.assemble(&out), Err(Redo::Records(_))));
}

#[test]
fn json_arrays_are_verified_side_by_side() {
    let json =
        r#"{"to": ["Zyxwuria", "Quolnath"], "rows": [["Qwxzvk", "Wien"], []], "n": [{"a": 1}]}"#;
    let doc = prepare(Format::Json, json.as_bytes()).unwrap();
    let a = doc.assemble(doc.blocks()).unwrap();
    assert!(
        a.verify.iter().any(|v| v == r#"["Zyxwuria","Quolnath"]"#),
        "{:?}",
        a.verify.len()
    );
    assert!(
        a.verify.iter().any(|v| v == r#"["Qwxzvk","Wien"]"#),
        "row arrays are verified"
    );
    let doc = prepare(Format::Json, br#"["Zyxwuria", "Quolnath", 7, {"k": 1}]"#).unwrap();
    let a = doc.assemble(doc.blocks()).unwrap();
    assert!(
        a.verify
            .iter()
            .any(|v| v == r#"["Zyxwuria","Quolnath",7,{}]"#)
    );
}

#[test]
fn a_bom_does_not_hide_a_binary_file() {
    assert!(decode(b"\xEF\xBB\xBFab\x00cd").is_err());
}
