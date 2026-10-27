#!/usr/bin/env python3
"""Convert a hand-written cases TOML file (crates/inumaki-eval/cases/*.toml)
to an eval JSONL corpus with the semantics of inumaki_eval::cases::parse_cases:
NFC text, span texts located in the NFC text (every occurrence, or the
1-based `occurrence`), UTF-8 byte offsets, spans sorted by start, `sensitive`
defaulting by kind. Build time only (python3 >= 3.11, stdlib).
  python3 -I scripts/harness-corpus/cases-to-jsonl.py CASES.toml > OUT.jsonl"""
import json
import sys
import tomllib
import unicodedata

NOT_SENSITIVE = {"CITY", "POSTAL_CODE", "COUNTRY", "ORGANIZATION", "URL", "DATE"}


def nfc(s):
    return unicodedata.normalize("NFC", s)


with open(sys.argv[1], "rb") as f:
    cases = tomllib.load(f)["case"]
for c in cases:
    text = nfc(c["text"])
    raw = text.encode("utf-8")
    spans = []
    for i, s in enumerate(c.get("spans", [])):
        needle = nfc(s["text"]).encode("utf-8")
        starts, at = [], raw.find(needle)
        while at >= 0:
            starts.append(at)
            at = raw.find(needle, at + 1)
        if "occurrence" in s:
            n = s["occurrence"]
            starts = starts[n - 1:n] if 0 < n <= len(starts) else []
        if not starts:
            sys.exit(f"{c['id']}: span {i} not found")
        for p in starts:
            spans.append({"start": p, "end": p + len(needle), "kind": s["kind"],
                          "sensitive": s.get("sensitive", s["kind"] not in NOT_SENSITIVE)})
    spans.sort(key=lambda s: s["start"])
    doc = {"id": c["id"], "lang": c["lang"], "text": text, "spans": spans}
    if "why" in c:
        doc["why"] = c["why"]
    print(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))
