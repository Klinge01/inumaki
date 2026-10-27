#!/usr/bin/env python3
"""Negative-only precision corpus for the structured-positions work (plan
2026-10-20, ruling S22): documents that contain no identifying information,
so every detected span is a false positive. Prints JSONL (ids and synthetic
texts only; `spans` empty, `lang` de, NFC).
  python3 -I scripts/harness-corpus/build-structured-negatives.py fnames  > harness/structured-negatives-fnames.jsonl
  python3 -I scripts/harness-corpus/build-structured-negatives.py text    > harness/structured-negatives-text.jsonl
`fnames`: every file-name stem as written and, when different, in the
spelling the folder mirror's detection pass uses (a `_ - . +` becomes a space,
except inside a date or time shape: YYYY-MM-DD, YYYY-MM, DD.MM.YYYY,
HH.MM[.SS], separators `-` `_` `.` `:`, valid ranges, no digit glued on
either side and no further digit group across one separator).
`text`: path, URL and table lines. Build time only (python3 >= 3.11, stdlib)."""
import json
import re
import sys
import unicodedata

STEMS = """mail-anfrage|notizen|readme|todo|protokoll|bericht|entwurf|angebot|rechnung|vertrag|liste|kontakte|scan|foto|dokument|praesentation|notes|draft|report|invoice|minutes|summary|meeting-notes|angebot-entwurf-v2|protokoll_sitzung_2026-10-01|kundenliste|offerte|lieferschein|mahnung|kündigung|bewerbung|lebenslauf|zeugnis|steuer-2025|budget_q3|projektplan|changelog|index|tabelle|anfrage-kunde|antwort|anhang|kopie|final|IMG_2034|IMG_20261001_123456|PXL_20261001_123456789|DSC01234|DSCN0042|VID_20261001_101010|Screenshot 2026-10-01 at 12.34.56|Bildschirmfoto 2026-10-01 um 12.34.56|Scan_20261001|scan0001|Dokument1|Mappe1|Neues Dokument|Unbenannt|Untitled|Kopie von angebot|angebot (1)|angebot_final_v3|foto-2025-07-14|export_20261001|angebot_2026-03|reisekosten_oktober|urlaubsantrag-2026|stundenzettel_kw42|preisliste-2026|übersicht|zusammenfassung_final|präsentation_kunde|vorlage-brief|einladung_weihnachtsfeier|bestellung_bueromaterial|inventur-lager|fahrtenbuch_2025|Quartalsbericht|Jahresabschluss 2025|Kostenvoranschlag""".split("|")
LINES = [
    r"Logs liegen unter /home/runner/work/app/app/build.log und /Users/Shared/tmp.",
    r"Öffentlich: C:\Users\Public\Documents\Vorlagen",
    r"Cache: /Users/admin/Library/Caches/com.example.app",
    r"Siehe https://example.com/team/about und https://example.com/people/search?q=angebot",
    r"Code: https://github.com/rust-lang/cargo/issues",
    r"Doku: https://docs.example.com/user/guide/install.html",
    r"Deploy nach /home/deploy/app/current und /var/www/html/index.php",
    r"Binary: /opt/homebrew/bin/git, Config: ~/Documents/Projekte/angebot.docx",
    "Name;Typ;Standard\nport;Zahl;8080\nhost;Text;localhost",
    "| Name | Beschreibung |\n|---|---|\n| Export | Schreibt eine CSV-Datei |\n| Import | Liest eine Liste ein |",
    "Artikel;Menge;Preis\nSchrauben;100;4,50\nDübel;50;3,20",
    "Datum,Betrag,Kategorie\n2026-10-01,45.00,Büro\n2026-10-02,12.50,Reise",
]
SEPS = "-_.:"
D = r"\d"
# (regex, validator) tried longest shape first at each position.
SHAPES = [
    (re.compile(r"(\d{4})[-_.:](\d{2})[-_.:](\d{2})"), lambda a, b, c: 1 <= int(b) <= 12 and 1 <= int(c) <= 31),
    (re.compile(r"(\d{2})[-_.:](\d{2})[-_.:](\d{4})"), lambda a, b, c: 1 <= int(a) <= 31 and 1 <= int(b) <= 12),
    (re.compile(r"(\d{2})[-_.:](\d{2})[-_.:](\d{2})"), lambda a, b, c: int(a) <= 23 and int(b) <= 59 and int(c) <= 59),
    (re.compile(r"(\d{4})[-_.:](\d{2})"), lambda a, b: 1 <= int(b) <= 12),
    (re.compile(r"(\d{2})[-_.:](\d{2})"), lambda a, b: int(a) <= 23 and int(b) <= 59),
]


def nfc(s):
    return unicodedata.normalize("NFC", s)


def keep_ranges(s):
    """Byte-free character ranges [i, j) of date/time shapes whose separators stay."""
    out = []
    i = 0
    while i < len(s):
        hit = None
        if s[i].isdigit() and (i == 0 or not s[i - 1].isdigit()):
            for rx, ok in SHAPES:
                m = rx.match(s, i)
                if not m or not ok(*m.groups()):
                    continue
                j = m.end()
                if j < len(s) and s[j].isdigit():
                    continue
                if i >= 2 and s[i - 1] in SEPS and s[i - 2].isdigit():
                    continue
                if j + 1 < len(s) and s[j] in SEPS and s[j + 1].isdigit():
                    continue
                hit = (i, j)
                break
        if hit:
            out.append(hit)
            i = hit[1]
        else:
            i += 1
    return out


def detection_spelling(stem):
    keep = [False] * len(stem)
    for i, j in keep_ranges(stem):
        for k in range(i, j):
            keep[k] = True
    return "".join(" " if c in "_-.+" and not keep[k] else c for k, c in enumerate(stem))


def doc(prefix, n, text):
    return {"id": f"{prefix}-{n:03d}", "lang": "de", "text": nfc(text), "spans": []}


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    docs = []
    if mode == "fnames":
        texts = []
        for stem in STEMS:
            texts.append(stem)
            spaced = detection_spelling(stem)
            if spaced != stem:
                texts.append(spaced)
        docs = [doc("fname", n, t) for n, t in enumerate(texts, 1)]
    elif mode == "text":
        docs = [doc("struct", n, t) for n, t in enumerate(LINES, 1)]
    else:
        sys.exit("usage: build-structured-negatives.py fnames|text")
    for d in docs:
        print(json.dumps(d, ensure_ascii=False, separators=(",", ":")))


main()
