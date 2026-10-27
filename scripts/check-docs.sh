#!/usr/bin/env bash
# Documentation checks. Run from anywhere; it works on the repository root.
#
#   (a) every relative Markdown link [..](path) resolves to an existing file or directory;
#   (b) every #anchor into a Markdown file names a heading there (GitHub slugs);
#   (c) every key and table of configs/default.toml, commented or not, is
#       documented in docs/configuration.md as a backticked `table.key`
#       (skipped while that file does not exist);
#   (d) every backticked repository path (docs/, crates/, configs/, scripts/,
#       packaging/, apps/) exists. Paths with < * … { $ are placeholders.
#
# Failures print as `file:line: message`. Exit 1 on any failure, 0 otherwise.
# External links (http, https, mailto, ...) are not fetched.
#
# scripts/check-docs.allow lists exceptions, one per line, `#` starts a comment:
#   file:target       skip that link or backticked path everywhere in the file;
#   file:target@LINE  skip it on that line only (preferred);
#   file:*            skip the backticked-path rule (d) for the whole file, for
#                     files that cite paths of other repositories as evidence.
#
# `check-docs.sh --self-test` (also run before every normal check) builds a few
# throwaway Markdown trees and checks that the script accepts and rejects what it
# should: heading slugs with punctuation and umlauts, fences, parentheses in
# link targets.
#
# Needs only bash 3.2, find, grep, and a POSIX awk (the macOS defaults work).

set -u
# macOS awk aborts on some multibyte input in a UTF-8 locale (towc failure) and
# the heading slugs then come out empty; bytes are enough for these checks.
export LC_ALL=C
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
ROOT="${CHECK_DOCS_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 2

TMP="$(mktemp -d "${TMPDIR:-/tmp}/check-docs.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT

FAILURES=0
fail() { # file line message
  printf '%s:%s: %s\n' "$1" "$2" "$3"
  FAILURES=$((FAILURES + 1))
}

# --- allowlist -------------------------------------------------------------
ALLOW="$TMP/allow"
: >"$ALLOW"
if [ -f scripts/check-docs.allow ]; then
  sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    scripts/check-docs.allow | grep -v '^$' >"$ALLOW" || true
fi
# allowed FILE TARGET LINE: `file:target` for every line, `file:target@LINE` for one.
allowed() { grep -qxF -e "$1:$2" -e "$1:$2@$3" "$ALLOW"; }
# A `file:*` entry exempts every backticked path (rule d) in that file. A
# per-line list would be impractical there: those files cite hundreds of paths.
allowed_path() { allowed "$1" "$2" "$3" || grep -qxF "$1:*" "$ALLOW"; }

# --- awk: pieces shared by the scanners ------------------------------------
# fence(line): tracks CommonMark code fences. An opening run is three or more
# backticks or tildes (a backtick run may not have a backtick in its info
# string, so a one-line ```x``` is code, not a fence); the closing run must use
# the same character, be at least as long, and be followed by nothing.
# Returns 1 when the line is a fence line or inside a fence.
cat >"$TMP/common.awk" <<'AWK'
function fence(line,   p, ch, n, rest) {
  p = line
  sub(/^[ \t>]*/, "", p)
  ch = substr(p, 1, 1)
  if (ch == "`" || ch == "~") {
    n = 0
    while (substr(p, n + 1, 1) == ch) n++
    rest = substr(p, n + 1)
    if (n >= 3) {
      if (!infence) {
        if (ch == "~" || index(rest, "`") == 0) {
          infence = 1; fch = ch; flen = n
          return 1
        }
      } else if (ch == fch && n >= flen && rest ~ /^[ \t]*$/) {
        infence = 0
        return 1
      }
    }
  }
  return infence
}
# link_end(s, i): s[i-1] is "(" of a link target; returns the index of the
# matching ")" counting nested pairs, or 0 when the target is not closed.
function link_end(s, i,   depth, c, n) {
  depth = 1
  n = length(s)
  for (; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\\") i++
    else if (c == "(") depth++
    else if (c == ")" && --depth == 0) return i
  }
  return 0
}
AWK

# --- awk: extract links and backticked paths -------------------------------
# Emits tab-separated records: kind (L link, P path), line number, target.
cat >"$TMP/scan.awk" <<'AWK'
function trim(s) { gsub(/^[ \t]+/, "", s); gsub(/[ \t]+$/, "", s); return s }
{
  line = $0
  if (fence(line)) next
  # Backticked spans: candidates for rule (d); then blanked out for links.
  s = line
  while (match(s, /`[^`]+`/)) {
    span = substr(s, RSTART + 1, RLENGTH - 2)
    if (span !~ /[ \t]/) printf "P\t%d\t%s\n", FNR, span
    s = substr(s, 1, RSTART - 1) " " substr(s, RSTART + RLENGTH)
  }
  rest = s
  while ((k = index(rest, "](")) > 0) {
    e = link_end(rest, k + 2)
    if (e == 0) { rest = substr(rest, k + 2); continue }
    t = trim(substr(rest, k + 2, e - k - 2))
    rest = substr(rest, e + 1)
    if (t ~ /^</) { sub(/^</, "", t); sub(/>.*$/, "", t) }
    else { sub(/[ \t].*$/, "", t) }
    if (t != "") printf "L\t%d\t%s\n", FNR, t
  }
  rest = s
  while (match(rest, /(href|src)="[^"]*"/)) {
    t = substr(rest, RSTART, RLENGTH)
    rest = substr(rest, RSTART + RLENGTH)
    sub(/^[a-z]+="/, "", t); sub(/"$/, "", t)
    if (t != "") printf "L\t%d\t%s\n", FNR, t
  }
  if (s ~ /^ ? ? ?\[[^^][^]]*\]:[ \t]+[^ \t]/) {
    t = s
    sub(/^ ? ? ?\[[^]]*\]:[ \t]+/, "", t)
    sub(/[ \t].*$/, "", t)
    if (t ~ /^</) { sub(/^</, "", t); sub(/>.*$/, "", t) }
    printf "L\t%d\t%s\n", FNR, t
  }
}
AWK

# --- awk: GitHub-style heading slugs of a Markdown file ---------------------
# GitHub lowercases the heading text, keeps letters, digits, `_` and `-`, turns
# each space into `-`, and drops all other punctuation, including `§` and `—`.
# It keeps Unicode letters. The script runs in the C locale, so a UTF-8
# character is a run of bytes; those are decoded by hand:
#   Latin-1 letters (U+00C0..U+00FF except × and ÷)   kept, upper case lowered
#   other 2-byte letters (Latin Extended, Greek, Cyrillic)  kept as written
#   everything else non-ASCII (punctuation, symbols, emoji, CJK)  dropped
# Not handled: lower-casing outside Latin-1, and `ª º µ`. Write such headings
# in lower case or link them by the slug GitHub shows.
cat >"$TMP/slugs.awk" <<'AWK'
BEGIN { for (b = 128; b < 256; b++) ord[sprintf("%c", b)] = b }
function utf8(t, i,   b, b2, len) { # -> kept bytes of the character at i, or ""
  b = ord[substr(t, i, 1)]
  if (b >= 240) len = 4; else if (b >= 224) len = 3; else if (b >= 192) len = 2; else len = 1
  step = len
  if (len != 2) return ""
  b2 = ord[substr(t, i + 1, 1)]
  if (b2 == "") return ""
  if (b == 195) { # Latin-1 supplement
    if (b2 == 151 || b2 == 183) return "" # × ÷
    if (b2 >= 128 && b2 <= 158) b2 += 32  # À..Þ -> à..þ
    return sprintf("%c%c", b, b2)
  }
  if (b >= 196 && b <= 201) return substr(t, i, 2) # Latin Extended, IPA
  if (b >= 206 && b <= 211) return substr(t, i, 2) # Greek, Cyrillic
  return ""
}
{
  if (fence($0)) next
  if ($0 !~ /^ ? ? ?#(#?#?#?#?#?)[ \t]/) next
  t = $0
  sub(/^ ? ? ?#+[ \t]+/, "", t)
  sub(/[ \t]+#+[ \t]*$/, "", t)
  gsub(/<[^>]*>/, "", t)
  out = ""
  while ((k = index(t, "](")) > 0) { # [text](target) -> text
    e = link_end(t, k + 2)
    if (e == 0) break
    st = 0
    for (j = k - 1; j >= 1; j--) if (substr(t, j, 1) == "[") { st = j; break }
    if (st == 0) break
    t = substr(t, 1, st - 1 - (st > 1 && substr(t, st - 1, 1) == "!" ? 1 : 0)) substr(t, st + 1, k - st - 1) substr(t, e + 1)
  }
  gsub(/`/, "", t)
  t = tolower(t)
  slug = ""
  for (i = 1; i <= length(t); i += step) {
    step = 1
    c = substr(t, i, 1)
    if (c ~ /[a-z0-9_-]/) slug = slug c
    else if (c == " ") slug = slug "-"
    else if (c !~ /[ -~]/) slug = slug utf8(t, i)
  }
  n = seen[slug]++
  print (n > 0) ? slug "-" n : slug
}
AWK

slug_file() { # markdown path -> file with its slugs
  local key out
  key="$(printf '%s' "$1" | tr '/ ' '__')"
  out="$TMP/slugs.$key"
  [ -f "$out" ] || awk -f "$TMP/common.awk" -f "$TMP/slugs.awk" "$1" >"$out"
  printf '%s' "$out"
}

# --- self-test ---------------------------------------------------------------
# Builds two throwaway trees and runs this script on them (CHECK_DOCS_ROOT).
self_test() {
  local good="$TMP/st-good" bad="$TMP/st-bad" out rc ok=1
  mkdir -p "$good" "$bad"
  cat >"$good/a.md" <<'MD'
# Intro

## § 4.3 — Die Größe (Ärger)

## Über uns

## `code` and [a link](x_(y).md)

Anchors: [one](#intro), [two](#-43--die-größe-ärger), [three](#über-uns),
[four](#code-and-a-link), [five](x_(y).md), [six](x_(y).md#target-heading).

A one-line ```fence``` is code, so the next heading counts: [seven](#after).

````text
```
[hidden](nope.md)
```
[still hidden](nope.md)
````

## After
MD
  printf '# Target heading\n' >"$good/x_(y).md"
  cat >"$bad/a.md" <<'MD'
# § Foo

[good](#-foo)
[no-section-sign](#foo)
[paren](missing_(a).md)
[anchor](#nonexistent)
MD
  out="$(CHECK_DOCS_ROOT="$good" bash "$SELF" 2>&1)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'self-test: the good fixture failed:\n%s\n' "$out"
    ok=0
  fi
  out="$(CHECK_DOCS_ROOT="$bad" bash "$SELF" 2>&1)"
  rc=$?
  if [ "$rc" -ne 1 ]; then
    printf 'self-test: the bad fixture did not fail (exit %s)\n' "$rc"
    ok=0
  fi
  for want in 'a.md:4: no heading for anchor: #foo' \
    'a.md:5: broken link: missing_(a).md' 'a.md:6: no heading for anchor: #nonexistent'; do
    case "$out" in
      *"$want"*) ;;
      *) printf 'self-test: expected "%s" in:\n%s\n' "$want" "$out"; ok=0 ;;
    esac
  done
  case "$out" in
    *"a.md:3:"*) printf 'self-test: #-foo was rejected:\n%s\n' "$out"; ok=0 ;;
  esac
  [ "$ok" -eq 1 ]
}

if [ "${1:-}" = --self-test ] || [ -z "${CHECK_DOCS_ROOT:-}" ]; then
  if ! self_test; then
    echo "check-docs: self-test failed" >&2
    exit 1
  fi
  [ "${1:-}" = --self-test ] && { echo "check-docs: self-test ok"; exit 0; }
fi

# --- files to scan ---------------------------------------------------------
find . \( -path ./.git -o -path ./.superpowers -o -path ./.worktrees \
  -o -path ./docs/superpowers -o -path ./models -o -name target \
  -o -name node_modules \) -prune -o -type f -name '*.md' -print |
  sed 's|^\./||' | LC_ALL=C sort >"$TMP/files"

SCHEME_RE='^[A-Za-z][A-Za-z0-9+.-]*:'
PATH_RE='^(docs|crates|configs|scripts|packaging|apps)/'

while IFS= read -r f; do
  dir="$(dirname "$f")"
  awk -f "$TMP/common.awk" -f "$TMP/scan.awk" "$f" >"$TMP/records"
  while IFS="$(printf '\t')" read -r kind lineno target; do
    if [ "$kind" = L ]; then
      allowed "$f" "$target" "$lineno" && continue
      t="$target"
      [[ $t =~ $SCHEME_RE ]] && continue
      anchor=""
      case "$t" in *"#"*) anchor="${t#*#}"; t="${t%%#*}" ;; esac
      t="${t%%\?*}"
      t="${t//%20/ }"
      if [ -z "$t" ]; then
        path="$f"
      elif [ "${t#/}" != "$t" ]; then
        path="${t#/}"
      elif [ "$dir" = . ]; then
        path="$t"
      else
        path="$dir/$t"
      fi
      if [ ! -e "$path" ]; then
        fail "$f" "$lineno" "broken link: $target"
        continue
      fi
      if [ -n "$anchor" ] && [ -f "$path" ]; then
        case "$path" in
          *.md)
            a="$(printf '%s' "$anchor" | tr 'A-Z' 'a-z')"
            if ! grep -qxF -- "$a" "$(slug_file "$path")"; then
              fail "$f" "$lineno" "no heading for anchor: $target"
            fi
            ;;
        esac # anchors into other files (#L12) are exempt
      fi
    else # P: backticked path, rule (d)
      p="$target"
      [[ $p =~ $PATH_RE ]] || continue
      allowed_path "$f" "$p" "$lineno" && continue
      case "$p" in *"<"* | *"*"* | *"…"* | *"{"* | *"$"* | *"..."* | *"?"* | *'"'* | *"="*) continue ;; esac
      p="${p%%#*}"
      p="${p%%::*}" # crates/x/src/y.rs::test_name
      p="$(printf '%s' "$p" | sed -E -e 's/:[0-9]+(-[0-9]+)?$//' -e 's/[,.;:)]+$//')"
      p="${p%/}"
      [ -e "$p" ] || fail "$f" "$lineno" "path does not exist: $p"
    fi
  done <"$TMP/records"
done <"$TMP/files"

# --- rule (c): default.toml keys are documented ------------------------------
TOML=configs/default.toml
DOC=docs/configuration.md
if [ -f "$DOC" ] && [ -f "$TOML" ]; then
  cat >"$TMP/config.awk" <<'AWK'
# First file: the documentation; second: the TOML.
FNR == NR {
  s = $0
  while (match(s, /`[^`]+`/)) {
    tok = substr(s, RSTART + 1, RLENGTH - 2)
    s = substr(s, RSTART + RLENGTH)
    if (tok ~ /[ \t]/) continue
    if (tok ~ /</) {
      gsub(/\./, "\\.", tok); gsub(/<[^>]*>/, "[^.]+", tok)
      pat[++np] = "^" tok "$"
    } else has[tok] = 1
  }
  next
}
function documented(id,   i) {
  if (id in has) return 1
  for (i = 1; i <= np; i++) if (id ~ pat[i]) return 1
  return 0
}
function report(id) {
  if (id in done) return
  done[id] = 1
  printf "%s:%d: `%s` is not documented in %s\n", TOML, FNR, id, DOC
}
{
  if (match($0, /^[ \t]*#?[ \t]*\[\[?[A-Za-z0-9_.-]+\]\]?[ \t]*(#.*)?$/)) {
    h = $0
    sub(/^[ \t]*#?[ \t]*\[\[?/, "", h); sub(/\]\]?[ \t]*(#.*)?$/, "", h)
    tbl = h
    prof = ""; sub_ = ""
    if (tbl ~ /^profiles\./) {
      n = split(tbl, seg, ".")
      prof = seg[2]
      if (n > 2) sub_ = seg[3]
    }
    if (prof == "") {
      if (!documented(tbl)) report(tbl)
    } else if (sub_ == "") {
      if (!(("profiles." prof) in has) && !(prof in has)) report("profiles." prof)
    }
    next
  }
  if (match($0, /^[ \t]*#?[ \t]*[A-Za-z0-9_-]+[ \t]*=/)) {
    k = $0
    sub(/^[ \t]*#?[ \t]*/, "", k); sub(/[ \t]*=.*$/, "", k)
    if (prof != "") {
      # A profile table: the key may be written with its profile, with a
      # `profiles.<name>` placeholder, or bare (profile keys and entity kinds).
      base = "profiles." prof (sub_ == "" ? "" : "." sub_)
      if (documented(base "." k) || (k in has)) next
      report(base "." k)
    } else {
      id = (tbl == "") ? k : tbl "." k
      if (!documented(id)) report(id)
    }
  }
}
AWK
  while IFS= read -r msg; do
    [ -n "$msg" ] || continue
    printf '%s\n' "$msg"
    FAILURES=$((FAILURES + 1))
  done < <(awk -v TOML="$TOML" -v DOC="$DOC" -f "$TMP/config.awk" "$DOC" "$TOML")
fi

if [ "$FAILURES" -gt 0 ]; then
  echo "check-docs: $FAILURES problem(s)" >&2
  exit 1
fi
echo "check-docs: ok"
exit 0
