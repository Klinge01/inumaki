// Offsets for redactions and inspected spans: the daemon counts UTF-8 bytes
// of the NFC-normalized text (M6 spec §6.4); a textarea counts UTF-16 code
// units. Both conversions run over the same, already normalized string.
const enc = new TextEncoder();

export function nfc(text: string): string {
  return text.normalize("NFC");
}

/** UTF-8 length of the code point `cp` (a lone surrogate encodes as U+FFFD: 3 bytes). */
function utf8Len(cp: number): number {
  return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
}

/** UTF-8 byte offset of UTF-16 index `i` in `s`. */
export function utf8Offset(s: string, i: number): number {
  return enc.encode(s.slice(0, i)).length;
}

/** UTF-16 index of UTF-8 byte offset `b` in `s` (a byte inside a character maps to its end). */
export function utf16Index(s: string, b: number): number {
  let bytes = 0;
  let i = 0;
  for (const ch of s) {
    if (bytes >= b) return i;
    bytes += utf8Len(ch.codePointAt(0) ?? 0);
    i += ch.length;
  }
  return i;
}

/** Byte range of the UTF-16 selection [start, end) of `s`. */
export function byteRange(s: string, start: number, end: number): { start: number; end: number } {
  return { start: utf8Offset(s, start), end: utf8Offset(s, end) };
}
