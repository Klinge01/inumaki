// Inspect & recover sends UTF-8 byte offsets into the NFC-normalized input
// (M6 spec §6.4); the textarea gives UTF-16 indices.
import { describe, expect, it } from "vitest";
import { byteRange, nfc, utf16Index, utf8Offset } from "../nfc";

describe("nfc offsets", () => {
  it("normalizes decomposed input and converts both ways", () => {
    // Decomposed input (e + U+0301, u + U+0308): what macOS file names and some
    // pastes give. An astral character (a surrogate pair, 4 UTF-8 bytes) sits
    // before the span too.
    const raw = "Cafe\u0301 \u{1F600} Mu\u0308ller";
    expect(raw).not.toBe(raw.normalize("NFC"));
    const text = nfc(raw);
    expect(text).toBe("Café \u{1F600} Müller");
    expect(text.length).toBeLessThan(raw.length);
    const start = text.indexOf("Müller");
    const r = byteRange(text, start, start + "Müller".length);
    // "Café " = 6 bytes, the emoji 4, the space 1.
    expect(r).toEqual({ start: 11, end: 18 });
    const bytes = new TextEncoder().encode(text);
    expect(new TextDecoder().decode(bytes.slice(r.start, r.end))).toBe("Müller");
    expect(text.slice(utf16Index(text, r.start), utf16Index(text, r.end))).toBe("Müller");
    for (let i = 0; i <= text.length; i++) {
      const c = text.charCodeAt(i - 1);
      if (i > 0 && c >= 0xd800 && c <= 0xdbff) continue; // i is inside a surrogate pair
      expect(utf16Index(text, utf8Offset(text, i))).toBe(i);
    }
  });

  it("maps a byte inside a character to the character's end", () => {
    const text = "é\u{1F600}x";
    expect(utf16Index(text, 1)).toBe(1); // inside é (2 bytes)
    expect(utf16Index(text, 3)).toBe(3); // inside the emoji: after its surrogate pair
    expect(utf16Index(text, 6)).toBe(3);
    expect(utf16Index(text, 7)).toBe(4);
  });
});
