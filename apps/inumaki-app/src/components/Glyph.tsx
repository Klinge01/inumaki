/** Status tones (spec section 3). The tone is data, so tests read `data-tone`, not a class. */
export type Tone = "on" | "unv" | "off" | "na" | "bad" | "protected";

/** The 10 px status glyph. Decorative: the word next to it carries the meaning. */
export function Glyph({ tone }: { tone: Tone }) {
  return <span className="glyph" data-tone={tone} aria-hidden="true" />;
}
