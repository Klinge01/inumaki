/** "14:32" for a time on today's local date, "Oct 11, 2026, 14:32" otherwise. `at` is Unix seconds. */
export function formatCheckTime(at: number, now: Date = new Date()): string {
  const d = new Date(at * 1000);
  const time = new Intl.DateTimeFormat(undefined, { timeStyle: "short" }).format(d);
  if (d.toDateString() === now.toDateString()) return time;
  return `${new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(d)}, ${time}`;
}
