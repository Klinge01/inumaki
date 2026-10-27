// Review Focus 1: a reveal lasts at most 60 s, ends when the window hides
// (the Rust side emits "window-hidden"; the document may also turn hidden),
// does not survive an unmount (a view switch), and an answer that arrives
// after its reason is gone is dropped.
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const handlers: Record<string, () => void> = {};
vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, cb: () => void) => {
    handlers[name] = cb;
    return Promise.resolve(() => delete handlers[name]);
  },
}));

import { REVEAL_MS, useReveal } from "../reveal";
import { useWindowHidden } from "../useWindowHidden";

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

describe("useReveal", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("clears after 60 s", () => {
    const { result } = renderHook(() => useReveal<string>());
    act(() => result.current.show("Qwxzvk Zyxwuria"));
    expect(result.current.value).toBe("Qwxzvk Zyxwuria");
    act(() => vi.advanceTimersByTime(REVEAL_MS - 1));
    expect(result.current.value).toBe("Qwxzvk Zyxwuria");
    act(() => vi.advanceTimersByTime(1));
    expect(result.current.value).toBeNull();
  });

  it("clears when the window hides", async () => {
    const { result } = renderHook(() => useReveal<string>());
    await act(async () => Promise.resolve());
    act(() => result.current.show("x"));
    act(() => handlers["window-hidden"]());
    expect(result.current.value).toBeNull();
    act(() => result.current.show("y"));
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    expect(result.current.value).toBeNull();
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
  });

  it("does not come back after an unmount", () => {
    const first = renderHook(() => useReveal<string>());
    act(() => first.result.current.show("x"));
    first.unmount();
    const second = renderHook(() => useReveal<string>());
    expect(second.result.current.value).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("drops an answer that arrives after the window hid", async () => {
    const { result } = renderHook(() => useReveal<string>());
    await act(async () => Promise.resolve());
    const d = deferred<string>();
    let shown!: Promise<boolean>;
    act(() => void (shown = result.current.request(() => d.promise)));
    act(() => handlers["window-hidden"]());
    await act(async () => {
      d.resolve("Qwxzvk Zyxwuria");
      expect(await shown).toBe(false);
    });
    expect(result.current.value).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("one item at a time: a newer reveal ends the shown one and drops an older answer", async () => {
    const { result } = renderHook(() => useReveal<string>());
    act(() => result.current.show("first"));
    const older = deferred<string>();
    const newer = deferred<string>();
    let a!: Promise<boolean>;
    let b!: Promise<boolean>;
    act(() => void (a = result.current.request(() => older.promise)));
    expect(result.current.value).toBeNull();
    act(() => void (b = result.current.request(() => newer.promise)));
    await act(async () => {
      newer.resolve("newer");
      expect(await b).toBe(true);
      older.resolve("older");
      expect(await a).toBe(false);
    });
    expect(result.current.value).toBe("newer");
  });

  it("a direct show is newer than a pending request", async () => {
    const { result } = renderHook(() => useReveal<string>());
    const older = deferred<string>();
    let a!: Promise<boolean>;
    act(() => void (a = result.current.request(() => older.promise)));
    act(() => result.current.show("direct"));
    await act(async () => {
      older.resolve("older");
      expect(await a).toBe(false);
    });
    expect(result.current.value).toBe("direct");
  });

  it("drops an answer that arrives after an unmount and leaves no timer", async () => {
    const { result, unmount } = renderHook(() => useReveal<string>());
    const d = deferred<string>();
    let shown!: Promise<boolean>;
    act(() => void (shown = result.current.request(() => d.promise)));
    unmount();
    d.resolve("Qwxzvk Zyxwuria");
    expect(await shown).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });
});

// Review M4: minimize and Cmd+H send no "window-hidden"; the holders that
// listen only through useWindowHidden (tokens, snippets, passwords) still clear.
describe("useWindowHidden", () => {
  it("fires on window-hidden and when the document turns hidden", async () => {
    const onHidden = vi.fn();
    const { unmount } = renderHook(() => useWindowHidden(onHidden));
    await act(async () => Promise.resolve());
    act(() => handlers["window-hidden"]());
    expect(onHidden).toHaveBeenCalledTimes(1);
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    expect(onHidden).toHaveBeenCalledTimes(1);
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    expect(onHidden).toHaveBeenCalledTimes(2);
    unmount();
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    expect(onHidden).toHaveBeenCalledTimes(2);
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
  });
});
