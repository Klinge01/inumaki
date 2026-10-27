// A confirmation sheet opens with Cancel focused (a stray Enter never confirms), closes on Escape, keeps Tab
// inside the panel, and gives the focus back to its opener.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Confirm } from "../components/Confirm";

afterEach(cleanup);

describe("Confirm sheet", () => {
  it("Cancel has focus when a sheet opens", () => {
    render(<Confirm text="Remove it?" verb="Remove" onYes={() => undefined} onNo={() => undefined} />);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancel" }));
  });

  it("Escape calls onNo, not onYes", () => {
    const onYes = vi.fn();
    const onNo = vi.fn();
    render(<Confirm text="Remove it?" verb="Remove" onYes={onYes} onNo={onNo} />);
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    expect(onNo).toHaveBeenCalledTimes(1);
    expect(onYes).not.toHaveBeenCalled();
  });

  it("Tab from the confirm button wraps to Cancel", () => {
    render(<Confirm text="Remove it?" verb="Remove" onYes={() => undefined} onNo={() => undefined} />);
    const verb = screen.getByRole("button", { name: "Remove" });
    verb.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(verb);
  });

  it("focus returns to the opener after Cancel", () => {
    function Host() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Open
          </button>
          {open && <Confirm text="Remove it?" verb="Remove" onYes={() => undefined} onNo={() => setOpen(false)} />}
        </>
      );
    }
    render(<Host />);
    const opener = screen.getByRole("button", { name: "Open" });
    opener.focus();
    fireEvent.click(opener);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("a titled sheet is named by its title, not by its whole body", () => {
    render(<Confirm title="Remove the folder?" text="Long body text." verb="Remove" onYes={() => undefined} onNo={() => undefined} />);
    expect(screen.getByRole("alertdialog", { name: "Remove the folder?" })).toBeTruthy();
  });
});
