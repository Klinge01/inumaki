// Navigation between views (spec section 4, plan R3). `App` provides `NavContext`; views and
// components that open another view call `useNavigate()`. Without a provider (tests render
// views standalone) navigating does nothing.
import { createContext, useContext } from "react";
import type { HarnessId } from "./types";

export type ViewId =
  | "overview"
  | "mcp"
  | "email"
  | "folders"
  | "activity"
  | "inspect"
  | "settings"
  | `connection:${HarnessId}`
  | "connection:other";

export type Navigate = (id: ViewId) => void;

export const NavContext = createContext<Navigate>(() => undefined);

export const useNavigate = (): Navigate => useContext(NavContext);
