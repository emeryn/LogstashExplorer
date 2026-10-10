// Light / dark theme. The preference ("system" by default) is a per-browser convenience kept in localStorage;
// every access is guarded because storage can be unavailable (private mode, blocked site data).
import { useEffect, useState } from "react";

export type ThemePref = "system" | "light" | "dark";
const KEY = "lsx.theme";
const media = () => window.matchMedia("(prefers-color-scheme: light)");

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" || v === "system" ? v : "system";
  } catch {
    return "system";
  }
}

function resolve(pref: ThemePref): "light" | "dark" {
  return pref === "system" ? (media().matches ? "light" : "dark") : pref;
}

export function applyTheme(pref: ThemePref = readPref()): "light" | "dark" {
  const theme = resolve(pref);
  document.documentElement.dataset.theme = theme;
  window.dispatchEvent(new CustomEvent("lsx:theme", { detail: theme }));
  return theme;
}

/** Current preference + resolved theme; re-resolves when the OS theme changes in "system" mode. */
export function useTheme() {
  const [pref, setPrefState] = useState<ThemePref>(readPref);
  const [theme, setTheme] = useState<"light" | "dark">(() => resolve(pref));

  useEffect(() => {
    setTheme(applyTheme(pref));
    if (pref !== "system") return;
    const mq = media();
    const onChange = () => setTheme(applyTheme("system"));
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [pref]);

  const setPref = (next: ThemePref) => {
    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* not persisted: still applied for this page */
    }
    setPrefState(next);
  };
  return { pref, theme, setPref };
}

/** Monaco theme following the app theme (for editors that are not inside the App tree's hook). */
export function useEditorTheme(): string {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || "dark");
  useEffect(() => {
    const onTheme = (e: Event) => setTheme((e as CustomEvent<string>).detail);
    window.addEventListener("lsx:theme", onTheme);
    return () => window.removeEventListener("lsx:theme", onTheme);
  }, []);
  return theme === "light" ? "vs" : "vs-dark";
}
