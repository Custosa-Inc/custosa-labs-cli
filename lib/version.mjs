/* The package's version, the oldest Node.js it runs on, and how a path in the home folder is shown. One copy of each
  . bin/custosa.mjs imports this before its Node.js check, so it uses only node:fs and
   syntax far older than that check allows. */
import { readFileSync } from "node:fs";

export const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

export const MIN_NODE = Object.freeze([20, 3]); // package.json engines: 20.3 brings AbortSignal.any

/** True when a Node.js version string ("20.3.0") is MIN_NODE or later. */
export function nodeSupported(version) {
  const [major, minor] = String(version).split(".").map(Number);
  return major > MIN_NODE[0] || (major === MIN_NODE[0] && minor >= MIN_NODE[1]);
}

/** path with a leading home folder shown as ~. Only the home folder itself or a path inside it: /home/u2 stays whole. */
export function tilde(path, home) {
  if (!home || !path) return path;
  const base = home.endsWith("/") || home.endsWith("\\") ? home.slice(0, -1) : home;
  if (path === base) return "~";
  const next = path[base.length];
  return path.startsWith(base) && (next === "/" || next === "\\") ? `~${path.slice(base.length)}` : path;
}
