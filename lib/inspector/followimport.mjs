/* One import hop for evidence rules marked follow_import (T28-P1-C5, design T28-P3-C14).
 *
 * An items rule sees one file. A Next.js route handler that loads the session through the app's own helper
 * (`const { error } = await requireAuth([...])`, imported from "@/lib/<guard>", whose body calls auth()) has no control
 * the rule can see, so its item lacks its control and the practice fails. A follow_import evidence rule matches such a
 * call (a bare name called in the handler); after every file has run, this pass follows the name one hop:
 *
 * - Only a handler with an item lacking its control is followed; on any other, the evidence match is dropped.
 * - The name must be one the file imports from a local specifier (relative, @/ or ~/; helpers.resolveLocal). Any other
 *   name (a package import, a name the file declares, a global) is not followed and its evidence match is dropped, as
 *   if the rule had not matched.
 * - Resolved: the specifier names a walked file, parsed, with an export of that name that is a function (export
 *   function, export const f = () => ..., export { f }, export default function). Each item on the same handler whose
 *   rule has a control and lacks it is matched against that control on the function's node, as the worker does on the
 *   item's own node. A hit sets the item's has_control to true. The evidence match is dropped either way: a helper
 *   with no control leaves its item failing, as before.
 * - Not resolved (no walked file there, a file that can't be read or parsed, or no such function export): the evidence
 *   match stays, and core holds the handler's item for a person (an auth-unobserved name), never a fail or a pass.
 *
 * The call is found again by its fingerprint (rule id, path and the node's text), so a line with two calls is never
 * confused. One hop only: a helper that calls another helper is resolved only if its own body holds the control.
 * followImports(rules, matches, files, {root, maxBytes, key}) -> matches (a new array; matches it doesn't touch are the
 * same objects). */
import { readWalked } from "./walkread.mjs";
import { fileURLToPath } from "node:url";
import { resolveLocal } from "./helpers.mjs";
import { parseSync } from "./parse.mjs";
import { fingerprint, normalizeBreaks } from "./rules-worker.mjs";

const JS_LANGS = new Set(["javascript", "typescript", "tsx"]);
const FUNCTION_VALUE = new Set(["arrow_function", "function_expression", "function"]);

const stringValue = (node) => {
  const t = node?.text() ?? "";
  return /^(["'`])(.*)\1$/s.test(t) ? t.slice(1, -1) : null;
};

/* The names a file imports: local name -> {spec, imported}, imported being the export's name or "default". A
 * namespace import binds no bare name and is left out; `import type` binds nothing at run time. */
function importsOf(root) {
  const out = new Map();
  for (const st of root.findAll({ rule: { kind: "import_statement" } })) {
    if (/^import\s+type\s/.test(st.text())) continue;
    const spec = stringValue(st.field("source"));
    if (spec === null) continue;
    const clause = st.children().find((c) => c.kind() === "import_clause");
    if (!clause) continue;
    for (const part of clause.children()) {
      if (part.kind() === "identifier") out.set(part.text(), { spec, imported: "default" });
      if (part.kind() !== "named_imports") continue;
      for (const s of part.children().filter((c) => c.kind() === "import_specifier")) {
        if (/^type\s/.test(s.text())) continue;
        const name = s.field("name")?.text(), alias = s.field("alias")?.text();
        if (name) out.set(alias ?? name, { spec, imported: name });
      }
    }
  }
  return out;
}

/* The node a function export of `name` is (the function declaration, or the variable declarator holding the arrow or
 * function expression, as the items rules match them), or null. */
function exportedFunction(root, name) {
  const local = new Map(); // a top-level function or const in the file, by name
  for (const top of root.children()) {
    const decl = top.kind() === "export_statement" ? top.field("declaration") : top;
    if (!decl) continue;
    if (decl.kind() === "function_declaration" && decl.field("name")) local.set(decl.field("name").text(), decl);
    if (decl.kind() === "lexical_declaration" || decl.kind() === "variable_declaration") {
      for (const d of decl.children().filter((c) => c.kind() === "variable_declarator")) {
        if (FUNCTION_VALUE.has(d.field("value")?.kind()) && d.field("name")) local.set(d.field("name").text(), d);
      }
    }
  }
  for (const top of root.children().filter((c) => c.kind() === "export_statement")) {
    const decl = top.field("declaration");
    const isDefault = top.children().some((c) => c.kind() === "default");
    if (decl) {
      if (isDefault && name === "default" && decl.kind() === "function_declaration") return decl;
      if (decl.kind() === "function_declaration" && decl.field("name")?.text() === name) return decl;
      if (decl.kind() === "lexical_declaration" || decl.kind() === "variable_declaration") {
        const d = decl.children().find((c) => c.kind() === "variable_declarator" && c.field("name")?.text() === name);
        if (d && FUNCTION_VALUE.has(d.field("value")?.kind())) return d;
      }
      continue;
    }
    const value = top.field("value");
    if (isDefault && name === "default" && value) {
      if (value.kind() === "identifier") return local.get(value.text()) ?? null;
      if (FUNCTION_VALUE.has(value.kind()) || value.kind() === "function_declaration") return value;
    }
    const clause = top.children().find((c) => c.kind() === "export_clause");
    if (clause && !top.field("source")) {
      for (const s of clause.children().filter((c) => c.kind() === "export_specifier")) {
        const own = s.field("name")?.text(), as = s.field("alias")?.text() ?? own;
        if (as === name && local.has(own)) return local.get(own);
      }
    }
  }
  return null;
}

export async function followImports(rules, matches, files, { root = null, maxBytes = Infinity, key }) {
  const byId = new Map(rules.map((r) => [r.id, r]));
  const followed = matches.filter((m) => m.kind === "evidence" && byId.get(m.rule_id)?.follow_import === true);
  if (!followed.length) return matches;
  const paths = new Set(files.map((f) => f.path));
  const byPath = new Map(files.map((f) => [f.path, f]));
  const parsed = new Map(); // path -> root node, or null when it can't be read or parsed
  const rootDir = root instanceof URL ? fileURLToPath(root) : root;
  async function parsedRoot(path) {
    if (parsed.has(path)) return parsed.get(path);
    let out = null;
    const f = byPath.get(path);
    const lang = f?.lang ?? (path.endsWith(".tsx") ? "tsx" : /\.(?:c|m)?tsx?$/.test(path) ? "typescript" : "javascript");
    let text = typeof f?.text === "string" ? f.text : null;
    if (text === null && rootDir && f) {
      const read = await readWalked(rootDir, path, maxBytes);
      text = read.buf ? read.buf.toString("utf8") : null;
    }
    if (text !== null && Buffer.byteLength(text, "utf8") <= maxBytes && JS_LANGS.has(lang)) {
      try { out = parseSync(lang, normalizeBreaks(text)).root(); } catch { out = null; }
    }
    parsed.set(path, out);
    return out;
  }
  const drop = new Set();
  const controlled = new Set();
  // The items on a handler that lack their control: only those are worth a hop.
  const open = (ev) => matches.filter((m) => m.kind === "item" && m.has_control === false && m.handler !== null
    && m.handler === ev.handler && m.practice_id === ev.practice_id && m.path === ev.path);
  for (const ev of followed) {
    const rule = byId.get(ev.rule_id);
    if (!open(ev).length) { drop.add(ev); continue; } // nothing on its handler lacks a control: nothing to hold
    const fileRoot = JS_LANGS.has(rule.language) ? await parsedRoot(ev.path) : null;
    if (!fileRoot) continue; // the file the rule ran on can't be read again: keep the evidence (held, never a fail)
    const call = fileRoot.findAll({ rule: rule.rule }).find((n) => fingerprint(key, rule.id, ev.path, n.text()) === ev.fingerprint);
    const callee = call?.field("function");
    if (!callee || callee.kind() !== "identifier") { drop.add(ev); continue; }
    const bound = importsOf(fileRoot).get(callee.text());
    const target = bound ? resolveLocal(bound.spec, ev.path, paths, rule.language) : null;
    const local = bound && (/^[@~]\//.test(bound.spec) || bound.spec.startsWith("."));
    if (!local) { drop.add(ev); continue; } // a package, a name the file declares or a global: not followed
    if (!target) continue; // a local specifier with no walked file: held
    const helperRoot = await parsedRoot(target);
    const fn = helperRoot ? exportedFunction(helperRoot, bound.imported) : null;
    if (!fn) continue; // unreadable, unparsable, or no such function export: held
    drop.add(ev);
    for (const m of open(ev)) {
      const items = byId.get(m.rule_id);
      if (!items?.control || items.language !== rule.language) continue;
      try { if (fn.matches({ rule: items.control })) controlled.add(m); } catch { /* a control that fails here proves nothing */ }
    }
  }
  return matches.filter((m) => !drop.has(m)).map((m) => (controlled.has(m) ? { ...m, has_control: true } : m));
}
