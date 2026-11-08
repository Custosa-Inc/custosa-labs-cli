/* The shared fingerprint of a match: a keyed hash of a walk of the matched node, the
 * same on every machine of the project, that changes with any edit to what the node does and not with its
 * formatting. The core keys a match-based decision's fact token with it, so a committed decision reopens when the
 * matched code changes.
 *
 *   HMAC-SHA256(content_key, SHARED_FP_VERSION \x1f rule_id \x1f path \x1f walk(node))
 *
 * path is the local repository path, never its per-install hashed form. The walk is a preorder walk emitting items,
 * each with its line breaks normalised (\r\n and a lone \r become \n). Each item is escaped (a backslash becomes two,
 * \x1f becomes backslash, "x1f") and then joined by \x1f, so two different walks never join to the same string
 * (joinWalk). Version 2: version 1 joined the items unescaped.
 *   1. a comment node emits nothing and its subtree is skipped, except a PHP docblock (text starting with slash and
 *      two stars), which Symfony and Doctrine execute: it is walked as a leaf;
 *   2. a leaf emits "L" + its text, verbatim;
 *   3. a node with children emits "<" + its kind first and ">" last when it is named, and between its children's
 *      items each gap of its text no child covers, as "G" + the gap, verbatim: every gap inside a string-like kind,
 *      whitespace included; elsewhere, only gaps that are not just whitespace.
 * Gaps are sliced from the exact text passed to parseSync, in the unit range().index reports, never from
 * root.text() (which drops leading whitespace and a BOM).
 *
 * The self-check: every L and G item's text, joined, with all whitespace removed, must equal the node's text with
 * all whitespace and every skipped comment removed, and every leaf sliced from the text must equal the binding's own
 * text of that leaf (the joined check alone can't see an offset shift, since both sides slice the same string).
 * Otherwise the match gets null, and the core answers no_content_key: an unknown grammar quirk or an offset error
 * fails safe, never open. */
import { createHmac } from "node:crypto";

export const SHARED_FP_VERSION = "2";
const SEP = "\x1f";

// The kinds that hold a string's contents (§3.5): a kind that may have one of these as a child is string-like.
export const STRING_CONTENT_KINDS = Object.freeze(["string_content", "string_fragment", "nowdoc_string",
  "escape_sequence", "multiline_string_fragment", "interpreted_string_literal_content", "raw_string_literal_content",
  "heredoc_content"]);
// Added on top of each grammar's derived kinds (§3.5).
export const LISTED_STRING_LIKE = Object.freeze(["string", "string_content", "string_fragment", "format_specifier",
  "character_literal", "template_string", "single_quote_scalar", "double_quote_scalar", "block_scalar",
  "heredoc_body", "nowdoc_body"]);

/* Per routed language: the comment kinds, and the string-like kinds derived from the grammar's node-types.json
 * (test/walk.test.mjs derives them again and fails on any difference). TS, TSX and JS are built into
 * @ast-grep/napi 0.45.3, which ships no node-types.json. Their lists were derived the same way, once, from the
 * versions its Cargo.lock pins: tree-sitter-typescript 0.23.2 (typescript/src sha256 c790a733..., tsx/src
 * 78b57891...) and tree-sitter-javascript 0.25.0 (src 188a8baa...). The files are not copied here; a test checks
 * the lists against napi's own parse instead. Re-derive them when napi moves. */
const DERIVED = {
  go: ["interpreted_string_literal", "raw_string_literal"],
  java: ["string_literal"],
  json: ["string"],
  kotlin: ["string_literal"],
  php: ["encapsed_string", "heredoc_body", "nowdoc_body", "shell_command_expression", "string"],
  python: ["string", "string_content"],
  ruby: ["bare_string", "bare_symbol", "delimited_symbol", "heredoc_body", "regex", "string", "subshell"],
  yaml: ["double_quote_scalar", "single_quote_scalar"],
  typescript: ["string", "template_literal_type", "template_string"],
  tsx: ["string", "template_literal_type", "template_string"],
  javascript: ["string", "template_string"],
};
const COMMENTS = {
  go: ["comment"], java: ["line_comment", "block_comment"], json: ["comment"],
  kotlin: ["line_comment", "multiline_comment"], php: ["comment"], python: ["comment"], ruby: ["comment"],
  yaml: ["comment"], typescript: ["comment", "html_comment"], tsx: ["comment", "html_comment"],
  javascript: ["comment", "html_comment"],
};
const BASE_COMMENTS = ["comment", "line_comment", "block_comment", "html_comment"];

export const KINDS = Object.freeze(Object.fromEntries(Object.keys(DERIVED).map((lang) => [lang, Object.freeze({
  comments: new Set([...BASE_COMMENTS, ...COMMENTS[lang]]),
  stringLike: new Set([...LISTED_STRING_LIKE, ...DERIVED[lang]]),
})])));
export const DERIVED_STRING_LIKE = DERIVED;

const breaks = (s) => s.replace(/\r\n?/g, "\n");
const bare = (s) => s.replace(/\s+/g, "");

/* The walk's items for `node` in `text` (the exact string parsed), or null when the language has no kind table or
 * the self-check fails. */
export function walk(node, lang, text) {
  const kinds = KINDS[lang];
  if (!kinds) return null;
  const items = [];
  const skipped = [];
  let shifted = false;
  const slice = (n) => text.slice(n.range().start.index, n.range().end.index);
  const visit = (n) => {
    const own = slice(n);
    if (kinds.comments.has(n.kind())) {
      if (!(lang === "php" && own.startsWith("/**"))) {
        skipped.push(n.range());
        return;
      }
      items.push("L" + breaks(own));
      return;
    }
    const children = n.children();
    if (!children.length) {
      shifted ||= own !== n.text();
      items.push("L" + breaks(own));
      return;
    }
    const named = n.isNamed();
    const stringLike = kinds.stringLike.has(n.kind());
    const gap = (from, to) => {
      const g = text.slice(from, to);
      if (g && (stringLike || /\S/.test(g))) items.push("G" + breaks(g));
    };
    if (named) items.push("<" + n.kind());
    let at = n.range().start.index;
    for (const c of children) {
      gap(at, c.range().start.index);
      visit(c);
      at = c.range().end.index;
    }
    gap(at, n.range().end.index);
    if (named) items.push(">");
  };
  visit(node);
  const start = node.range().start.index;
  let rest = "";
  let at = start;
  for (const r of skipped.sort((a, b) => a.start.index - b.start.index)) {
    rest += text.slice(at, r.start.index);
    at = r.end.index;
  }
  rest += text.slice(at, node.range().end.index);
  const said = items.filter((i) => i[0] === "L" || i[0] === "G").map((i) => i.slice(1)).join("");
  return !shifted && bare(said) === bare(breaks(rest)) ? items : null;
}

/* The walk's items as one string: each escaped, then joined by SEP. A source text holding \x1f or a backslash can't
 * pass for an item boundary. */
export const joinWalk = (items) => items.map((i) => i.replace(/\\/g, "\\\\").replace(/\x1f/g, "\\x1f")).join(SEP);

/* 64 hex, or null when there is no content key or the walk fails its self-check. `path` is the local repository
 * path, never its per-install hashed form. */
export function sharedFingerprint(contentKey, ruleId, path, node, lang, text) {
  if (!contentKey) return null;
  const items = walk(node, lang, text);
  if (!items) return null;
  return createHmac("sha256", Buffer.from(contentKey, "hex"))
    .update([SHARED_FP_VERSION, ruleId, path, joinWalk(items)].join(SEP), "utf8").digest("hex");
}
