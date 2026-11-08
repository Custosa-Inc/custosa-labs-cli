#!/usr/bin/env node
// Rewrites JSON and JSONL test fixtures so no fake key in them is spelled as a key in the file's bytes.
// Inside a JSON string, one character of each key-shaped value becomes a \uXXXX escape. JSON.parse gives the
// same string as before, so every test reads the same input; only GitHub push protection and gitleaks, which
// read the raw bytes, stop seeing a key.
//
//   node scripts/escape-fake-keys.mjs <file or folder>...           rewrite in place
//   node scripts/escape-fake-keys.mjs --check <file or folder>...   exit 1 if a file would change
//
// Run it on any fixture a script writes (for example a regenerated screen-parity.<sha>.json) before committing.
// It knows the shapes the tests use today. CI's gitleaks job still decides: a shape this list misses fails there,
// and then belongs here. In .mjs files write the key with a \x escape or a split string by hand (CONTRIBUTING.md).
import { readFileSync, writeFileSync, statSync, readdirSync } from "node:fs";
import { join } from "node:path";

// Each shape is matched on the parsed string. `at` is the index, inside the match (or inside group 1 when the
// pattern has one), of the character that gets escaped. An escape adds hex digits (\u00XX), so in a uuid it goes
// in the second group, where those digits can't make an 8-digit run.
const SHAPES = [
  { re: /[rs]k_(?:live|test|prod)_/g, at: 2 },
  { re: /gh[pousr]_[A-Za-z0-9]{20,}/g, at: 3 },
  { re: /github_pat_/g, at: 6 },
  { re: /(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/g, at: 1, skip: /^AKIAIOSFODNN7EXAMPLE$/ },
  { re: /(?:AC|SK)[0-9a-fA-F]{32}/g, at: 1 },
  { re: /xox[baprs]-[0-9]{6,}/g, at: 4 },
  { re: /glpat-/g, at: 5 },
  { re: /npm_[A-Za-z0-9]{30,}/g, at: 3 },
  { re: /npm\b[^\n]{0,30}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi, at: 9 },
  { re: /sb_secret_|sbp_[0-9a-f]{20,}/g, at: 2 },
  { re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY/g, at: 0 },
  { re: /\bey[A-Za-z0-9_-]{10,}\.ey/g, at: 1 },
  // Mailgun: GitHub matches the bare shape; gitleaks' rule needs the word "mailgun" nearby, so only GitHub sees it.
  { re: /\bkey-[0-9a-f]{32}\b/g, at: 3 },
  // A cue word, an assignment mark, then a value: gitleaks' generic-api-key and the vendor rules built like it.
  {
    re: /(?:key|token|secret|passw(?:or)?d|api|auth|credential|creds|access|datadog)[\w .-]{0,20}[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([\w.=+/-]{10,150})/gi,
    at: 4,
    keep: (value) => entropy(value) >= 3.5 && /[0-9=]/.test(value),
  },
];

function entropy(s) {
  const n = new Map();
  for (const c of s) n.set(c, (n.get(c) ?? 0) + 1);
  let h = 0;
  for (const k of n.values()) h -= (k / s.length) * Math.log2(k / s.length);
  return h;
}

const hex4 = (code) => "\\u" + code.toString(16).padStart(4, "0");

// One JSON string's raw content (between the quotes) to its escaped form.
function escapeString(raw) {
  const units = [];
  for (let i = 0; i < raw.length; ) {
    const len = raw[i] !== "\\" ? 1 : raw[i + 1] === "u" ? 6 : 2;
    const unit = raw.slice(i, i + len);
    units.push({ raw: unit, ch: len === 1 ? unit : JSON.parse(`"${unit}"`) });
    i += len;
  }
  const text = units.map((u) => u.ch).join("");
  const targets = new Set();
  for (const { re, at, skip, keep } of SHAPES) {
    // Overlapping matches too: the value after one cue word can hold a second cue word and its own value.
    re.lastIndex = 0;
    for (let m; (m = re.exec(text)); re.lastIndex = m.index + 1) {
      if (skip?.test(m[0])) continue;
      const start = m[1] === undefined ? m.index : m.index + m[0].lastIndexOf(m[1]);
      if (keep && !keep(m[1] ?? m[0])) continue;
      targets.add(start + at);
    }
  }
  for (const t of targets) if (units[t].raw.length === 1) units[t].raw = hex4(units[t].ch.charCodeAt(0));
  return units.map((u) => u.raw).join("");
}

export function escapeJsonText(text) {
  let out = "";
  for (let i = 0; i < text.length; ) {
    if (text[i] !== '"') { out += text[i++]; continue; }
    let j = i + 1;
    while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
    out += '"' + escapeString(text.slice(i + 1, j)) + '"';
    i = j + 1;
  }
  return out;
}

function filesOf(path) {
  if (!statSync(path).isDirectory()) return [path];
  return readdirSync(path, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? filesOf(join(path, e.name)) : /\.jsonl?$/.test(e.name) ? [join(path, e.name)] : []);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const check = args[0] === "--check";
  const paths = check ? args.slice(1) : args;
  if (!paths.length) { console.error("usage: escape-fake-keys.mjs [--check] <file or folder>..."); process.exit(2); }
  let changed = 0;
  for (const file of paths.flatMap(filesOf)) {
    const text = readFileSync(file, "utf8");
    const next = escapeJsonText(text);
    if (next === text) continue;
    changed++;
    if (check) console.error(`${file}: a key-shaped value is not escaped; run node scripts/escape-fake-keys.mjs ${file}`);
    else writeFileSync(file, next);
  }
  if (check && changed) process.exit(1);
  if (!check) console.log(`${changed} file(s) rewritten`);
}
