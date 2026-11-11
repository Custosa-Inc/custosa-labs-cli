/* How names and paths are sent (evaluator_api.md 1.4): as the project has them when they fit their field's pattern,
 * else hashed, never dropped. A hashed name is u_ plus the first 16 lowercase hex digits of HMAC-SHA256 with the
 * per-install key over its UTF-8 bytes. Paths are hashed segment by segment (the file is still analysed); a path
 * still over 512 characters is sent as one hash of the whole path.
 *
 * A segment that holds a secret is hashed whatever its pattern (holdsSecret, below). Known limit: a key split across
 * nested directories (ghp/aB3dE5gH7jK9mN1pQ3s/x.ts) is judged one segment at a time, so a piece too short to look like
 * a key on its own is sent as written. */
import { createHmac } from "node:crypto";
import { IDENTIFIER, PATH, PATH_MAX } from "./contracts.mjs";
import { scanSecrets } from "./secrets.mjs";
import { freeTextShape, localRecordShape, proseRecordShape, screenText, screenValue } from "./valueshape.mjs";

const PATH_RE = new RegExp(PATH);
const IDENTIFIER_RE = new RegExp(IDENTIFIER);
// enums.PATH_SEGMENT_PATTERN: one segment of a path, never "." or "..".
export const PATH_SEGMENT = "^(?!\\.\\.?$)[A-Za-z0-9_.@+$\\[\\]()~-]{1,255}$";
const SEGMENT_RE = new RegExp(PATH_SEGMENT);

export function hashed(key, text) {
  return `u_${createHmac("sha256", key).update(String(text), "utf8").digest("hex").slice(0, 16)}`;
}

/* Whether a name holds a secret. Over-hashing a name is safe; leaking one is not. Two checks, cached per name:
 *  1. Generic, whatever the boundaries: a known key prefix anywhere in the name (KEY_PREFIX), or a run of 20 or more
 *     letters and digits that mixes both (a high-entropy token; a git SHA-named file is hashed too, which is fine).
 *  2. the secret scan's own patterns, which want a boundary that isn't `_` or a letter: run over the name whole, without its
 *     extension, each part between `_`, `-`, `.` or a space, every suffix starting after one of them and every prefix
 *     ending before one. A scan that fails counts as a secret. The fingerprints are never used: a throwaway key.
 * Both run on the name as written and with %XX escapes decoded. */
const SCAN_KEY = Buffer.alloc(32);
const secretNames = new Map();
const SECRET_CACHE_MAX = 200_000;
// Each separator written either way (`_` or `-`): a name is often a key with its punctuation swapped.
/* Known key prefixes (the secret scan's providers in secret-patterns.mjs and the common ones it doesn't list), each a secret only
 * when followed by a body of its known shape and length (BODY), so risk_test_utils.ts or ASIAN_COUNTRIES.json stay
 * clear. In a prefix, a separator (_ - .) matches any of the three: a name is often a key with its punctuation swapped
 * (sk.live.<body>). */
const KEY_PREFIXES = [
  // [prefix, case-sensitive, body]: a body names the token's known shape and length (BODY below)
  ["sk_live_", false, "stripe"], ["sk_test_", false, "stripe"], ["rk_live_", false, "stripe"], ["rk_test_", false, "stripe"],
  ["whsec_", false, "whsec"], ["ghp_", false, "alnum"], ["gho_", false, "alnum"], ["ghs_", false, "alnum"],
  ["ghu_", false, "alnum"], ["ghr_", false, "alnum"], ["github_pat_", false, "ghpat"], ["xoxa-", false, "slack"],
  ["xoxb-", false, "slack"], ["xoxp-", false, "slack"], ["xoxr-", false, "slack"], ["xoxs-", false, "slack"],
  ["xapp-", false, "slack"], ["sb_secret_", false, "url20"], ["sk-proj-", false, "url40"], ["sk-svcacct-", false, "url40"],
  ["sk-admin-", false, "url40"], ["sk-ant-", false, "url32"], ["sk-", false, "alnum"], ["sbp_", false, "alnum"],
  ["glpat-", false, "glpat"], ["hf_", false, "alnum"], ["lin_api_", false, "alnum"], ["pypi-", false, "url40"],
  ["npm_", false, "alnum"], ["shpat_", false, "alnum"], ["shpss_", false, "alnum"], ["dop_v1_", false, "alnum"],
  ["SG.", true, "sendgrid"], ["AIza", true, "google"], ["ya29.", true, "url40"], ["eyJ", true, "jwt"],
  ["AKIA", true, "upper"], ["ASIA", true, "upper"], ["ABIA", true, "upper"], ["ACCA", true, "upper"],
  ["akia", false, "alnum"], ["asia", false, "lowerAws"],
];
const escape = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/* Each body is the token's own shape at its known length: a body that long is a secret whatever its letters (a
 * letters-only glpat- token included); a shorter one stays clear, so sk-live-preview-component.tsx and
 * whsec_handler_for_stripe.ts are not keys. A re-punctuated name (sk.live.51Habc.defg...) still counts when it holds a
 * digit and reaches the same length with _ - . inside. */
const repunct = (n) => `(?=[A-Za-z0-9_.-]*[0-9])[A-Za-z0-9][A-Za-z0-9_.-]{${n - 1},}`;
const BODY = {
  alnum: "[A-Za-z0-9]{16}", jwt: "[A-Za-z0-9_-]{10}", upper: "[A-Z0-9]{16}", lowerAws: "[a-z0-9]{16}",
  stripe: `(?:[A-Za-z0-9]{24}|${repunct(24)})`, // sk_live_ and kin: 24 or more letters and digits
  whsec: `(?:[A-Za-z0-9+/=]{32}|${repunct(32)})`, // Stripe webhook secrets: 32 or more base64 characters
  ghpat: "[A-Za-z0-9_]{40}", // github_pat_: 22, _, 59
  // Slack: 24 or more body characters are a secret whatever they hold; a shorter body only with a digit, so
  // xoxb-bot-token-handler.ts and xapp-config-settings.json stay clear.
  slack: "(?:[A-Za-z0-9_.-]{24}|(?=[A-Za-z0-9_.-]*[0-9])[A-Za-z0-9_.-]{20})",
  glpat: "[A-Za-z0-9_-]{20}", // GitLab personal access tokens: 20 characters, any letters, - and _ included
  url20: "[A-Za-z0-9_-]{20}", url32: "[A-Za-z0-9_-]{32}", url40: "[A-Za-z0-9_.-]{40}",
  sendgrid: "[A-Za-z0-9_-]{22}[_.-][A-Za-z0-9_-]{20}", google: "[A-Za-z0-9_-]{35}",
};
const prefixRe = (p) => p.split(/([_.-])/).map((x) => (/^[_.-]$/.test(x) ? "[_.-]" : escape(x))).join("");
export const KEY_PREFIX = new RegExp(KEY_PREFIXES.filter(([, cased]) => !cased).map(([p, , b]) => `${prefixRe(p)}${BODY[b]}`).join("|"), "i");
const KEY_PREFIX_CASED = new RegExp(KEY_PREFIXES.filter(([, cased]) => cased).map(([p, , b]) => `${prefixRe(p)}${BODY[b]}`).join("|"));
const MIXED_RUN = /[A-Za-z0-9]{20,}/g;
const SEPARATOR = /[_\-. ]/;

function genericSecret(text) {
  if (KEY_PREFIX.test(text) || KEY_PREFIX_CASED.test(text)) return true;
  for (const m of text.matchAll(MIXED_RUN)) if (/[A-Za-z]/.test(m[0]) && /[0-9]/.test(m[0])) return true;
  return false;
}

function candidatesOf(text) {
  const out = new Set([text]);
  const dot = text.lastIndexOf(".");
  if (dot > 0) out.add(text.slice(0, dot));
  for (const part of text.split(/[_\-. ]+/)) if (part) out.add(part);
  for (let i = 0; i < text.length; i++) {
    if (!SEPARATOR.test(text[i])) continue;
    if (i + 1 < text.length) out.add(text.slice(i + 1)); // a suffix starting after a separator
    if (i > 0) out.add(text.slice(0, i)); // a prefix ending before one
  }
  return out;
}

export function holdsSecret(name) {
  const text = String(name);
  if (secretNames.has(text)) return secretNames.get(text);
  let decoded = text;
  try { decoded = decodeURIComponent(text); } catch { /* not escaped */ }
  const forms = decoded === text ? [text] : [text, decoded];
  let found = forms.some(genericSecret);
  if (!found) {
    try {
      const lines = new Set();
      for (const f of forms) for (const c of candidatesOf(f)) lines.add(c);
      const out = scanSecrets([{ path: "name", text: [...lines].join("\n") }], { key: SCAN_KEY });
      found = out.secrets.length > 0 || out.truncated.length > 0;
    } catch { found = true; }
  }
  if (secretNames.size >= SECRET_CACHE_MAX) secretNames.clear();
  secretNames.set(text, found);
  return found;
}

/* Whether the evaluator's value-shape screen (valueshape.mjs) would refuse this text: an email address, an
 * SSN, a phone number, a long digit run, a card number, an IP address, a date beside a name, or a secret. Names and
 * paths go through this one; free text through holdsFreeTextValue. Cached. */
const recordNames = new Map();
export function holdsRecordValue(text) {
  const t = String(text);
  if (recordNames.has(t)) return recordNames.get(t);
  const hit = screenValue(t);
  if (recordNames.size >= SECRET_CACHE_MAX) recordNames.clear();
  recordNames.set(t, hit);
  return hit;
}

/* What core's prose_value_spans refuses: the value screen and valueshape.proseRecordShape. A verdict's
 * searched roots go through this one. Read without the hash masking names and paths get, as core does. */
export function holdsProseValue(text) {
  return holdsRecordValue(text) || screenText(String(text)) || proseRecordShape(String(text));
}

/* Free text the assistant wrote (a verdict's reason, a concern's text, a decider_ref): holdsProseValue, and also
 * valueshape.localRecordShape (so names and paths are sent as before) and
 * valueshape.freeTextShape. */
export function holdsFreeTextValue(text) {
  return holdsProseValue(text) || localRecordShape(String(text)) || freeTextShape(String(text));
}

/* A run of 24 or more letters that reads as a random token rather than words: few vowels, or mostly one- and
 * two-letter case humps (aBcDeF...). Words run together, in any case style (FacilitySubscriptionPayment,
 * patientmedicationadministrations), stay names, and so does a run that splits at case into two or more words
 * (caseWords: ConsentRecordsController, whose vowel share is 0.29). A heuristic: over-hashing is safe, leaking is not.
 * A table name and a path segment are judged alike (exports/QwErTyUiOpAsDfGhJkLzXcVbNm.json). */
export function letterToken(text) {
  for (const [run] of text.matchAll(/[A-Za-z]{24,}/g)) {
    const vowels = (run.match(/[aeiouyAEIOUY]/g) ?? []).length / run.length;
    const humps = run.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])/g) ?? [run];
    if (caseWords(humps)) continue;
    if (vowels < 0.3 || humps.filter((h) => h.length <= 2).length * 2 >= humps.length) return true;
  }
  return false;
}
/* Every case hump reads as a word: 3 to 14 letters, at least a sixth of them vowels (y counts; String passes), and no
 * 4 consonants in a row. One hump is not enough, so a run in one case stays judged by its vowels. Of random letters
 * the old reading hashed, this spares fewer than 1 in 50,000 mixed-case runs at 24 letters and none seen from 32, and
 * about 1 in 400 runs built as random humps (a capital and 4 to 9 random lower-case letters, T29-P3-C264's probe). */
function caseWords(humps) {
  return humps.length >= 2 && humps.every((h) => h.length >= 3 && h.length <= 14
    && (h.match(/[aeiouyAEIOUY]/g) ?? []).length * 6 >= h.length && !/[^aeiouyAEIOUY]{4}/.test(h));
}
/* A segment the screen would refuse is hashed with its extension kept when the extension is a plain one (letters and
 * digits, at most 8) the screen passes: patients/john.doe@example.com.json -> patients/u_<16 hex>.json. A segment
 * holding a secret is hashed whole, extension and all. */
const EXTENSION = /\.([A-Za-z0-9]{1,8})$/;
function hashedSegment(key, seg) {
  if (holdsSecret(seg)) return hashed(key, seg);
  const m = EXTENSION.exec(seg);
  return m && m.index > 0 && !holdsRecordValue(m[1]) ? `${hashed(key, seg)}.${m[1]}` : hashed(key, seg);
}

/* A walked path (relative, forward slashes) as the fact document carries it. A segment holding a secret, or a value
 * the evaluator's screen would refuse, is hashed whatever the pattern says, so a key or a record value in a
 * file or folder name never leaves the machine; the folders around it and a plain extension stay readable. A shape
 * that only appears across segments (a name in one folder, a date in the next) hashes the whole path, extension kept.
 * Deterministic: the same path and key always give the same text. */
export function sentPath(key, path) {
  const segs = path.split("/");
  // The stem too: 5551234567.csv passes the screen as written (a dot follows the digits), its stem doesn't.
  const secret = segs.map(holdsSecret);
  // A letters-only random token (letterToken) is hashed like a record value, its plain extension kept.
  const record = segs.map((seg) => holdsRecordValue(seg) || holdsRecordValue(seg.replace(EXTENSION, "")) || letterToken(seg));
  if (!secret.includes(true) && !record.includes(true) && PATH_RE.test(path) && !holdsRecordValue(path)) return path;
  // A segment hashed for its pattern or a secret is hashed whole, as before; one hashed for a record value keeps its
  // plain extension.
  const out = segs.map((seg, i) => (secret[i] ? hashed(key, seg) : record[i] ? hashedSegment(key, seg)
    : SEGMENT_RE.test(seg) ? seg : hashed(key, seg))).join("/");
  if (!(out.length <= PATH_MAX && PATH_RE.test(out))) return hashed(key, path);
  if (!holdsRecordValue(out)) return out;
  const whole = hashedSegment(key, path); // a shape across segments: one hash for the path, its extension kept
  return PATH_RE.test(whole) && !holdsRecordValue(whole) ? whole : hashed(key, path);
}

/* A name in an identifier field (an Edge Function's name, a plan entity); hashed when it isn't an identifier, holds a
 * secret, or holds a value the evaluator's screen would refuse. */
export function sentIdentifier(key, name) {
  return IDENTIFIER_RE.test(name) && !holdsSecret(name) && !holdsRecordValue(name) ? name : hashed(key, name);
}

/* root_id: HMAC-SHA256 of the root's absolute path (forward slashes, no trailing slash), lowercase hex. */
export function rootId(key, abs) {
  let p = String(abs).replaceAll("\\", "/");
  while (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return createHmac("sha256", key).update(p, "utf8").digest("hex");
}
