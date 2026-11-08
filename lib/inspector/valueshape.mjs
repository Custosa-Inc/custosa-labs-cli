/* The evaluator's value-shape screen, ported so the inspector hashes what the screen would refuse before
 * anything is sent. The evaluator refuses, uncharged, a fact document with any string shaped like a record value or a
 * secret: the evaluator's app/core/api.py check_values over app/validation.py record_value_spans. This module follows those patterns one for one; where a JavaScript regex reads
 * differently from Python's (\w, \d and \b are Unicode-aware there), it reads at least as much, since hashing more is
 * safe and sending a hit is refused.
 *
 * recordValueSpans(text) -> [{label, start, end}]   labels: secret, ssn, phone, long_digit_run, payment_card, email,
 *                                                   ip_address, date_with_name; never the value
 * screenValue(text, field) -> boolean               the evaluator's reading of one string in that field (hash shapes
 *                                                   masked first; path fields also without their last extension)
 * documentValueProblem(doc) -> null | {at, label}   the first string the evaluator would refuse, as a JSON pointer
 * VALUE_SCREEN_EXEMPT: the fields the evaluator doesn't screen (a number or version by design).
 * localRecordShape(text) -> boolean              extra shapes, refused by the inspector only
 * proseRecordShape(text) -> boolean              the evaluator's prose_value_spans shapes beyond record_value_spans
 * freeTextShape(text) -> boolean                 an extra shape for the free text the assistant writes only
 * roleRefShape(text) -> boolean                  what a decider_ref (a role) never holds */

import { readFileSync } from "node:fs";

// ---------------------------------------------------------------- secrets (validation.py _SECRET_PATTERNS)
const START = "(?<![A-Za-z0-9_-])";
const UPPER_IN_RUN = "(?=[A-Za-z0-9]*[A-Z])";
const UPPER_IN_TAIL = "(?=[A-Za-z0-9_-]*[A-Z])";
const HEX_BODY = "(?:[a-z0-9]{1,8}-){0,3}(?=[0-9a-f]{0,31}[0-9])[0-9a-f]{32,}";
const TOKEN = "[^\\s\\x1c-\\x1f\\x85/@:=\"'`()<>,;]";
const PASSWORD = "[^\\s\\x1c-\\x1f\\x85@:\"'`()<>,;]";
const PASSWORD_NO_SLASH = "[^\\s\\x1c-\\x1f\\x85/@:\"'`()<>,;]";
const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const shape = (label, markers, source, flags = "") => {
  const alternation = `(?:${markers.map(esc).join("|")})`;
  return { label, markers, rx: new RegExp(source.replace("<M>", alternation), `${flags}u`) };
};
const SECRET_PATTERNS = [
  shape("jwt", ["eyJ"], `${START}<M>[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*`),
  shape("supabase_secret", ["sb_secret_"], `${START}<M>${UPPER_IN_TAIL}[A-Za-z0-9_-]{20,}`),
  shape("sk_key", ["sk-"], `${START}<M>(?:${UPPER_IN_TAIL}[A-Za-z0-9_-]{20,}|${HEX_BODY})`),
  shape("stripe_key", ["sk_live_", "sk_test_", "rk_live_", "rk_test_"], `${START}<M>${UPPER_IN_RUN}[A-Za-z0-9]{16,}`),
  shape("stripe_webhook_secret", ["whsec_"], `${START}<M>${UPPER_IN_RUN}[A-Za-z0-9]{16,}`),
  shape("phisc_token", ["phisc_"], `${START}<M>${UPPER_IN_TAIL}[A-Za-z0-9_-]{30,}`),
  shape("aws_access_key_id", ["AKIA", "ASIA"], "(?<![A-Za-z0-9])<M>[A-Z0-9]{16}(?![A-Za-z0-9])"),
  shape("github_token", ["ghp_", "gho_", "ghs_", "ghu_", "ghr_"], `${START}<M>${UPPER_IN_RUN}[A-Za-z0-9]{30,}`),
  shape("github_pat", ["github_pat_"], `${START}<M>(?:[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|${UPPER_IN_RUN}[A-Za-z0-9]{20,})`),
  shape("url_credentials", ["://"], "<M>[^\\s\\x1c-\\x1f\\x85/@:]*:[^\\s\\x1c-\\x1f\\x85/@]*@"),
  shape("connection_string", ["://"], "\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?)<M>(?![\\s\\x1c-\\x1f\\x85)|'\"`\\\\\\]]|$)", "i"),
  shape("pem_block", ["-----BEGIN "], "<M>[A-Z]"),
  shape("google_api_key", ["AIza"], `${START}<M>[0-9A-Za-z_-]{35}`),
  shape("sendgrid_key", ["SG."], `${START}<M>[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}`),
  shape("aws_secret_access_key", ["aws_secret", "AWS_SECRET", "SecretAccessKey", "secret_access_key", "SECRET_ACCESS_KEY"],
    "<M>[A-Za-z_]{0,24}[\"']?[ \\t]{0,4}[=:][ \\t]{0,4}[\"']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
  shape("password_assignment", ["PASSWORD=", "PASSWORD: ", "password=", "Password="], "<M>(?![\\s\\x1c-\\x1f\\x85\"'`$<*{]|$)[^\\s\\x1c-\\x1f\\x85\"'`]{3,}"),
  shape("twilio_key", ["SK"], "(?<![A-Za-z0-9])<M>[0-9a-f]{32}(?![A-Za-z0-9])"),
  shape("slack_token", ["xoxb-", "xoxp-", "xoxa-", "xoxs-"], `${START}<M>[A-Za-z0-9-]{10,}`),
  shape("credentials_without_scheme", ["@"],
    `(?<!${TOKEN})(?!(?:user|serviceAccount|group|domain|principal|principalSet|deleted|[Mm][Aa][Ii][Ll][Tt][Oo]):)`
    + `(?:(?<!//)${TOKEN}+:(?!/)${PASSWORD}+|(?<=//)${TOKEN}+:${PASSWORD_NO_SLASH}+)<M>[A-Za-z0-9.-]+\\.[A-Za-z]{2,}`),
];
const WORDS = /[^\s\x1c-\x1f\x85"'`]+/gu;
const ANY_MARKER = new RegExp([...new Set(SECRET_PATTERNS.flatMap((p) => p.markers))].sort((a, b) => b.length - a.length).map(esc).join("|"), "u");

function found(p, s) {
  if (p.label !== "credentials_without_scheme") return p.rx.test(s);
  return (s.match(WORDS) ?? []).some((w) => !w.startsWith("arn:") && p.rx.test(w));
}

export function looksLikeSecret(s) {
  if (typeof s !== "string" || !ANY_MARKER.test(s)) return null;
  return SECRET_PATTERNS.find((p) => p.markers.some((m) => s.includes(m)) && found(p, s))?.label ?? null;
}

// ---------------------------------------------------------------- record values
const PHI_VALUE_PATTERNS = [
  ["ssn", /(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])/gu],
  ["phone", /(?<![0-9])(?:\([0-9]{3}\)[\s\x1c-\x1f\x85]*|[0-9]{3}[-.\s\x1c-\x1f\x85])[0-9]{3}[-.\s\x1c-\x1f\x85][0-9]{4}(?![0-9])/gu],
];
const PHONE_RUN = /(?<![A-Za-z0-9.])[2-9][0-9]{2}[2-9][0-9]{6}(?![A-Za-z0-9.])/gu;
const SSN_RUN = /(?<![A-Za-z0-9.])(?!000|666|9[0-9]{2})[0-9]{3}(?!00)[0-9]{2}(?!0000)[0-9]{4}(?![A-Za-z0-9.])/gu;
const KEYWORD_SSN = /(?<![A-Za-z])(?:ssn|social[ _-]?security(?:[ _-]?(?:number|no))?|ss#)[^A-Za-z0-9]{0,12}(?<![0-9])([0-9]{3} ?[0-9]{2} ?[0-9]{4})(?![0-9])/giud;
const KEYWORD_PHONE = /(?<![A-Za-z])(?:phone|tel|telephone|mobile|cell|fax)[^A-Za-z0-9]{0,12}(?<![0-9])([0-9]{10})(?![0-9])/giud;
const IPV6 = /(?<![\p{L}\p{N}_:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})(?![\p{L}\p{N}_:])/gu;
const ANY_CASE_NAME = /(?=(?<![A-Za-z])([A-Za-z]{2,20})[ ,]+([A-Za-z]{2,20})(?![A-Za-z]))/gud;
/* The common words, data shared with the evaluator: rules/value_screen_words.json, which
 * core's manifest lists, so it is part of the ruleset id and sync-rules.mjs copies it with the rule set.
 * `common` is validation.py _COMMON; `file_words` adds migration and file-naming words, read only for a name joined by
 * _ or -. */
const SCREEN_WORDS = JSON.parse(readFileSync(new URL("../../rules/value_screen_words.json", import.meta.url), "utf8"));
const COMMON = new Set(SCREEN_WORDS.common);
const FILE_COMMON = new Set([...SCREEN_WORDS.common, ...SCREEN_WORDS.file_words]);
/* A name and a date joined by _ or - (patients/john_smith_1985-03-02.json), as validation.py
 * _joined_name_dates has it: two words of 2 to 20 letters in any script (Python's [^\W\d_]: letters and
 * the non-decimal numbers), read overlapping, joined by _ or -. The date may also use _ (1985_03_02) or be compact
 * (19850302, 1900 to 2099). A hit needs the pair within 0 to 3 of _, - or space of the date, the pair alone in its path
 * segment (the other side is the start or end of the text, a / or a .), and neither word common (common or
 * file_words). So 2024-01-05_add_users_table.sql and created_at_2024_01_05 stay readable. */
const JOINED_NAME = /(?=(?<![\p{L}\p{Nl}\p{No}])([\p{L}\p{Nl}\p{No}]{2,20})[_-]+([\p{L}\p{Nl}\p{No}]{2,20})(?![\p{L}\p{Nl}\p{No}]))/gud;
const JOINED_GAP = /^[-_ ]{0,3}$/u;
const SEGMENT_EDGE = "/.";
const JOINED_DATE = new RegExp(
  "(?<!\\p{Nd})(?:(?:19|20)\\p{Nd}\\p{Nd}[-_/.](?:0?[1-9]|1[0-2])[-_/.](?:0?[1-9]|[12]\\p{Nd}|3[01])"
  + "|(?:0?[1-9]|[12]\\p{Nd}|3[01])[-_/.](?:0?[1-9]|[12]\\p{Nd}|3[01])[-_/.](?:19|20)\\p{Nd}\\p{Nd}"
  + "|(?:19|20)\\p{Nd}\\p{Nd}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\p{Nd}|3[01]))(?!\\p{Nd})", "gu");
const LONG_DIGITS = /(?<![A-Za-z0-9])[0-9]{11,}(?![A-Za-z0-9])/gu;
const STAMP = /^(199[0-9]|20[0-9][0-9])(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])[0-5][0-9]([0-5][0-9])?$/u;
const EPOCH_MS = /^(?:1[0-9]{12}|2[01][0-9]{11})$/u;
const CARD = /(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}(?![0-9])/gu;
const UUID = /(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])/giu;
const ARN_ACCOUNT = /(?<![A-Za-z0-9])(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)([0-9]{12})(?=:)/gu;
const EMAIL = /(?<![\p{L}\p{N}_.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\p{L}\p{N}_-])/gu;
const SERVICE_EMAIL = /(\.iam(\.gserviceaccount\.com)?|\.gserviceaccount\.com)$/iu;
const IPV4_VALUE = /(?<![\p{L}\p{N}_.])(?:(?:25[0-5]|2[0-4]\p{Nd}|1\p{Nd}\p{Nd}|[1-9]?\p{Nd})\.){3}(?:25[0-5]|2[0-4]\p{Nd}|1\p{Nd}\p{Nd}|[1-9]?\p{Nd})(?![\p{L}\p{N}_]|\.\p{Nd})/gu;
const NOT_A_PERSON_IP = new Set(["0.0.0.0", "127.0.0.1", "255.255.255.255"]);
const MONTHS = "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\\.?";
// \b is ASCII here and Unicode in Python: (?<![\p{L}\p{N}_]) and (?![\p{L}\p{N}_]) read it the Unicode way.
const B0 = "(?<![\\p{L}\\p{N}_])", B1 = "(?![\\p{L}\\p{N}_])";
const FULL_DATE = new RegExp(
  "(?<!\\p{Nd})(?:(?:19|20)\\p{Nd}\\p{Nd}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\\p{Nd}|3[01])"
  + "|(?:0?[1-9]|[12]\\p{Nd}|3[01])[-/.](?:0?[1-9]|[12]\\p{Nd}|3[01])[-/.](?:19|20)\\p{Nd}\\p{Nd})(?!\\p{Nd})"
  + `|${B0}${MONTHS} (?:0?[1-9]|[12]\\p{Nd}|3[01])(?:st|nd|rd|th)?,? (?:19|20)\\p{Nd}\\p{Nd}${B1}`
  + `|${B0}(?:0?[1-9]|[12]\\p{Nd}|3[01]) ${MONTHS},? (?:19|20)\\p{Nd}\\p{Nd}${B1}`, "gu");
const PERSON_NAME = new RegExp(`(?=${B0}([A-Z][a-z]{1,20}(?: [A-Z]\\.)?(?: |, )[A-Z][a-z]{1,20}(?:-[A-Z][a-z]{1,20})?)${B1})`, "gud");
const NOT_NAMES = new Set(["Next", "Supabase", "Postgres", "Prisma", "Drizzle", "Sentry", "Open", "OpenAI", "Storage", "Auth", "Row",
  "Level", "Security", "Edge", "Function", "Functions", "Server", "Client", "Data", "Session", "Replay", "Google", "Amazon",
  "Microsoft", "Azure", "Cloud", "Vercel", "Neon", "React", "Native", "Node", "Express", "Django", "Rails", "Lab",
  "Labs", "Patient", "Patients", "Care", "Team", "App", "Router", "Pages", "Health", "Telehealth", "Clinic", "Visit",
  "Visits", "The", "This", "Our", "We", "It", "Created", "Updated", "Added", "Migration", "Release", "Version",
  "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "Read", "Sampled", "Checked"].map((w) => w.toLowerCase()));
const WORD = /[^\s\x1c-\x1f\x85,;()'"<>[\]{}]+/gu;
const ANY_DIGIT = /\p{Nd}/gu;

function luhnOk(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

function namesMasked(s) {
  let t = s;
  if (t.includes("-")) t = t.replace(UUID, (m) => "x".repeat(m.length));
  if (t.includes("arn:aws")) t = t.replace(ARN_ACCOUNT, (m, pre) => pre + "x".repeat(12));
  return t;
}

function digitValues(s, out) {
  const text = namesMasked(s);
  for (const [label, rx] of PHI_VALUE_PATTERNS) for (const m of text.matchAll(rx)) out.push({ label, start: m.index, end: m.index + m[0].length });
  for (const m of text.matchAll(LONG_DIGITS)) if (!(STAMP.test(m[0]) || EPOCH_MS.test(m[0]))) out.push({ label: "long_digit_run", start: m.index, end: m.index + m[0].length });
  for (const m of text.matchAll(PHONE_RUN)) if (!(STAMP.test(m[0]) || EPOCH_MS.test(m[0]))) out.push({ label: "phone", start: m.index, end: m.index + m[0].length });
  for (const m of text.matchAll(SSN_RUN)) out.push({ label: "ssn", start: m.index, end: m.index + m[0].length });
  for (const m of text.matchAll(KEYWORD_SSN)) out.push({ label: "ssn", start: m.indices[1][0], end: m.indices[1][1] });
  for (const m of text.matchAll(KEYWORD_PHONE)) out.push({ label: "phone", start: m.indices[1][0], end: m.indices[1][1] });
  for (const m of text.matchAll(CARD)) {
    if ((m[0].includes(" ") || m[0].includes("-")) && luhnOk(m[0].replace(/[^0-9]/g, ""))) out.push({ label: "payment_card", start: m.index, end: m.index + m[0].length });
  }
}

/* validation.py _joined_name_dates: the date and the pair, as date_with_name. A date joins a pair only within
 * JOINED_GAP's 3 characters, so each pair looks its dates up by offset: linear in the text, never pairs times dates
 *. One matchAll's matches never overlap, so one date starts, and one ends, at each offset. */
function joinedNameDates(s, out) {
  const dates = [...s.matchAll(JOINED_DATE)].map((d) => [d.index, d.index + d[0].length]);
  if (!dates.length) return;
  const byStart = new Map(dates.map((d) => [d[0], d])), byEnd = new Map(dates.map((d) => [d[1], d]));
  for (const n of s.matchAll(JOINED_NAME)) {
    const a = n.indices[1][0], b = n.indices[2][1];
    if (FILE_COMMON.has(n[1].toLowerCase()) || FILE_COMMON.has(n[2].toLowerCase())) continue;
    const joined = [];
    for (let e = Math.max(0, a - 3); e <= a; e++) {   // the date, then the pair
      const d = byEnd.get(e);
      if (d && JOINED_GAP.test(s.slice(d[1], a))) joined.push([d, b < s.length ? s[b] : ""]);
    }
    for (let e = b; e < b + 4; e++) {                 // the pair, then the date
      const d = byStart.get(e);
      if (d && JOINED_GAP.test(s.slice(b, d[0]))) joined.push([d, a ? s[a - 1] : ""]);
    }
    for (const [[dStart, dEnd], edge] of joined) {
      if (!edge || SEGMENT_EDGE.includes(edge)) {
        out.push({ label: "date_with_name", start: dStart, end: dEnd }, { label: "date_with_name", start: a, end: b });
      }
    }
  }
}

function extendedValues(s, digits, out) {
  if (s.includes("@")) for (const m of s.matchAll(EMAIL)) if (!SERVICE_EMAIL.test(m[0])) out.push({ label: "email", start: m.index, end: m.index + m[0].length });
  if ((s.match(/:/g) ?? []).length >= 2) {
    for (const m of s.matchAll(IPV6)) if (/\p{Nd}/u.test(m[0]) && (m[0].match(/:/g) ?? []).length >= 2) out.push({ label: "ip_address", start: m.index, end: m.index + m[0].length });
  }
  if (digits < 4) return;
  for (const m of s.matchAll(IPV4_VALUE)) {
    const before = s.slice(Math.max(0, m.index - 1), m.index);
    WORD.lastIndex = Math.max(0, s.lastIndexOf(" ", m.index - 1) + 1);
    const word = WORD.exec(s);
    const inPath = word !== null && word[0].includes("/");
    if (!NOT_A_PERSON_IP.has(m[0]) && before.toLowerCase() !== "v" && !inPath) out.push({ label: "ip_address", start: m.index, end: m.index + m[0].length });
  }
  const dates = [...s.matchAll(FULL_DATE)];
  for (const d of dates) {
    const dStart = d.index, dEnd = d.index + d[0].length;
    const off = Math.max(0, dStart - 44);
    for (const n of s.slice(off, dEnd + 44).matchAll(ANY_CASE_NAME)) {
      const a = n.indices[1][0] + off, b = n.indices[2][1] + off;
      const adjacent = (dStart - b >= 0 && dStart - b <= 3) || (a - dEnd >= 0 && a - dEnd <= 3);
      const words = [n[1].toLowerCase(), n[2].toLowerCase()];
      if (adjacent && !words.some((w) => COMMON.has(w)) && !words.some((w) => NOT_NAMES.has(w))) {
        out.push({ label: "date_with_name", start: dStart, end: dEnd }, { label: "date_with_name", start: a, end: b });
      }
    }
  }
  joinedNameDates(s, out);
  if (dates.length) {
    const names = [...s.matchAll(PERSON_NAME)]
      .filter((n) => !n[1].replaceAll("-", " ").split(/\s+/).some((w) => NOT_NAMES.has(w.toLowerCase().replace(/[,.]+$/, ""))))
      .map((n) => [n.indices[1][0], n.indices[1][1]]);
    for (const d of dates) {
      const near = names.filter(([a, b]) => b >= d.index - 40 && a <= d.index + d[0].length + 40);
      if (near.length) {
        out.push({ label: "date_with_name", start: d.index, end: d.index + d[0].length });
        for (const [a, b] of near) out.push({ label: "date_with_name", start: a, end: b });
      }
    }
  }
}

/* Python's re.I folds dotless ı and dotted İ to i, and JavaScript's /iu doesn't. The screens read a copy with
 * them mapped (one UTF-16 unit each, so spans still line up). */
const foldI = (s) => s.replace(/ı/gu, "i").replace(/İ/gu, "I");

export function recordValueSpans(s) {
  if (typeof s !== "string" || !s) return [];
  s = foldI(s);
  const out = [];
  if (looksLikeSecret(s)) out.push({ label: "secret", start: 0, end: s.length });
  const digits = (s.match(ANY_DIGIT) ?? []).length;
  if (!digits && !s.includes("@")) return out;
  if (digits >= 9) digitValues(s, out);
  extendedValues(s, digits, out);
  return out;
}

/* shapes the inspector refuses in the free text the assistant writes and in names it would send, beyond the
 * evaluator's screen (not part of the port above, so documentValueProblem doesn't read them): a medical record,
 * member, patient or account number; a full date beside dob, born or birth; a title before two capitalised words. */
// an id's digits are counted with single spaces and dashes between them dropped (MRN 0012-3456).
const RECORD_ID = /(?<![A-Za-z])(?:mrn|medical[ _-]?record|member|patient|account|acct)(?:[ _-]?(?:id|number|num|no\.?))?[^A-Za-z0-9]{0,4}#?[A-Za-z]{0,3}-?[0-9](?:[ -]?[0-9]){4,}(?![0-9])/iu;
const BIRTH_WORD = "(?:dob|d\\.o\\.b\\.?|born|birth(?:[ _-]?(?:day|date))?)";
const BIRTH_BEFORE = new RegExp(`(?<![A-Za-z])${BIRTH_WORD}(?:[^A-Za-z0-9]{1,4}(?:on|in))?[^A-Za-z0-9]{0,4}$`, "iu");
const BIRTH_AFTER = /^[^A-Za-z0-9]{0,4}(?:dob|d\.o\.b|born|birth)(?![A-Za-z])/iu;
// beside a birth word, a compact date (19840312) or one with a two-digit year (03-12-84, 3/12/84) too.
const BIRTH_LOOSE = new RegExp(`(?<![A-Za-z])${BIRTH_WORD}(?:[^A-Za-z0-9]{1,4}(?:on|in))?[^A-Za-z0-9]{0,4}`
  + "(?:(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])|[0-9]{1,2}[-/.][0-9]{1,2}[-/.][0-9]{2})(?![0-9])", "iu");
// a title before two names, each capitalised or hyphenated (Jean-Luc), with up to three lowercase particles
// between them (van der Berg); or before two words in capitals (JANE SMITH).
// any cased letter, so accented names (José García, Zoë Kim) are read too.
// as core builds _UPPER, _LOWER and _NAME_PART (validation.py): letters of the Basic Multilingual
// Plane only, and a lower-case part may carry the combining accents of a decomposed name (Jose\u0301).
const UPPER = "(?:(?=[\\u0000-\\uFFFF])\\p{Lu})";
const LOWER = "(?:(?=[\\u0000-\\uFFFF])\\p{Ll}|[\\u0300-\\u036f])";
const NAME_PART = `${UPPER}${LOWER}{1,20}`;
const NAME = `${NAME_PART}(?:-${NAME_PART})?`;
const PARTICLES = "(?:(?:van|von|der|den|de|del|della|di|da|du|le|la|al|el|bin|ibn|ten|ter) ){0,3}";
const TITLE = "(?<!\\p{L})(?:Dr|Mr|Mrs|Ms|Mx|Prof)\\.? ";
const TITLED_NAME = new RegExp(`${TITLE}(${NAME}) ${PARTICLES}(${NAME})(?!\\p{L})`, "gu");
const TITLED_CAPS = new RegExp(`${TITLE}(${UPPER}{2,20}) (${UPPER}{2,20})(?!\\p{L})`, "gu");

export function localRecordShape(s) {
  if (typeof s !== "string" || !s) return false;
  s = foldI(s);
  if (RECORD_ID.test(s) || BIRTH_LOOSE.test(s)) return true;
  for (const d of s.matchAll(FULL_DATE)) {
    if (BIRTH_BEFORE.test(s.slice(Math.max(0, d.index - 24), d.index)) || BIRTH_AFTER.test(s.slice(d.index + d[0].length, d.index + d[0].length + 16))) return true;
  }
  const named = (n) => ![n[1], n[2]].some((w) => w.toLowerCase().split("-").some((part) => NOT_NAMES.has(part)));
  for (const n of s.matchAll(TITLED_NAME)) if (named(n)) return true;
  for (const n of s.matchAll(TITLED_CAPS)) if (named(n)) return true;
  return false;
}

/* app/validation.py _record_like, regex for regex: a record
 * keyword with a number after it, an id-shaped code, a street address, a person's name beside a condition. Core reads
 * them in prose_value_spans, so in a reason, a decider_ref and a searched root; the CLI also reads them in a concern's
 * text, which core never screens. \\b reads the Unicode way, as B0 and B1 do above. */
const WB = "(?:(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_])|(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_]))";
const CONDITIONS = "hiv|aids|diabetes|diabetic|asthma|copd|ckd|cancer|leukemia|lymphoma|tumou?r|chemo(?:therapy)?|depression"
  + "|anxiety|bipolar|schizophrenia|ptsd|adhd|autism|dementia|alzheimer'?s|parkinson'?s|epilepsy|hepatitis"
  + "|tuberculosis|pregnan(?:t|cy)|miscarriage|abortion|stroke|hypertension|opioid|addiction|overdose|suicid[\\p{L}\\p{N}_]*"
  + "|a1c|hba1c|dialysis|biktarvy|insulin|metformin|chlamydia|gonorrh?oea|syphilis|herpes";
const CONDITION = new RegExp(`${B0}(?:${CONDITIONS})${B1}`, "giu");
const STREET = new RegExp(`${B0}\\p{Nd}{1,6} (?:[A-Z][a-z]+ ){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct`
  + `|Way|Place|Pl|Terrace|Ter|Parkway|Pkwy|Highway|Hwy)${B1}\\.?`, "u");
const RECORD_NUMBER = new RegExp(`${B0}(?:mrn|medical record(?: number| no\\.?)?|record (?:number|no\\.?|#)|chart (?:number|no\\.?)`
  + "|member (?:id|number|no\\.?)|subscriber (?:id|number)|policy (?:number|no\\.?)|patient (?:id|number|no\\.?|#)|insurance(?: id| number)?)"
  + `[\\s\\x1c-\\x1f\\x85]*[:#=]?[\\s\\x1c-\\x1f\\x85]*#?([A-Z]{0,3}[0-9][0-9A-Z-]{3,19})${WB}`, "giu");
const ID_CODE = new RegExp(`${B0}(?:[A-Z]{1,3}\\p{Nd}{7,12}|\\p{Nd}{3,5}-\\p{Nd}{2,4}-\\p{Nd}{2,4})${B1}`, "gu");
const WHOLE_DATE = new RegExp(`^(?:${FULL_DATE.source})$`, "u");
// As the evaluator's _ANY_PERSON_NAME: beside a condition a name part reads any cased letter (José García,
// Siobhán Kelly). PERSON_NAME stays ASCII for date_with_name, as core's _PERSON_NAME does, since names and paths get it.
const ANY_PERSON_NAME = new RegExp(`(?=${B0}(${NAME_PART}(?: ${UPPER}\\.)?(?: |, )${NAME_PART}(?:-${NAME_PART})?)${B1})`, "gud");

export function proseRecordShape(s) {
  if (typeof s !== "string" || !s) return false;
  s = foldI(s);
  for (const m of s.matchAll(RECORD_NUMBER)) if ((m[1].match(/[0-9]/g) ?? []).length >= 4) return true;
  for (const m of s.matchAll(ID_CODE)) if (!WHOLE_DATE.test(m[0])) return true;
  if (STREET.test(s)) return true;
  const conditions = [...s.matchAll(CONDITION)];
  if (!conditions.length) return false;
  const names = [...s.matchAll(ANY_PERSON_NAME)]
    .filter((n) => !n[1].replaceAll("-", " ").split(/\s+/).some((w) => NOT_NAMES.has(w.toLowerCase().replace(/[,.]+$/, ""))))
    .map((n) => [n.indices[1][0], n.indices[1][1]]);
  return conditions.some((c) => names.some(([a, b]) => b >= c.index - 60 && a <= c.index + c[0].length + 60));
}

/* a bare run of exactly 10 digits, which the evaluator's screen passes unless it is NANP-shaped (PHONE_RUN), while
 * it refuses 9 and 11. Free text only: names and paths keep the evaluator's reading, so a migration named by its Unix
 * seconds (golang-migrate's 1481574547_init.up.sql) is sent as before. */
const TEN_DIGITS = /(?<![0-9])[0-9]{10}(?![0-9])/u;
export function freeTextShape(s) {
  return typeof s === "string" && TEN_DIGITS.test(s);
}

/* a decider_ref names a role, never a person or a record, so a run of 5 or more digits (an MRN, a phone number,
 * a user id), a UUID or a full date is refused there, without touching reasons. */
const DIGIT_RUN = /[0-9]{5}/u;
// a non-global twin, since .test on the shared global FULL_DATE leaves its lastIndex set, and a later
// matchAll(FULL_DATE) starts from there.
const ANY_DATE = new RegExp(FULL_DATE.source, "u");
const ANY_UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/iu;
export function roleRefShape(s) {
  if (typeof s !== "string") return false;
  return DIGIT_RUN.test(s) || ANY_UUID.test(s) || ANY_DATE.test(s);
}

// ---------------------------------------------------------------- the document screen (api.py check_values)
const HASHES = /(?<![0-9A-Za-z])(?:[0-9a-f]{64}|u_[0-9a-f]{16})(?![0-9A-Za-z])/g;
export const VALUE_SCREEN_EXEMPT = Object.freeze(new Set(["system_identifier", "ruleset_id", "inspector_version"]));
// api.py _PATH_KEYS and object_id: the fields check_values reads with _path_refused, which also screens the text with
// its last extension (and a :line suffix) cut off (_LAST_EXTENSION), so data/4155550123.csv reads its number. Its
// asset '@' exemption (logo@2x.png) isn't ported: this screen reads those as an email, which is stricter.
const PATH_FIELDS = new Set(["path", "location", "object_id"]);
const LAST_EXTENSION = /\.[A-Za-z0-9]{1,10}(?=(?::[0-9]+(?:-[0-9]+)?)?$)/;

/* The first label the evaluator's screen gives one string in a field named `field`, or null: hash shapes masked, an
 * object_id read after its '@', a path field read as written and without its last extension. */
function screenLabel(text, field) {
  if (typeof text !== "string" || !text || VALUE_SCREEN_EXEMPT.has(field)) return null;
  let t = text.replace(HASHES, "x");
  if (field === "object_id") t = t.slice(t.indexOf("@") + 1 || t.length);
  const reads = PATH_FIELDS.has(field) ? [t, t.replace(LAST_EXTENSION, "")] : [t];
  for (const r of reads) if (r) { const spans = recordValueSpans(r); if (spans.length) return spans[0].label; }
  return null;
}

/* free text and searched roots as core reads them (api.py reason and root screens): no hash masking. */
export function screenText(text) {
  return typeof text === "string" && recordValueSpans(text).length > 0;
}

/* One string as the evaluator reads it in a field named `field` (screenLabel). */
export function screenValue(text, field = null) {
  return screenLabel(text, field) !== null;
}

const pointer = (path) => (path.length ? `/${path.map((p) => String(p).replaceAll("~", "~0").replaceAll("/", "~1")).join("/")}` : "");

export function documentValueProblem(doc) {
  const stack = [[doc, []]];
  while (stack.length) {
    const [node, path] = stack.pop();
    if (Array.isArray(node)) node.forEach((v, i) => stack.push([v, [...path, i]]));
    else if (node && typeof node === "object") for (const [k, v] of Object.entries(node)) stack.push([v, [...path, k]]);
    else if (typeof node === "string") {
      const label = screenLabel(node, path.at(-1) ?? null);
      if (label !== null) return { at: pointer(path), label };
    }
  }
  return null;
}
