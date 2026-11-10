/* A default set of provider secret patterns, a starting point until the rules shipped in the package
 * (queries/secrets.yml) supply them.
 *
 * Each pattern is {rule_id, regex, validate?, normalize?, placeholders?, fileContext?}.
 * - regex matches a secret VALUE, never a key name: every pattern is anchored on a provider prefix or a named context
 *   (aws_secret_access_key=, SUPABASE_JWT_SECRET=) plus a minimum length of value characters, with lookarounds so the
 *   match cannot sit inside a longer token. When the regex has a named group `secret`, only that group is the secret
 *   (and the finding's line is the line where it starts); otherwise the whole match is. The secret group must end the
 *   match: anything that has to follow it is written as a lookahead, which gives its exact position without the
 *   slow d flag. Several patterns may share a
 *   rule_id (one rule, several shapes).
 * - validate(secret, {groups, line, before, after, memo}) is an optional extra check that returns true for a
 *   real-looking secret; `groups` are the regex's named groups, `line` the text of the line holding the secret,
 *   `before` and `after` up to 4 KB of text on each side of it, and memo(name, fn) runs fn(whole file text) once per
 *   file (file-wide facts such as the hosts a file names). A validate that throws counts as a finding (fail closed).
 * - normalize(secret, context) optionally maps the secret to a canonical form before fingerprinting (a PEM key
 *   gives the same fingerprint whether its lines are real newlines, escaped \n, indented or split across string
 *   literals); context is what validate sees (before, after, ...).
 * - placeholders: true drops CLEAR documentation placeholders (isClearPlaceholder, isShapePlaceholder). Only provider tokens set it, never
 *   a human-chosen value such as a password, so a password like dummyPass77Q is still a finding.
 * - fileContext: a regex the whole file must match for the pattern to run (a Twilio key SID only in a file that
 *   names Twilio). Also used as a cheap hint for patterns with no literal prefix.
 * - ending(after): how a match ends, from up to 256 characters after it: "complete", "quote" (a closing quote comes
 *   first: resolved against the joined view) or "incomplete" (the file is reported as truncated). Used for PEM keys.
 * - fallback: true marks a generic pattern whose finding is dropped when a specific rule's hit on the same line has
 *   the same fingerprint or overlaps its match.
 * - inspectorOnly: true marks a pattern the hosted rule set's secrets.yml doesn't carry yet (rules-sync.test.mjs).
 * - pathContext: a regex the file's name (its last path segment) must match for the pattern to run (config files
 *   only). validate also gets `path`, the whole path as passed to the scanner.
 * - location: true fingerprints the finding's location (rule_id, path and line) instead of its value (a
 *   human-chosen password under a config key; nothing about the value is sent, not even keyed). Such a pattern does
 *   not run on the joined view.
 *
 * Every pattern's match is bounded (no unbounded repetition), which the windowed scan in secrets.mjs relies on.
 *
 * Known limits (not detected):
 * - Kubernetes Secret manifests: values under `data:` are base64 encoded, so a key, password or PEM there is not
 *   recognised (`stringData:` values are plain and are scanned).
 * - Secrets encoded in other ways: base64 or hex blobs, URL-encoded whole values, values split by code that is not a
 *   plain string concatenation (template literals with ${}, arrays joined at run time, string builders).
 * - A quoted value containing spaces or # after a config key (DB_PASSWORD="a b#c") is cut at the first such character.
 * - A database URL password containing an unencoded @ is cut at the first @ (an unencoded // is fine).
 * - A well-known default password under a config key (POSTGRES_PASSWORD: postgres) is a finding only when the same
 *   file names a non-loopback host (a database URL, DB_HOST and the like, or a compose port published on all
 *   interfaces); in a file that names no host at all it is taken as local.
 * - Host detection for those defaults reads env, properties, YAML (compose ports, nested database mappings) and JSON
 *   compose. A YAML alias for ports (ports: *name) is not resolved and counts as published on all interfaces. Hosts
 *   only in TOML tables, XML, HCL or code (a host built at run time) are not seen.
 * - UTF-16 or UTF-32 text without a byte-order mark is read as UTF-8; runs of NUL-interleaved ASCII in it (one NUL per
 *   character for UTF-16, three for UTF-32, either byte order) are scanned with those NULs removed, which recovers
 *   ASCII secrets (secrets.mjs, readableText). Non-ASCII text in it is not decoded.
 * - A PEM key with no END line is reported as truncated (incomplete), and its body stops at the first line that is not
 *   base64.
 * - A PEM key with a comment prefix is read when every line uses one of # // * ; > (mixed prefixes are accepted
 *   too); other prefixes are not.
 * - A PEM key longer than about 12 KB may be cut by the scan window; the file is then reported as truncated.
 * - Provider formats not listed here (other clouds, payment providers and SaaS tokens) until the shipped rules add
 *   them. */

// Appends items one by one: push(...items) overflows the call stack on very long lists.
const pushAll = (target, items) => { for (const item of items) target.push(item); return target; };

const decodeJwtPart = (part) => {
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
};

/* A clear placeholder for a provider token: it contains "example" or a your_/your- token, a run of 8 or more x's,
 * or its last segment (after the provider prefix) is all x's. */
export function isClearPlaceholder(secret) {
  if (/example/i.test(secret) || /(?:^|[^A-Za-z])your[_-]/i.test(secret) || /[xX]{8,}/.test(secret)) return true;
  const last = secret.split(/[_\-.]/).pop();
  return /^[xX]+$/.test(last);
}

/* A provider token made up as a shape rather than drawn at random: some tail of it, starting within its first 12
 * characters (past a prefix such as AKIA, sk-proj- or SG.) and at least 12 long, is under 4 distinct characters, one
 * unit of up to 8 characters repeated, or an ascending run (0-9, a-z, A-Z; 9 to 0 counts as a step) broken at most
 * once per 8 characters. Each is far below 1e-9 for a random tail. A run beside random text is not a shape. Applied
 * with isClearPlaceholder to the patterns that set placeholders. */
export function isShapePlaceholder(secret) {
  for (let k = 0; k <= 12 && secret.length - k >= 12; k++) if (shaped(secret.slice(k))) return true;
  return false;
}

const shaped = (s) => {
  if (new Set(s).size < 4) return true;
  for (let n = 1; n <= 8 && n * 2 <= s.length; n++) {
    let repeats = true;
    for (let i = n; i < s.length && repeats; i++) repeats = s[i] === s[i - n];
    if (repeats) return true;
  }
  let breaks = 0;
  for (let i = 1; i < s.length; i++) if (!ascends(s[i - 1], s[i])) breaks++;
  return breaks <= Math.floor(s.length / 8);
};
const ascends = (a, b) => (a === "9" && b === "0") ||
  (/^(?:[0-9]{2}|[a-z]{2}|[A-Z]{2})$/.test(a + b) && b.charCodeAt(0) === a.charCodeAt(0) + 1);

/* isClearPlaceholder for a password value: its all-x last segment needs 4 or more x's, so Zr7pQw-x and Zr7pQw.XX are
 * passwords. */
const isPasswordPlaceholder = (v) => /example/i.test(v) || /(?:^|[^A-Za-z])your[_-]/i.test(v) || /[xX]{8,}/.test(v) ||
  /^[xX]{4,}$/.test(v.split(/[_\-.]/).pop());

/* A variable reference or template slot standing in for a value, not a value: ${VAR}, ${{ secrets.X }}, $VAR (an
 * environment-style name, upper case, digits and underscores), $(cmd), <password>, [YOUR-PASSWORD], {{ pw }},
 * {password} or {settings.db_password} (format strings), %s, %(pw)s, '+pw+' (string concatenation), or a mask of
 * asterisks. A value that merely starts with $ or % (a URL-encoded or human-chosen password such as $ecretPw9) is not
 * one. */
export function isVariableReference(value) {
  if (!/^[$<[{%*"']/.test(value)) return false; // every form below starts with one of these
  return /^\$\{[^{}]*\}$/.test(value) || /^\$\{\{[^{}]*\}\}$/.test(value) || /^\$[A-Z_][A-Z0-9_]*$/.test(value) ||
    /^\$\([^)]*\)$/.test(value) || /^<[^<>]*>$/.test(value) || /^\[[^[\]]*\]$/.test(value) ||
    /^\{\{[^{}]*\}\}$/.test(value) || /^\{[A-Za-z_][A-Za-z0-9_.]*\}$/.test(value) || /^%s$/.test(value) ||
    /^%\([A-Za-z_][A-Za-z0-9_]*\)s$/.test(value) || /^(["'])\s*\+.*\+\s*\1$/.test(value) || /^\*+$/.test(value);
}

// Exact passwords that are documentation placeholders (compared whole and case-insensitively, never as substrings).
const PLACEHOLDER_PASSWORDS = new Set([
  "password", "pass", "changeme", "secret", "example", "your-password", "your_password", "yourpassword",
]);
// Well-known local defaults: not a finding when the host is loopback (a local-only default is not a leak).
const LOCAL_DEFAULT_PASSWORDS = new Set(["postgres", "password", "root", "admin", "example", "mysql", "guest"]);

/* Loopback hosts only. A docker-compose service name (db, postgres) is not loopback: it is reachable by name and its
 * password is a finding. An empty host means a local socket. */
export function isLoopbackHost(host) {
  const h = String(host ?? "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h === "" || h.startsWith("/") || h.startsWith("%2f") || h === "localhost" || h.endsWith(".localhost") || /^127(?:\.\d{1,3}){3}$/.test(h) ||
    h === "::1" || h === "0:0:0:0:0:0:0:1" || h === "host.docker.internal";
}

/* A password is a secret unless it is a variable reference, an exact placeholder word, or a well-known local default
 * on a connection whose hosts are ALL loopback (every host of a multi-host URL, ?host= and hostaddr= parameters,
 * and anything after a second @). hosts === null means no host is known (a config key): a local default is then
 * taken as local. */
const passwordIsSecret = (secret, hosts, path) => {
  if (isReference(secret, path)) return false;
  const lower = secret.toLowerCase();
  if (PLACEHOLDER_PASSWORDS.has(lower)) return false;
  if (!LOCAL_DEFAULT_PASSWORDS.has(lower)) return true;
  return hosts !== null && !hosts.every(isLoopbackHost);
};

const URL_REST = /^[^\s'"`<>]{0,2048}/;
// host:port, [v6]:port -> host.
const stripPort = (h) => (h.startsWith("[") ? h.slice(0, h.indexOf("]") + 1 || h.length) : h.split(":")[0]);
const paramHosts = (query) => {
  const out = [];
  const re = /(?:^|[?&;])(?:host|hostaddr)=([^&;#]*)/gi;
  let m;
  while ((m = re.exec(query)) !== null) pushAll(out, m[1].split(/,|%2C/i));
  return out;
};
const authorityHosts = (authority) => authority.split(/[@,]/).map(stripPort);

/* Hosts of user:PASSWORD@authority... : everything after the password's @ up to the path, split on , and @. */
function hostsAfterPassword(after) {
  const url = (URL_REST.exec(after.slice(1)) || [""])[0];
  const cut = url.search(/[/?#]/);
  const authority = cut === -1 ? url : url.slice(0, cut);
  const query = cut === -1 ? "" : url.slice(cut);
  return [...authorityHosts(authority), ...paramHosts(query.slice(query.indexOf("?") + 1))];
}

/* Hosts of scheme://[user@]authority/...?...password=PASSWORD... : the authority before the query (minus the user
 * part before the first @) and any host= parameter before or after the password. */
function hostsAroundQueryPassword(before, after) {
  const pre = before.slice(before.lastIndexOf("://") + 3);
  const cut = pre.search(/[/?#]/);
  let authority = cut === -1 ? pre : pre.slice(0, cut);
  const at = authority.indexOf("@");
  if (at !== -1) authority = authority.slice(at + 1);
  const query = (cut === -1 ? "" : pre.slice(cut)) + (URL_REST.exec(after) || [""])[0];
  return [...authorityHosts(authority), ...paramHosts(query.slice(query.indexOf("?") + 1))];
}

// A PEM line separator: a real newline, an escaped \n inside a JSON or env string, or a double-escaped \\n,
// optionally followed by indentation (YAML block scalars, Helm values), or spaces alone (a key pasted on one line).
// The two branches cannot overlap and every run is bounded, so a header followed by a long run of whitespace fails
// fast (no backtracking blowup). Proc-Type style header lines must end at a newline, which pins where each one stops.
// A line may also carry a comment prefix after its indentation (# , // , * , ; , > : a key pasted into a comment or a
// quoted reply). "//" needs a space after it, since a base64 line may itself start with "/".
// Newline escapes in strings: \n, \r\n, double-escaped \\n and \\r\\n, and \u000a, \x0a, \012.
const NL = String.raw`(?:\r?\n|\\\\r\\\\n|\\\\n|\\r\\n|\\n|\\u000[aA]|\\x0[aA]|\\012)`;
const COMMENT = String.raw`(?:[#;>*][ \t]{0,8}|\/\/[ \t]{1,8})?`;
// Trailing spaces or tabs before a newline are allowed everywhere (they neither drop nor cut a key), and up to two
// comment-only lines ("//", "#") may sit between key lines.
const NLW = String.raw`[ \t]{0,64}${NL}(?:[ \t]{0,64}(?:[#;>*]|\/\/)[ \t]{0,8}${NL}){0,2}`;
const SEP = String.raw`(?:${NLW}[ \t]{0,64}${COMMENT}|[ \t]{1,64})`;
// Body lines are bounded at 8192 characters (a one-line body included). A body chunk must be a whole line (end of
// line, a closing quote, or the end of text after it) or, on a space-separated one-line key, be followed by another
// chunk of 16 or more characters or the END line: prose after a key ("// see the docs") is never body. A chunk that is
// only "/" or "//" (a bare // comment prefix, or the prefix of the END line) is never body either. A chunk that
// reaches the 8192 bound is taken as it is; the base64 after it then marks the key as cut (pemEnding).
const BODY_START = String.raw`(?!\/\/?(?:[ \t\r\n\\]|$))`;
const BODY_END = String.raw`(?=[ \t]{0,64}(?:${NL}|["'\`,;]|$)|[ \t]{1,64}(?:-----END|[A-Za-z0-9+/]{16}))`;
const PEM = new RegExp(
  String.raw`-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----` +
  String.raw`(?:${NLW}[ \t]{0,64}${COMMENT}[A-Za-z0-9-]+: [^\r\n\\]{0,200}(?=${NL})){0,4}(?:${NLW})?` +
  String.raw`${SEP}${BODY_START}(?:[A-Za-z0-9+/]{8192}|[A-Za-z0-9+/]{40,8191}={0,2}${BODY_END})` +
  String.raw`(?:${SEP}${BODY_START}(?:[A-Za-z0-9+/]{8192}|[A-Za-z0-9+/]{1,8191}={0,2}${BODY_END})){0,400}`, "g");

/* What a PEM key is fingerprinted on: the first PEM_FINGERPRINT_BODY characters of its base64 body, with the header,
 * Proc-Type style lines, newlines, escaped newlines and indentation removed. The body of a key that is shorter is
 * used whole. A scan window always holds at least 12 KB after a match start, which covers 4096 body characters even
 * with 64 spaces of indentation and escaped newlines on every line, so the fingerprint is the same wherever the key
 * sits in a file and whether or not the window cut the rest of it. (Distinct keys differ well within 4096 body
 * characters: only the first few dozen are shared ASN.1 structure.) */
export const PEM_FINGERPRINT_BODY = 4096;
// Comment prefixes as COMMENT above, at the start of a trimmed line.
// A line that is only a prefix ("//", "#") becomes empty and is dropped.
const PEM_COMMENT = /^(?:[#;>*][ \t]*|\/\/(?:[ \t]+|$))/;
/* Line by line: escaped newlines become newlines, each line is trimmed and loses a comment prefix, every armour
 * header line (any line with a colon: Proc-Type:, DEK-Info:, Comment:, ...) and the BEGIN/END lines are dropped, and
 * the base64 of the rest is concatenated, up to PEM_FINGERPRINT_BODY characters. */
/* The BEGIN line right before the match and the END line after it both carry a "//" prefix. */
function blockCommented(context) {
  if (!context) return false;
  if (!/\/\/[ \t]*$/.test(context.before)) return false;
  const after = context.after;
  const end = after.indexOf("-----END");
  return end !== -1 && /\/\/[ \t]*$/.test(after.slice(0, end));
}
const normalizePem = (match, context) => {
  const lines = match.replace(/^-----BEGIN [A-Z0-9 ]*-----/, "")
    .replace(/\\\\r\\\\n|\\\\n|\\r\\n|\\n|\\u000[aA]|\\x0[aA]|\\012/g, "\n").split(/\r?\n/);
  const kept = [];
  for (const raw of lines) {
    const line = raw.trim().replace(PEM_COMMENT, "");
    if (line && !line.includes(":") && !line.includes("-----")) kept.push(line);
  }
  // "//" with no space is a comment prefix only when the whole block is commented: the BEGIN line, the END line and
  // every body line carry it. Body lines alone never decide it, since an encrypted key's body (ciphertext) can start
  // with "//".
  const slashes = kept.length > 0 && kept.every((line) => line.startsWith("//")) && blockCommented(context);
  let body = "";
  for (const line of kept) {
    for (const part of (slashes ? line.slice(2) : line).split(/[ \t]+/)) if (/^[A-Za-z0-9+/]+=*$/.test(part)) body += part;
    if (body.length >= PEM_FINGERPRINT_BODY) break;
  }
  return body.slice(0, PEM_FINGERPRINT_BODY);
};
/* How a PEM match ends, from the text after it: "complete" when the END line follows within up to eight blank
 * lines (separators, trailing spaces, escaped newlines and comment prefixes skipped), "quote" when a closing quote
 * comes first (a key that continues in a later string literal, or one whose string closes with no END line), and
 * "incomplete" otherwise (cut by a bound or a window's end, or no END line at all). The scanner flags "incomplete" as
 * truncated, and resolves "quote" against the joined view (secrets.mjs). A loop, not a regex: nested optional
 * whitespace runs would backtrack badly. */
const MAX_BLANK_LINES = 8;
function pemEnding(after) {
  // The newline ending the last body line, then at most MAX_BLANK_LINES blank lines: MAX_BLANK_LINES + 1 newlines.
  let i = 0, newlines = 0;
  const atLineStart = () => newlines > 0;
  const newline = (width) => {
    if (newlines === MAX_BLANK_LINES + 1) return false;
    newlines++;
    i += width;
    return true;
  };
  while (i < after.length) {
    const width = after.startsWith("\\\\r\\\\n", i) ? 6 : after.startsWith("\\\\n", i) ? 3
      : after.startsWith("\\r\\n", i) ? 4 : after.startsWith("\\n", i) ? 2 : after[i] === "\n" ? 1
        : /^\\(?:u000[aA]|x0[aA]|012)/.test(after.slice(i, i + 6)) ? (after[i + 1] === "u" ? 6 : 4) : 0;
    if (width) { if (newline(width)) continue; break; }
    const c = after[i];
    if (c === "\r" || c === " " || c === "\t") { i++; continue; }
    if (atLineStart() && (c === "#" || c === ";" || c === ">" || c === "*")) { i++; continue; }
    if (atLineStart() && after.startsWith("//", i)) { i += 2; continue; }
    break;
  }
  if (after.startsWith("-----END ", i)) return "complete";
  if (i < after.length && (after[i] === '"' || after[i] === "'" || after[i] === "`")) return "quote";
  return "incomplete";
}

/* NAME = value, NAME: value, "NAME": "value", NAME => value, NAME := value, or a YAML folded or literal block
 * (NAME: >- or NAME: |) with the value on the next indented line. Whitespace runs are bounded and stay on the line
 * (except the block form), so an empty NAME= never takes the next line as its value. */
// Up to 200 aligned spaces before the operator, and an optional type annotation of up to 120 characters (pydantic
// and dataclass settings: secret_key: str = "...", jwt_secret: Annotated[str, Field(min_length=32)] = "...").
const ASSIGN = String.raw`(?:["']?[ \t]{0,200}:[ \t]{0,40}[>|][-+]?[0-9]?[ \t]{0,40}\r?\n[ \t]{1,40}["']?|` +
  String.raw`["']?[ \t]{0,200}(?::[ \t]{0,40}[A-Za-z_][\w.[\]|, ()=]{0,120}?[ \t]{0,40}(?==))?(?::|=>?|:=)[ \t]{0,40}["']?)`;
const contextValue = (names, value, flags = "g") => new RegExp(
  String.raw`(?<![A-Za-z0-9])(?:${names})${ASSIGN}(?<secret>${value})`, flags);
/* A name/value pair: {"name": "NAME", "value": "..."} (ECS task definitions) or a Kubernetes env entry
 * (- name: NAME, then value: ... on the next line). */
const W40 = String.raw`\s{0,40}`;
const nameValue = (names, value, flags = "gi") => new RegExp(
  String.raw`["']?\bname["']?${W40}[:=]${W40}["']?(?:${names})["']?${W40},?${W40}(?:-[ \t]{0,40})?["']?value["']?` +
  String.raw`${W40}[:=]${W40}["']?(?<secret>${value})`, flags);

// AWS secret access key names, with any prefix (PROD_, NEXT_) and up to three suffix segments (_PROD), any case,
// underscores or dashes: AWS_SECRET_ACCESS_KEY, aws-secret-access-key, awsSecretAccessKey, SecretAccessKey.
const AWS_SECRET_NAMES = String.raw`(?:aws[_-]?)?secret[_-]?access[_-]?key(?:[_-][A-Za-z0-9]{1,32}){0,3}|aws[_-]?secret[_-]?key|` +
  String.raw`cloud\.aws\.credentials\.secret-key`;
// fileContext hints: a pattern with no literal prefix (a context or name list) only runs on files containing its
// hint, which keeps unrelated large files cheap.
const AWS_HINT = /secret.?access.?key|secret-key|aws.?secret/i;
const AWS_SECRET_VALUE = String.raw`[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])`;
// Terraform: secret_key = "..." counts only inside a provider "aws" block (no closing brace between the block's start
// and the key) or with an access_key within three lines before or after. Checked in validate on the bounded context,
// not in the regex, so the scan stays linear.
const TF_SECRET = /(?<![A-Za-z0-9_])secret_key[ \t]{0,40}=[ \t]{0,40}"(?<secret>[A-Za-z0-9/+]{40})(?=")/g;
const lastLines = (text, n) => { let i = text.length; while (n-- > 0 && i > 0) i = text.lastIndexOf("\n", i - 1); return text.slice(Math.max(i, 0)); };
const firstLines = (text, n) => { let i = -1; while (n-- > 0) { i = text.indexOf("\n", i + 1); if (i === -1) return text; } return text.slice(0, i); };
const terraformAws = (before, after) => {
  const k = before.lastIndexOf("provider");
  if (k !== -1 && /^provider\s{1,40}"aws"\s{0,40}\{/.test(before.slice(k, k + 100)) && !before.includes("}", k)) return true;
  return /(?<![A-Za-z0-9_])access_key[ \t]{0,40}=/.test(lastLines(before, 4) + "\n" + firstLines(after, 4));
};

/* scheme://user:password@host for one family of database URLs (any case, an optional +driver such as
 * postgresql+psycopg2 or mongodb+srv), plus the same family's ?password= / &password= query form (JDBC and
 * libpq URLs). The hosts for the loopback check are read from the text around the password. The password may hold
 * an unencoded // (userinfo runs to the @ before the host); an unencoded @ ends it. */
/* (?=(?<name>body))\k<name>: matches body greedily and never backtracks into it (JS has no possessive quantifiers;
 * a lookahead is atomic). Used where a failed match would otherwise retry every shorter length. */
const atomic = (name, body) => String.raw`(?=(?<${name}>${body}))\k<${name}>`;

/* A run of characters outside `excluded` that never contains "//": on text such as postgres://postgres://... the
 * URL path run stops at the next scheme instead of running to its length limit from every start. */
const NO_SLASH_SLASH = (excluded, range) => String.raw`(?:[^${excluded}/]|/(?!/)){${range}}`;

const urlPassword = (rule_id, schemes) => [
  Object.freeze({
    rule_id,
    regex: new RegExp(String.raw`(?<![A-Za-z0-9+.-])(?:jdbc:)?(?:${schemes})(?:\+[A-Za-z0-9_]+)?:\/\/` +
      atomic("user", String.raw`[^\s:/@'"\`]{0,128}`) + ":" + atomic("secret", String.raw`[^\s@\`]{1,256}`) + "(?=@)",
      "gi"),
    validate: (secret, { after }) => passwordIsSecret(secret, hostsAfterPassword(after)),
  }),
  Object.freeze({
    rule_id,
    regex: new RegExp(String.raw`(?<![A-Za-z0-9+.-])(?:jdbc:)?(?:${schemes})(?:\+[A-Za-z0-9_]+)?:\/\/` +
      atomic("path", NO_SLASH_SLASH(String.raw`\s'"\`?#`, "0,256")) + String.raw`\?(?:[^\s'"\`#]{0,512}?[&;])?password=(?<secret>[^\s&'"\`;#]{1,256})`, "gi"),
    validate: (secret, { before, after }) => passwordIsSecret(secret, hostsAroundQueryPassword(before, after)),
  }),
];

/* Every database host a file names, so a default password under a config key is reported when any of them is not
 * loopback. One linear pass per regex, once per file. Counted as hosts:
 * - hosts in database URLs (JDBC included, every host of a multi-host URL, host= parameters);
 * - settings named *_HOST, *_HOSTNAME or *_SERVER for a database (DB_HOST, PGHOST, POSTGRES_SERVER), properties-style
 *   *.host= / *.hostname= keys (db.host=, spring.data.redis.host=), and libpq DSN host= / hostaddr= anywhere;
 * - compose ports: a port published with no host or with 0.0.0.0 in any form (short "5432", "5432:5432",
 *   "${PG_PORT:-5432}:5432", flow ["5432:5432"], long form published: 5432 without a loopback host_ip) and
 *   network_mode: host count as published on all interfaces (0.0.0.0).
 * An interpolation with a default (${DB_HOST:-db.prod.example.com}) counts as its default; one without a default is
 * unknown and ignored. */
const INTERP = /\$\{[A-Za-z_][A-Za-z0-9_]{0,100}(?::?[-=]([^}]{0,256}))?\}/g;
const UNKNOWN = "\u0001";
const resolveInterp = (value) => value.replace(INTERP, (_, def) => def ?? UNKNOWN);
// Host values are trimmed (" db.prod " counts) and lose a trailing backslash left by a JSON-escaped path (\/).
const hostsFrom = (list) => list.split(",").map((h) => stripPort(h.trim().replace(/\\+$/, "").trim()))
  .filter((h) => !h.includes(UNKNOWN) && !/^\$[A-Za-z_]/.test(h));

const DB_URL_IN_FILE = /(?:jdbc:)?(?:postgres(?:ql)?|mysql|mariadb|mongodb|rediss?|amqps?)(?:\+[A-Za-z0-9_]{1,32})?:(?:\\?\/){2}((?:\$\{[^}\s]{0,256}\}|[^\s'"`<>/?#])*)([^\s'"`<>]{0,2048})/gi;
const HOST_SETTING = /(?<![A-Za-z0-9])(?:[A-Za-z0-9]{1,40}_)?(?:DB|DATABASE|PG|POSTGRES|POSTGRESQL|MYSQL|MARIADB|MONGO|MONGODB|REDIS)_?(?:HOST(?:NAME|ADDR)?|SERVER|ADDR(?:ESS)?)(?![A-Za-z0-9_])["']?[ \t]{0,200}[:=][ \t]{0,40}["']?[ \t]{0,40}((?:\$\{[^}\s]{0,256}\}|[^\s"'#;])+)/gi;
const DOTTED_HOST = /(?<![\w.-])(?:[\w-]{1,64}\.){1,8}host(?:name|addr)?[ \t]{0,200}[:=][ \t]{0,40}["']?[ \t]{0,40}((?:\$\{[^}\s]{0,256}\}|[^\s"'#;])+)/gi;
const LIBPQ_HOST = /(?:^|[\s'"?&;])(?:host|hostaddr)=((?:\$\{[^}\s]{0,256}\}|[^\s'"&;#])+)/g;
const NETWORK_HOST = /(?:^|\n)[ \t]*network_mode[ \t]*:[ \t]*["']?host["']?[ \t]*(?:#[^\n]*)?(?=\r?\n|$)|"network_mode"[ \t\r\n]{0,40}:[ \t\r\n]{0,40}"host"/;
// JSON compose: "ports": [ ... ] (short specs as strings or numbers, or long-form objects).
const JSON_PORTS = /"ports"[ \t\r\n]{0,40}:[ \t\r\n]{0,40}\[([^\]]{0,8192})\]/g;
// A YAML mapping for a database (database:, db:, datasource:, postgres:, redis:, ...): its nested host keys count.

/* A compose port spec ("5432", "5432:5432", "127.0.0.1:5432:5432", "[::1]:5432:5432", "${PG_PORT:-5432}:5432",
 * optionally /tcp) gives the interface it is published on: its host part, or 0.0.0.0. */
function portSpecHost(spec) {
  const v = resolveInterp(spec.trim().replace(/^["']|["']$/g, "")).replace(/\/(?:tcp|udp|sctp)$/i, "");
  if (v.startsWith("[")) return v.slice(0, v.indexOf("]") + 1) || "0.0.0.0";
  const parts = v.split(":");
  return parts.length >= 3 && parts[0] !== "" ? parts[0] : "0.0.0.0";
}

/* The interfaces a list of short port specs ("5432:5432", 6379, ...) is published on, one per non-empty spec. */
const specHosts = (list) => list.split(",").filter((spec) => spec.trim()).map(portSpecHost);

/* Ports published by a compose file: lines under a ports: key (list items, flow lists on one or more lines,
 * long-form items). ports: *alias refers to a list defined elsewhere, which is not resolved: it counts as published on
 * all interfaces. */
function composePortHosts(text) {
  const hosts = [];
  let inPorts = false, portsIndent = -1, item = null, flow = null;
  const endItem = () => {
    if (item && item.published) hosts.push(item.hostIp ?? "0.0.0.0");
    item = null;
  };
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (flow !== null) { // a flow list continued over several lines, up to its ]
      const close = line.indexOf("]");
      flow += " " + (close === -1 ? line : line.slice(0, close));
      if (close !== -1 || flow.length > 8192) {
        pushAll(hosts, specHosts(flow));
        flow = null;
      }
      continue;
    }
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const indent = line.length - line.trimStart().length;
    const ports = /^(\s*)ports\s*:\s*(.*)$/.exec(line);
    if (ports) {
      endItem();
      const rest = ports[2].replace(/\s+#.*$/, "").trim();
      if (rest.startsWith("*")) {
        hosts.push("0.0.0.0");
        inPorts = false;
      } else if (rest.startsWith("[") && !rest.includes("]")) {
        flow = rest.slice(1);
        inPorts = false;
      } else if (rest.startsWith("[")) {
        pushAll(hosts, specHosts(rest.replace(/^\[|\].*$/g, "")));
        inPorts = false;
      } else {
        inPorts = true;
        portsIndent = indent;
      }
      continue;
    }
    if (!inPorts) continue;
    const isItem = /^\s*-/.test(line);
    if (indent < portsIndent || (indent === portsIndent && !isItem)) { endItem(); inPorts = false; continue; }
    const body = isItem ? line.trimStart().slice(1).trim() : line.trim();
    if (isItem) endItem();
    const kv = /^([A-Za-z_]+)\s*:\s*(.*)$/.exec(body);
    if (kv && !/^["'$\[0-9]/.test(body)) {
      if (!item) item = { published: false, hostIp: null }; // a new list item (endItem cleared the last one)
      const value = kv[2].replace(/\s+#.*$/, "").trim().replace(/^["']|["']$/g, "");
      if (kv[1] === "published") item.published = true;
      if (kv[1] === "host_ip") item.hostIp = resolveInterp(value);
    } else if (isItem && body) {
      hosts.push(portSpecHost(body.replace(/\s+#.*$/, "")));
    }
  }
  endItem();
  if (flow !== null) pushAll(hosts, specHosts(flow));
  return pushAll(hosts, jsonPortHosts(text));
}

/* Ports published by a JSON compose file: "ports": [...] with short specs (strings or numbers), or long-form objects
 * that are published, on their host_ip or all interfaces. */
function jsonPortHosts(text) {
  const hosts = [];
  JSON_PORTS.lastIndex = 0;
  let m;
  while ((m = JSON_PORTS.exec(text)) !== null) {
    if (!m[1].includes("{")) {
      pushAll(hosts, specHosts(m[1]));
      continue;
    }
    // An object may hold ${...} interpolations (a host_ip of "${IP:-10.0.0.9}"): each is read as one unit, so its
    // braces neither end the object nor start one.
    for (const obj of m[1].match(/\{(?:[^{}$]|\$\{[^{}]{0,256}\}|\$(?!\{)){0,1024}\}/g) || []) {
      if (!/"published"/.test(obj)) continue;
      const ip = /"host_ip"[ \t\r\n]{0,40}:[ \t\r\n]{0,40}"([^"]{0,256})"/.exec(obj);
      hosts.push(ip ? resolveInterp(ip[1]) : "0.0.0.0");
    }
  }
  return hosts;
}

/* YAML host: / hostname: / hostaddr: / address: keys under any parent (or at the top level). The parent's name is
 * not checked: a host under an unrelated mapping (smtp:, feedback:) may make a default password a finding, which is
 * the safe direction; a database mapping with any name (mydb:, postgres14:, PrimaryDB:) is never missed. */
// [^\S\n] is any whitespace but a newline (NBSP, vertical tab and form feed included), also before the colon.
const YAML_HOST = /^[^\S\n]*-?[^\S\n]*["']?(?:host|hostname|hostaddr|address)["']?[^\S\n]*:[^\S\n]*["']?[^\S\n]*((?:\$\{[^}\s]{0,256}\}|[^\s"'#,])+)/gim;
function nestedYamlHosts(text) {
  const hosts = [];
  let m;
  YAML_HOST.lastIndex = 0;
  while ((m = YAML_HOST.exec(text)) !== null) pushAll(hosts, hostsFrom(resolveInterp(m[1])));
  return hosts;
}

function fileDbHosts(text) {
  const hosts = [];
  let m;
  DB_URL_IN_FILE.lastIndex = 0;
  while ((m = DB_URL_IN_FILE.exec(text)) !== null) {
    const authority = resolveInterp(m[1]);
    pushAll(hosts, hostsFrom(authority.slice(authority.lastIndexOf("@") + 1)));
    pushAll(hosts, paramHosts(resolveInterp(m[2]).slice(m[2].indexOf("?") + 1)).filter((h) => !h.includes(UNKNOWN)));
  }
  for (const re of [HOST_SETTING, DOTTED_HOST, LIBPQ_HOST]) {
    re.lastIndex = 0;
    while ((m = re.exec(text)) !== null) pushAll(hosts, hostsFrom(resolveInterp(m[1])));
  }
  pushAll(hosts, composePortHosts(text));
  pushAll(hosts, nestedYamlHosts(text));
  if (NETWORK_HOST.test(text)) hosts.push("0.0.0.0");
  return hosts;
}

/* libpq keyword form: host=h user=u password=PW dbname=d, password among other libpq keywords on the line. */
const LIBPQ_KEYS = "host|hostaddr|port|dbname|user|sslmode|connect_timeout";
/* Every host= and hostaddr= value on the line (comma lists split); none means a local socket. */
const libpqHosts = (line) => {
  const out = [];
  const re = /(?:^|[\s'"])(?:host|hostaddr)=([^\s'"]*)/g;
  let m;
  while ((m = re.exec(line)) !== null) pushAll(out, m[1].split(","));
  return out;
};

// Generic application secrets: a high-entropy value (24+ characters, at least two of lower case, upper case and
// digits) that is not a variable, a code reference (process.env.X, os.environ[...], settings.X) or a placeholder.
const looksRandom = (v) => v.length >= 24 &&
  [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(v)).length >= 2;
const isCodeReference = (v) => /[()[\]]/.test(v) || /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v);
/* A password value is code only when the whole value is a call of a known function (ENC(...) and DEC(...) of jasypt,
 * and getenv or env of an env-style name, getenv(DB_PW); no config format evaluates a bare lookup(, vault( or
 * secret(, and env(hunter2) is a password), an index on a known root (os.environ[X],
 * ENV[X], process.env[X]) or a dotted name on one (env., process.env., settings., config., os.environ.). A config file
 * evaluates nothing else, so Correct.Horse.Battery, Summer(2024) and Hunter2[99] are passwords. A bracket inside
 * a value is part of the password, and a quoted value is a string, never code. DEC(x) is jasypt's plaintext
 * waiting for jasypt:encrypt, a password; only an empty DEC() and an ENC(...) with no parentheses inside are code
 *. isCodeReference stays as it was
 * for the rules that also scan source code, where a capture cut at a quote (getOrThrow<string>() must read as code. */
const CODE_CALLS = String.raw`ENC\([^()\r\n]*\)|DEC\(\)|(?:(?:os\.|System\.)?getenv|env)\((?<q>["']?)[A-Z_][A-Z0-9_]*\k<q>\)`;
const CODE_ROOTS = String.raw`env|process\.env|settings|config|os\.environ|ENV`;
const CODE_VALUE = new RegExp(String.raw`^(?:${CODE_CALLS})$|^(?:os\.environ|ENV|process\.env|env)\[[^\]]*\]$|` +
  String.raw`^(?:${CODE_ROOTS})(?:\.[A-Za-z_$][\w$]*)+$`);
const isCodeValue = (v, quoted = false) => !quoted && CODE_VALUE.test(v);
// A sops-encrypted value (ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]): committed encrypted, the right practice
//. Read to the end of its line, since it may run past any value cap. Its data holds no space or quote, so it
// can't run past a comment or a closing quote into a ].
const SOPS_VALUE = /^ENC\[AES256_GCM,data:[^\]\s"']*\][ \t]*(?:#[^\n]*)?\r?$/;
// A quoted one is the whole quoted value. What may follow its closing quote depends on the file's format
//; anything else is part of the value: the shell joins "x",tail in .env, and .properties reads , } ] # and ; as
// value text.
const SOPS_QUOTED = /^ENC\[AES256_GCM,data:[^\]\s"']*\]/;
const SOPS_AFTER = {
  json: /^[ \t]*(?:[,}\]][^\n]*)?\r?$/,             // , } or ] of the object or array
  flow: /^[ \t]*(?:[,}\]][^\n]*|[ \t]#[^\n]*)?\r?$/,  // a YAML or TOML flow map or sequence, or a comment
  hash: /^(?:[ \t]*|[ \t]+#[^\n]*)\r?$/,              // YAML, TOML and .env: a comment after a space
  ini: /^(?:[ \t]*|[ \t]+[;#][^\n]*)\r?$/,            // INI: a ; or # comment after a space
  plain: /^[ \t]*\r?$/,                              // .properties, and any other file: trailing whitespace only
};
const ENV_NAME = /(?:^|\.)env(?:\.|$)/i;
// The form of SOPS_AFTER for the file, given the line before the opening quote (a { or [ there opens a flow collection).
const sopsAfter = (path, before) => {
  if (typeof path !== "string") return SOPS_AFTER.plain;
  if (JSON_FILE.test(path)) return SOPS_AFTER.json;
  if (YAML_OR_TOML_FILE.test(path)) return /[{[]/.test(before) ? SOPS_AFTER.flow : SOPS_AFTER.hash;
  if (PROPERTIES_FILE.test(path)) return SOPS_AFTER.plain;
  if (INI_FILE.test(path)) return SOPS_AFTER.ini;
  return ENV_NAME.test(path) ? SOPS_AFTER.hash : SOPS_AFTER.plain;
};
const isSops = (ctx) => {
  if (typeof ctx.text !== "string") return false;
  const end = ctx.text.indexOf("\n", ctx.index);
  const rest = ctx.text.slice(ctx.index, end < 0 ? undefined : end);
  if (SOPS_VALUE.test(rest)) return true;
  const quote = ctx.text[ctx.index - 1];
  const m = (quote === '"' || quote === "'") ? SOPS_QUOTED.exec(rest) : null;
  if (m === null || rest[m[0].length] !== quote) return false;
  const before = ctx.text.slice(ctx.text.lastIndexOf("\n", ctx.index - 1) + 1, ctx.index - 1);
  return sopsAfter(ctx.path, before).test(rest.slice(m[0].length + 1));
};

/* key-anchored passwords and service-role keys in config files, and passwords in the
 * userinfo of other URLs. These rules fingerprint the location (rule, path and line), never the value (location). */

// Template suffixes after a config extension, any number of them: app.yml.example, app.yml.local.example, app.yml.j2.
const TEMPLATE_SUFFIX = String.raw`(?:\.(?:example|sample|template|tmpl|dist|default|local|j2|jinja2?))*`;
// Config files by name: yml, yaml, properties, json, toml, ini, cfg, conf and cnf (MySQL option files), also with
// template suffixes, and env-named files (.env, production.env, env.local.example, prod.env.local).
const CONFIG_FILE = new RegExp(String.raw`(?:\.(?:ya?ml|properties|json|toml|ini|cfg|conf|cnf)${TEMPLATE_SUFFIX}$|(?:^|\.)env(?:\.|$))`, "i");
// Files where a value may start with , ; or #: .properties, env-named and ini-family files (.ini, .cfg, .cnf),
// none of which starts a comment there. Not YAML or TOML, where # starts one and , or ; can't start a plain value.
const LEADING_PUNCT_FILE = new RegExp(String.raw`\.(?:properties|ini|cfg|cnf)${TEMPLATE_SUFFIX}$|(?:^|\.)env(?:\.|$)`, "i");
// INI-family and .properties files, with template suffixes (what may follow a quoted sops value).
const INI_FILE = new RegExp(String.raw`\.(?:ini|cfg|cnf|conf)${TEMPLATE_SUFFIX}$`, "i");
const PROPERTIES_FILE = new RegExp(String.raw`\.properties${TEMPLATE_SUFFIX}$`, "i");
// Spring's own files: .properties, and application*.yml and bootstrap*.yml (also with template suffixes). Spring reads
// ${A:?x} there as the default ?x, never expands a bare $A, and a ${name} may hold a hyphen.
const SPRING_FILE = new RegExp(String.raw`\.properties${TEMPLATE_SUFFIX}$|(?:^|\/)(?:application|bootstrap)(?:[-.][\w.-]*)?` +
  String.raw`\.ya?ml${TEMPLATE_SUFFIX}$`, "i");
// Two or more plain references side by side (${A}${B}, $A$B): a reference, not a literal. In Spring's own
// files only the ${A} form is one (mail.password=$ZR7P$Q is a literal there).
const PLAIN_REFS = /^(?:\$\{[A-Za-z_][\w.-]{0,100}\}|\$[A-Z_][A-Z0-9_]{0,100}){2,8}$/;
const BRACED_REFS = /^(?:\$\{[A-Za-z_][\w.-]{0,100}\}){2,8}$/;
// A file whose own syntax may be a format string (.template, .tmpl): only there is a whole {name} a slot.
const FORMAT_TEMPLATE = /\.(?:template|tmpl)$/i;
const BRACE_SLOT = /^\{[A-Za-z_][A-Za-z0-9_.]*\}$/;
// In a connection string {0} to {9} are slots (string.Format), and a {name} is a slot only for a
// placeholder-like name: its last segment pass, passwd, pwd, password or secret ({password}, {dbPassword}).
// Any other {name} is the value.
const SLOT_NAME = /^(?:pass|passwd|pwd|password|secret)$/;
/* A variable reference or slot (isVariableReference), except a whole {name} in a config file that is not a template:
 * no config syntax reads {name} as a slot, so there it is the value. path undefined, or slots (an ADO.NET
 * connection string, which .NET code fills with string.Format): as isVariableReference. */
const isReference = (v, path, slots = false) => (slots && /^\{[0-9]\}$/.test(v)) ||
  (isVariableReference(v) && !(path !== undefined && BRACE_SLOT.test(v) &&
  (slots ? !SLOT_NAME.test(lastKeySegment(v.slice(1, -1))) : CONFIG_FILE.test(path) && !FORMAT_TEMPLATE.test(path)))) ||
  (path !== undefined && (SPRING_FILE.test(path) ? BRACED_REFS : PLAIN_REFS).test(v));
// Files that hold ADO.NET or SQL Server connection strings: the config files above plus .config (web.config).
const CONNECTION_FILE = new RegExp(String.raw`${CONFIG_FILE.source}|\.config$`, "i");
/* A translation file: its password keys hold labels, not passwords. It sits in a translation folder (lang, langs,
 * i18n, l10n, locale, locales, translations) right above it and its name is a locale code (de.yml, pt-BR.json,
 * messages_fr.properties, messages_pt_BR.properties), or it sits in a locale-code folder right under one
 * (locales/fr/common.json). A folder further up does not count (lang/java/.../application-it.yml). A
 * translation folder alone is not enough (config/lang/db.yml, lang/java/.../application.yml), nor a locale-code name
 * alone (deploy/en-US.yml). Locale codes are ISO 639-1. */
const ISO_639_1 = new Set(("aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch co cr cs cu cv cy " +
  "da de dv dz ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik " +
  "io is it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv mg mh mi mk ml mn mr ms mt " +
  "my na nb nd ne ng nl nn no nr nv ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd se sg si sk sl sm sn so " +
  "sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi vo wa wo xh yi yo za zh zu").split(" "));
const LOCALE_DIRS = new Set(["lang", "langs", "i18n", "l10n", "locale", "locales", "translation", "translations"]);
const LOCALE_FILE = /\.(?:ya?ml|json|properties)$/i;
// A Spring message bundle, wherever it sits: messages.properties, messages_de.properties, messages_pt_BR.properties.
const SPRING_MESSAGES = /^messages(?:_[a-z]{2,3}(?:_[A-Z]{2})?)?\.properties$/;
const REGION = /^(?:[A-Z]{2}|[A-Z][a-z]{3}|[0-9]{3})$/;
// A name stem (or folder) ending in a locale code: fr, pt-BR, messages_fr, messages_pt_BR, zh-Hans.
const isLocaleName = (stem) => {
  const parts = stem.split(/[._-]/);
  const last = parts[parts.length - 1], before = parts[parts.length - 2];
  return ISO_639_1.has(last) || (REGION.test(last) && before !== undefined && ISO_639_1.has(before));
};
function isTranslationFile(path) {
  const segs = String(path).split("/");
  const name = segs.pop();
  if (SPRING_MESSAGES.test(name)) return true;
  if (!LOCALE_FILE.test(name)) return false;
  const stem = name.replace(LOCALE_FILE, "");
  const inDir = (i) => i >= 0 && LOCALE_DIRS.has(segs[i].toLowerCase());
  if (isLocaleName(stem) && inDir(segs.length - 1)) return true;
  return segs.length >= 2 && isLocaleName(segs[segs.length - 1]) && inDir(segs.length - 2);
}
// A prod or production part anywhere in the path (application-prod.yml, config/production/app.yml).
const PROD_PATH = /(?:^|[/._-])(?:prod|production)(?=[/._-]|$)/i;
// The last segment of a key, split on . _ - and camel case: password, passwd, pwd, pass or passphrase.
const PASSWORD_SEGMENT = new Set(["password", "passwd", "pwd", "pass", "passphrase"]);
const lastKeySegment = (key) => key.replace(/([a-z0-9])([A-Z])/g, "$1.$2").split(/[._-]/).pop().toLowerCase();
// A key that names a password: its last segment, or an OAuth client secret or Spring's jwt.secret. JWT_SECRET
// and its kin stay with generic-app-secret.
const passwordKey = (key) => PASSWORD_SEGMENT.has(lastKeySegment(key)) ||
  /client[_.-]?secret$|(?:^|[._-])jwt\.secret$/i.test(key);
// Placeholder words for a key-anchored password (compared whole, any case).
const CONFIG_PLACEHOLDERS = new Set([...PLACEHOLDER_PASSWORDS, "passwd", "pwd", "change_me", "changeit", "xxx", "xxxx",
  "todo", "tbd", "null", "none", "nil", "~", "undefined",
  // YAML booleans: pass: true is a flag, not a secret.
  "true", "false", "yes", "no", "on", "off"]);
// Well-known local defaults, skipped only on a loopback-only file (configLocalOnly).
const CONFIG_LOCAL_DEFAULTS = new Set([...LOCAL_DEFAULT_PASSWORDS, "test", "dev", "sa", "secret", "pass", "user"]);
/* One level of Spring or shell interpolation: ${a.b:default}, ${X:-default}, ${X-default}, and the required forms
 * ${X:?message} and ${X?message}. The :?, bare - and ? forms are shell only, so their name is an upper-case shell
 * name: a Spring name may hold a hyphen (${my-app.pw} is a reference, not my with a default), and Spring has no
 * required form (${a.b:?lit} is the default ?lit). Groups: 2 is :?, 4 is :- or :, 6 is - or ?, 7 the rest. */
const CONFIG_INTERP = /^\$\{(?:([A-Z_][A-Z0-9_]{0,100})(:\?)|([A-Za-z_][\w.-]{0,100})(:-|:)|([A-Z_][A-Z0-9_]{0,100})(-|\?))([\s\S]*)\}$/;
// The same where the shell reads it, every file but Spring's own: a shell name may be lower case there
// (${smtp_pw-lit}).
const SHELL_INTERP = /^\$\{(?:([A-Za-z_][A-Za-z0-9_]{0,100})(:\?)|([A-Za-z_][\w.-]{0,100})(:-|:)|([A-Za-z_][A-Za-z0-9_]{0,100})(-|\?))([\s\S]*)\}$/;
// Levels unwrapped before a value is judged as a finding outright (the cap must not fail open).
const INTERP_LEVELS = 8;
const bracesBalanced = (s) => {
  let depth = 0;
  for (const c of s) if (c === "{") depth++; else if (c === "}" && --depth < 0) return false;
  return depth === 0;
};
/* A value unwrapped to its innermost default (${A:${B:lit}} is lit). interp says it was interpolation at all;
 * required says a level is a required-variable form, which names no value. ${A}${B} is not one interpolation.
 * capped says more than INTERP_LEVELS levels: the caller judges that as a finding. In Spring's own files Spring has no
 * required form, so ${A:?lit} is the default ?lit. */
function unwrapInterp(value, path = "") {
  const spring = SPRING_FILE.test(path);
  const forms = spring ? CONFIG_INTERP : SHELL_INTERP;
  let v = value, interp = false, m;
  for (let i = 0; (m = forms.exec(v)) !== null && bracesBalanced(m[7]); i++) {
    if (i === INTERP_LEVELS) return { interp: true, required: false, capped: true, value: v };
    if (m[2] !== undefined && spring) {
      interp = true;
      v = `?${m[7]}`;
      continue;
    }
    if (m[2] !== undefined || m[6] === "?") return { interp: true, required: true, capped: false, value: "" };
    interp = true;
    v = m[7];
  }
  return { interp, required: false, capped: false, value: v };
}
/* A whole YAML flow collection: it opens with { or [ and its matching bracket closes it at its very end
 * ({ min: 8 }, [a, b]). {noop}pw, {pw and {{ vault_pw }}x are not. */
function isFlowCollection(v) {
  if (!/^[{[]/.test(v)) return false;
  const open = [];
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === "{" || c === "[") open.push(c === "{" ? "}" : "]");
    else if (c === "}" || c === "]") {
      if (open.pop() !== c) return false;
      if (open.length === 0) return i === v.length - 1;
    }
  }
  return false;
}
// YAML files, with the same template suffixes as CONFIG_FILE. Only there does a bare { or [ open a collection.
const YAML_FILE = new RegExp(String.raw`\.ya?ml${TEMPLATE_SUFFIX}$`, "i");
// A plain YAML number (8, -1.5, 1e3, 0x1F, 0o17, .inf, .nan): a setting, not a password.
const YAML_NUMBER = /^(?:[-+]?(?:\d[\d_]*(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?|0x[0-9A-Fa-f]+|0o[0-7]+|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/;
/* The scalars of a whole YAML flow collection that stand as values: sequence items, map values, and a map entry with
 * no value ({pw}). A key followed by : is structure. Quoted scalars come back with quoted true. An unclosed quote
 * gives null: the caller judges that as a finding. A ${...} or {{...}} is one scalar, whatever its braces. */
function flowValues(v) {
  const out = [];
  let i = 0;
  while (i < v.length) {
    const c = v[i];
    const slot = interpEnd(v, i);
    if (slot > i) {
      out.push({ text: v.slice(i, slot), quoted: false });
      i = slot;
      continue;
    }
    if (/[{}[\],\s]/.test(c)) { i++; continue; }
    if (c === ":") { i++; continue; }
    let text, quoted = false;
    if (c === '"' || c === "'") {
      const end = v.indexOf(c, i + 1);
      if (end < 0) return null;
      text = v.slice(i + 1, end);
      quoted = true;
      i = end + 1;
    } else {
      let j = i;
      // A plain scalar ends at a flow indicator, or at a : that is followed by a space or an indicator.
      while (j < v.length && !/[{}[\],]/.test(v[j]) && !(v[j] === ":" && /[\s{}[\],]/.test(v[j + 1] ?? " "))) {
        const end = interpEnd(v, j);
        j = end > j ? end : j + 1;
      }
      text = v.slice(i, j).trim();
      i = j;
    }
    let k = i;
    while (k < v.length && /[ \t]/.test(v[k])) k++;
    if (v[k] !== ":") out.push({ text, quoted });   // followed by : it is a key
  }
  return out;
}
/* The end of a ${...} or {{...}} starting at i (its braces balanced), or i when none starts there or it never
 * closes. */
function interpEnd(v, i) {
  const open = v.startsWith("${", i) ? 2 : v.startsWith("{{", i) ? 2 : 0;
  if (!open) return i;
  let depth = 0;
  for (let j = i + (open - 1); j < v.length; j++) {
    if (v[j] === "{") depth++;
    else if (v[j] === "}" && --depth === 0) {
      if (v.startsWith("{{", i)) return v[j + 1] === "}" ? j + 2 : i;
      return j + 1;
    }
  }
  return i;
}
// A YAML tag before a value (!!str, !vault): the value is what follows it.
const YAML_TAG = /^!{1,2}[\w!/.-]*[ \t]+/;
// A YAML tag or anchor, or both, before a value (&pw "lit", !!str lit, &pw !!str "lit"), or standing alone.
const YAML_PROPS_SOURCE = String.raw`(?:!{1,2}[\w!/.-]{0,100}|&[^\s,[\]{}"']{1,100})`;
const YAML_PROPS = new RegExp(String.raw`^(?:${YAML_PROPS_SOURCE}(?:[ \t]{1,40}|$)){1,2}`);
// YAML and TOML files, with template suffixes.
const YAML_OR_TOML_FILE = new RegExp(String.raw`\.(?:ya?ml|toml)${TEMPLATE_SUFFIX}$`, "i");
// JSON files, with template suffixes.
const JSON_FILE = new RegExp(String.raw`\.json${TEMPLATE_SUFFIX}$`, "i");

/* A local default is skipped only when the file names at least one host, every host it names is loopback, and its
 * path has no prod or production part. A file that names no host is not taken as local. */
const configLocalOnly = (hosts, path) => hosts.length > 0 && hosts.every(isLoopbackHost) && !PROD_PATH.test(path);

// The keys database-password-config owns. Its own host rule decides their local defaults (no host named is
// local); config-password adds only the prod-path tightening on them (see configPassword).
const DB_PASSWORD_KEY = /^(?:(?:POSTGRES|POSTGRESQL|PG|MYSQL|MYSQL_ROOT|MARIADB|MARIADB_ROOT|MONGO_INITDB_ROOT|DB|DATABASE)_PASSWORD|PGPASSWORD|spring\.datasource\.password)$/i;

/* A key-anchored password value is a finding unless it is empty, a reference or a placeholder. hosts() gives the
 * hosts for the local-default check, read only when needed. */
// A ${...} whose whole body is a lower-case dotted property path, with no : (${mail-server.password}): a property
// reference in every file, never the shell's mail with a default. A dotted shell default is no password. Upper
// case or _ makes it a shell name with a default: ${postgres_pw-Hunter2.x}.
const PROPERTY_PATH_REF = /^\$\{[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+\}$/;
function configPasswordIsSecret(raw, hosts, path, { quoted = false, slots = false } = {}) {
  if (PROPERTY_PATH_REF.test(raw.replace(YAML_TAG, ""))) return false;
  const unwrapped = unwrapInterp(raw.replace(YAML_TAG, ""), path);
  if (unwrapped.required) return false;
  if (unwrapped.capped) return true;
  const v = unwrapped.value; // judged on its innermost default
  if (!v || isReference(v, path, slots) || isCodeValue(v, quoted)) return false;
  if (/^[|>][-+]?[0-9]?$/.test(v) || /^\*[\w-]+$/.test(v)) return false; // a YAML block scalar or alias
  // A multi-word placeholder reads as its words joined (change me, your password here).
  const lower = v.toLowerCase().replace(/\s+/g, "_");
  if (CONFIG_PLACEHOLDERS.has(lower) || isPasswordPlaceholder(lower)) return false;
  if (CONFIG_LOCAL_DEFAULTS.has(lower)) return !configLocalOnly(hosts(), path);
  return true;
}

// A password key at the start of its line (after indentation, "- ", "export " or a quote), then : or =.
const CONFIG_KEY = String.raw`^[ \t]{0,200}(?:-[ \t]{1,40}|export[ \t]{1,40})?["']?(?<key>[A-Za-z0-9_.-]{0,124}?(?:pass(?:wo?r?d)?|pwd|passphrase|client[_.-]?secret|jwt\.secret))["']?[ \t]{0,40}[:=][ \t]{0,40}`;
// The password-like key names every config-password form takes (with the passphrase and client and jwt secrets).
const PASSWORD_NAME = String.raw`[A-Za-z0-9_.-]{0,124}?(?:pass(?:wo?r?d)?|pwd|passphrase|client[_.-]?secret|jwt\.secret)`;
// Dockerfiles: Dockerfile, Dockerfile.prod, api.Dockerfile, Containerfile; not Dockerfile.md and the like.
const DOCKERFILE = /(?:^|\/)(?:Dockerfile|Containerfile)(?:\.(?!md$|txt$|rst$|adoc$)[\w-]+)?$|\.(?:dockerfile|containerfile)$/i;
// ENV or ARG, then any KEY=value pairs before the password key.
const DOCKER_KEY = String.raw`^[ \t]{0,40}(?:ENV|ARG)[ \t]{1,40}(?:[A-Za-z_][\w.-]{0,100}=(?:"[^"\r\n]{0,256}"|'[^'\r\n]{0,256}'|` +
  String.raw`[^\s"']{0,256})[ \t]{1,40}){0,20}?(?<key>${PASSWORD_NAME})=`;
// A continuation line of an ENV or ARG instruction: KEY=value pairs at its start, then the password key. Only
// lines `dockerContinued` lists count; the instruction is on an earlier line.
const DOCKER_CONTINUED_KEY = String.raw`^[ \t]{0,40}(?:[A-Za-z_][\w.-]{0,100}=(?:"[^"\r\n]{0,256}"|'[^'\r\n]{0,256}'|` +
  String.raw`[^\s"']{0,256})[ \t]{1,40}){0,20}?(?<key>${PASSWORD_NAME})=`;
/* The start offsets of the lines an ENV or ARG instruction continues onto: each line after one ending in \, while the
 * block goes on. A comment line inside the block is skipped, as Docker skips it. */
function dockerContinued(text) {
  const out = new Set();
  let block = false;
  let at = 0;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const ends = /\\[ \t]*$/.test(line);
    if (block && /^[ \t]*#/.test(line)) {
      at += raw.length + 1;
      continue;
    }
    if (block) out.add(at);
    block = block ? ends : ends && /^[ \t]*(?:ENV|ARG)[ \t]/i.test(line);
    at += raw.length + 1;
  }
  return out;
}
const continuesDocker = (ctx) => ctx.memo("dockerContinued", dockerContinued)
  .has(ctx.text.lastIndexOf("\n", ctx.index - 1) + 1);
// The one-pair form: ENV KEY value, the value running to the end of its line.
const DOCKER_LEGACY_KEY = String.raw`^[ \t]{0,40}ENV[ \t]{1,40}(?<key>${PASSWORD_NAME})[ \t]{1,40}`;
// XML files, with template suffixes, and .config files (web.config).
const XML_FILE = new RegExp(String.raw`\.xml${TEMPLATE_SUFFIX}$|\.config$`, "i");
// An XML element named for a password (<password>, <db.password>, <smtpPassword>, <db:password>).
const XML_ELEMENT_KEY = String.raw`<(?<key>(?:[A-Za-z_][\w.-]{0,60}:)?${PASSWORD_NAME})(?:\s[^<>]{0,200})?>`;
// An element whose name or key attribute names a password (<property name="db.password" ...>, <add key="SmtpPassword" ...>).
const XML_NAMED_KEY = String.raw`<[A-Za-z_][\w.:-]{0,60}\s[^<>]{0,200}?(?<![\w.:-])(?:name|key)[ \t]{0,10}=[ \t]{0,10}` +
  String.raw`["'](?<key>${PASSWORD_NAME})["']`;
// A password attribute (<user password="..."/>, <Resource password="..."/>), up to its value's opening quote.
const XML_ATTRIBUTE_KEY = String.raw`<[A-Za-z_][\w.:-]{0,60}\s[^<>]{0,400}?(?<![\w.:-])(?<key>${PASSWORD_NAME})[ \t]{0,10}=[ \t]{0,10}`;
// An XML attribute value: it runs to the quote it opened with, since XML allows an unescaped > and the other quote
// inside it; < must be escaped, so it ends one.
const XML_VALUE = String.raw`(?<q>["'])(?<secret>(?:(?!\k<q>)[^\r\n<]){1,256})(?=\k<q>)`;
// A value attribute before the name or key attribute that names a password (<add value="..." key="SmtpPassword"/>,
// ). The whole form is the key source: the secret comes first.
const XML_VALUE_FIRST = String.raw`<[A-Za-z_][\w.:-]{0,60}\s[^<>]{0,200}?(?<![\w.:-])value[ \t]{0,10}=[ \t]{0,10}${XML_VALUE}` +
  String.raw`\k<q>[^<>]{0,200}?(?<![\w.:-])(?:name|key)[ \t]{0,10}=[ \t]{0,10}["'](?<key>${PASSWORD_NAME})["']`;
// After a password element's start tag, or a named element's: CDATA text, text alone on the next line, and Spring's
// nested <value> element.
const XML_CDATA = String.raw`\s{0,200}<!\[CDATA\[(?<secret>(?:(?!\]\]>)[^\r\n]){1,256})(?=\]\]>)`;
const XML_OWN_LINE = String.raw`[ \t]{0,200}\r?\n[ \t]{0,200}(?<secret>[^<\s][^<\r\n]{0,255}?)(?=[ \t]{0,200}\r?\n[ \t]{0,200}</)`;
const XML_NESTED_VALUE = String.raw`\s{0,200}<value(?:\s[^<>]{0,200})?>(?<secret>[^<\r\n]{1,256})(?=</value>)`;
// A YAML key named secret alone: judged on its full nested path (jwt: secret:, oauth: client: secret:).
const YAML_SECRET_KEY = String.raw`^[ \t]{0,200}(?:-[ \t]{1,40})?["']?(?<key>secret)["']?[ \t]{0,40}:[ \t]{0,40}`;
/* Each YAML mapping key's dotted path by its line's start offset (jwt.secret, oauth.client.secret): the keys of the
 * lines above it with less indentation. A list item's key counts from after its "- ". Comments, blank lines and
 * anything that is not a key line are skipped. */
function yamlKeyPaths(text) {
  const out = new Map();
  const stack = [];
  let at = 0;
  for (const raw of text.split("\n")) {
    const m = /^([ \t]*(?:-[ \t]+)?)["']?([A-Za-z0-9_.-]{1,124})["']?[ \t]*:(?:[ \t]|$)/.exec(raw.replace(/\r$/, ""));
    if (m) {
      const indent = m[1].length;
      while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
      stack.push({ indent, key: m[2] });
      out.set(at, stack.map((k) => k.key).join("."));
    }
    at += raw.length + 1;
  }
  return out;
}
const yamlKeyPath = (ctx) => ctx.memo("yamlKeyPaths", yamlKeyPaths).get(ctx.text.lastIndexOf("\n", ctx.index - 1) + 1);
// A quoted JSON key after { or , on its line (one-line JSON), then :.
const JSON_KEY = String.raw`[{,][ \t]{0,40}"(?<key>[A-Za-z0-9_.-]{0,124}?(?:pass(?:wo?r?d)?|pwd|passphrase|client[_.-]?secret|jwt\.secret))"[ \t]{0,40}:[ \t]{0,40}`;
/* A YAML flow map holds a literal when any scalar standing as a value in it is a password by the same test:
 * {primary: lit}, {lit}, {a: [lit]}. Plain numbers are settings ({ min: 8 }). */
function flowHoldsLiteral(v, hosts, path) {
  const values = flowValues(v);
  if (values === null) return true;
  return values.some(({ text, quoted }) => !(!quoted && YAML_NUMBER.test(text)) &&
    configPasswordIsSecret(text, hosts, path, { quoted }));
}

/* bare: a bare value; overCap: a bare value longer than the 256-character cap, a finding on any password key;
 * flow: a YAML flow map holding quotes, judged on YAML paths only. Otherwise the value was quoted. keySource and
 * pathContext: the one-line JSON, Dockerfile and XML forms. ownDbKeys: a form database-password-config never matches
 * (ENV KEY value, XML), so this rule judges its keys too. */
const configPassword = (valueSource, { bare = false, overCap = false, flow = false, keySource = CONFIG_KEY,
  pathContext = CONFIG_FILE, ownDbKeys = false, continued = false, nested = false } = {}) => Object.freeze({
  rule_id: "config-password",
  regex: new RegExp(keySource + valueSource, "gim"),
  pathContext,
  fileContext: /pass|pwd|secret/i,
  fallback: true,
  location: true,
  inspectorOnly: true,
  validate(secret, ctx) {
    // An XML namespace prefix (db:password) names nothing; a nested YAML secret is named by its path.
    const key = nested ? yamlKeyPath(ctx) ?? "" : ctx.groups.key.replace(/^[^:]*:/, "");
    if (isTranslationFile(ctx.path) || isSops(ctx)) return false;
    if (continued && !continuesDocker(ctx)) return false;
    if (overCap) return DB_PASSWORD_KEY.test(key) || passwordKey(key);
    const yaml = YAML_FILE.test(ctx.path);
    if (flow && !yaml) return false;
    // In YAML a bare value is judged after its tag or anchor; one alone (password: &pw) is no value. A bare
    // value may hold a quote, but one that starts with a quote after its tag or anchor is the quoted form's.
    if (bare && yaml) {
      secret = secret.replace(YAML_PROPS, "");
      if (!secret || /^["']/.test(secret)) return false;
    }
    const hosts = () => ctx.memo("dbHosts", fileDbHosts);
    // A bare value that is a whole YAML flow map or sequence is structure, not a value, unless it holds a
    // literal (a map or a sequence). YAML only: elsewhere a leading { or [ is the password's first
    // character ({noop}pw in Spring properties).
    if (bare && yaml && isFlowCollection(secret)) {
      // {{ vault_pw }} is a slot; a sequence is judged by its items ([YOUR-PASSWORD] holds a placeholder)
      if (secret.startsWith("{") && isReference(secret, ctx.path)) return false;
      return passwordKey(key) && flowHoldsLiteral(secret, hosts, ctx.path);
    }
    // On a key database-password-config owns, that rule reports every other literal; this one adds a local default
    // in a file whose path names prod or production, wherever its hosts are. That rule reads ${VAR:default} as a
    // reference, so a default there is judged here, with that rule's own host logic.
    if (DB_PASSWORD_KEY.test(key) && !ownDbKeys) {
      if (PROPERTY_PATH_REF.test(secret)) return false;
      const { interp, required, capped, value } = unwrapInterp(secret, ctx.path);
      if (required) return false;
      if (capped) return true;
      if (interp && (!value || isReference(value, ctx.path) || isCodeValue(value, !bare))) return false;
      if (interp && passwordIsSecret(value, hosts(), ctx.path)) return true;
      return PROD_PATH.test(ctx.path) && CONFIG_LOCAL_DEFAULTS.has(value.toLowerCase());
    }
    return (passwordKey(key) || DB_PASSWORD_KEY.test(key)) &&
      configPasswordIsSecret(secret, hosts, ctx.path, { quoted: !bare });
  },
});

/* The server of an ADO.NET or SQL Server connection string on the line: Server=, Data Source=, Address= or Addr=,
 * without tcp:, a port (,1433) or an instance (\SQLEXPRESS). (local), (localdb) and "." are this machine. */
function connectionHosts(line) {
  const out = [];
  const re = /(?:^|[;"'\s])(?:server|data[ \t]+source|host|address|addr|network[ \t]+address)[ \t]*=[ \t]*([^;"']*)/gi;
  let m;
  while ((m = re.exec(line)) !== null) {
    const h = m[1].trim().replace(/^tcp:/i, "").split(/[,\\]/)[0].trim().toLowerCase();
    out.push(h === "." || h === "(local)" || h.startsWith("(localdb)") ? "localhost" : h);
  }
  return out;
}

// A service-role key name: *SERVICE_ROLE_KEY, SERVICE_ROLE, SUPABASE_SERVICE_KEY, serviceRoleKey, any case.
const SERVICE_ROLE_NAMES = String.raw`(?:[A-Za-z0-9]{1,40}[_-]?)?service[_-]?role(?:[_-]?key)?|supabase[_-]?service[_-]?key`;
/* A JWT whose payload decodes and names a role other than service_role (an anon key): public by design. */
const otherRoleJwt = (v) => {
  const parts = v.split(".");
  if (parts.length !== 3 || !v.startsWith("eyJ")) return false;
  const p = decodeJwtPart(parts[1]);
  return !!p && typeof p === "object" && typeof p.role === "string" && p.role !== "service_role";
};

// Schemes the five database URL rules cover (with jdbc: and +driver forms); url-userinfo-password skips them.
const DB_URL_SCHEMES = /^(?:postgres(?:ql)?|mysql|mariadb|mongodb|rediss?|amqps?)(?:\+[A-Za-z0-9_]+)?$/i;

export const DEFAULT_SECRET_PATTERNS = Object.freeze([
  Object.freeze({
    // Glued to lowercase letters is still a match (idAKIA...); glued to uppercase or digits is part of a longer token.
    rule_id: "aws-access-key-id",
    regex: /(?<![A-Z0-9])(?<secret>(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})(?![A-Z0-9])/g,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "aws-secret-access-key",
    regex: contextValue(AWS_SECRET_NAMES, AWS_SECRET_VALUE, "gi"),
    fileContext: AWS_HINT,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "aws-secret-access-key", regex: nameValue(AWS_SECRET_NAMES, AWS_SECRET_VALUE), fileContext: AWS_HINT,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "aws-secret-access-key",
    regex: TF_SECRET,
    fileContext: /secret_key/,
    validate: (secret, { before, after }) => terraformAws(before, after),
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "stripe-secret-key",
    regex: /(?<![A-Za-z0-9_])(?<secret>(?:sk|rk)_live_[A-Za-z0-9]{24,247})(?![A-Za-z0-9_])/g,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "stripe-webhook-secret",
    regex: /(?<![A-Za-z0-9_])(?<secret>whsec_[A-Za-z0-9+/=]{24,128})(?![A-Za-z0-9+/=])/g,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "rails-secret-key-base",
    regex: contextValue("secret_key_base", String.raw`[0-9a-fA-F]{64,256}(?![0-9A-Za-z])`, "gi"),
    fileContext: /secret_key_base/i,
    placeholders: true,
  }),
  Object.freeze({
    // Django's SECRET_KEY: 40 to 80 characters from Django's own alphabet (lower case, digits and !@#$%^&*(-_=+)),
    // optionally after django-insecure-, quoted (settings.py) or bare (.env).
    rule_id: "django-secret-key",
    fileContext: /SECRET_KEY/,
    regex: /(?<![A-Za-z0-9])(?:DJANGO_)?SECRET_KEY[ \t]{0,40}[:=][ \t]{0,40}(?<q>["']?)(?<secret>(?:django-insecure-)?[a-z0-9!@#$%^&*(\-_=+)]{40,80})(?![a-z0-9!@#$%^&*(\-_=+)])(?=\k<q>)/g,
    validate: (secret) => /[a-z]/.test(secret) && /[0-9]/.test(secret) && !isClearPlaceholder(secret) &&
      !isVariableReference(secret),
  }),
  Object.freeze({
    // Database password settings with a literal value. A well-known local default (POSTGRES_PASSWORD: postgres) is
    // skipped only when every host the file names is loopback (or it names none).
    rule_id: "database-password-config",
    regex: contextValue(String.raw`(?:POSTGRES|POSTGRESQL|PG|MYSQL|MYSQL_ROOT|MARIADB|MARIADB_ROOT|MONGO_INITDB_ROOT|DB|` +
      String.raw`DATABASE)_PASSWORD(?![A-Za-z0-9_])|PGPASSWORD(?![A-Za-z0-9_])|spring\.datasource\.password`,
      String.raw`(?:[^\s"'#,;]|[#,;](?=[^\s"'#,;]))[^\s"'#,;]{0,255}`, "gi"),
    fileContext: /password/i,
    // A value may start with , ; or # only where that is no comment.
    validate: (secret, ctx) => (!/^[#,;]/.test(secret) || LEADING_PUNCT_FILE.test(ctx.path)) && !isCodeValue(secret) &&
      !isSops(ctx) &&
      passwordIsSecret(secret, ctx.memo("dbHosts", fileDbHosts), ctx.path),
  }),
  Object.freeze({
    rule_id: "github-token",
    regex: /(?<![A-Za-z0-9_])(?<secret>gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{80,244})(?![A-Za-z0-9_])/g,
    placeholders: true,
  }),
  Object.freeze({
    // The header alone is not enough: a base64 body line must follow, so documentation that shows only the header
    // (or "...") is not a finding, and the fingerprint covers the key body rather than a header every key shares.
    rule_id: "pem-private-key",
    regex: PEM,
    normalize: normalizePem,
    ending: pemEnding,
  }),
  Object.freeze({
    // A JWT whose payload says role service_role (Supabase's service role key). The anon key has role anon and is
    // public by design, so it is not a finding.
    rule_id: "supabase-service-role-jwt",
    regex: /(?<![A-Za-z0-9_-])(?<secret>eyJ[A-Za-z0-9_-]{10,500}\.eyJ[A-Za-z0-9_-]{20,2000}\.[A-Za-z0-9_-]{20,500})(?![A-Za-z0-9_-])/g,
    validate(secret) {
      const [header, payload] = secret.split(".");
      // Cheap checks first: most JWT-shaped strings are not service role keys, and JSON.parse failures are slow.
      if (!Buffer.from(payload, "base64url").toString("latin1").includes("service_role")) return false;
      const h = decodeJwtPart(header), p = decodeJwtPart(payload);
      return !!h && typeof h === "object" && !!p && typeof p === "object" && p.role === "service_role";
    },
  }),
  Object.freeze({
    rule_id: "supabase-secret-key",
    regex: /(?<![A-Za-z0-9_])(?<secret>sb_secret_[A-Za-z0-9_-]{20,200})(?![A-Za-z0-9_-])/g,
    placeholders: true,
  }),
  Object.freeze({
    // The project's JWT signing secret, recognised by its variable name. The self-host default
    // (super-secret-jwt-token-with-at-least-32-characters-long) is a finding on purpose: using it anywhere real is a risk.
    rule_id: "supabase-jwt-secret",
    regex: contextValue("SUPABASE_JWT_SECRET|supabase_jwt_secret", String.raw`[^\s"'#]{16,512}`),
    fileContext: /supabase_jwt_secret/i,
    validate: (secret) => !isVariableReference(secret) && !isClearPlaceholder(secret),
  }),
  // Database URLs with a password. Only whole variable references, exact placeholder words and a well-known local
  // default on a loopback host are skipped; a password starting with $ or % (URL-encoded) is a finding.
  ...urlPassword("postgres-url-password", "postgres(?:ql)?"),
  ...urlPassword("mysql-url-password", "mysql|mariadb"),
  ...urlPassword("mongodb-url-password", "mongodb"),
  ...urlPassword("redis-url-password", "rediss?"),
  ...urlPassword("amqp-url-password", "amqps?"),
  Object.freeze({
    rule_id: "postgres-keyword-password",
    regex: new RegExp(String.raw`(?<![A-Za-z0-9_])(?:${LIBPQ_KEYS})=[^\s]{0,256}(?:[ \t]+[a-z_]{1,32}=[^\s]{0,256}){0,8}?` +
      String.raw`[ \t]+password=(?<secret>[^\s'"]{1,256})`, "g"),
    fileContext: /password=/,
    validate: (secret, { line }) => passwordIsSecret(secret, libpqHosts(line)),
  }),
  Object.freeze({
    rule_id: "postgres-keyword-password",
    regex: new RegExp(String.raw`(?<![A-Za-z0-9_])password=(?<secret>[^\s'"]{1,256})` +
      String.raw`(?=(?:[ \t]+[a-z_]{1,32}=[^\s]{0,256}){0,8}?[ \t]+(?:host|hostaddr|dbname)=)`, "g"),
    fileContext: /password=/,
    validate: (secret, { line }) => passwordIsSecret(secret, libpqHosts(line)),
  }),
  Object.freeze({
    rule_id: "openai-api-key",
    regex: /(?<![A-Za-z0-9_-])(?<secret>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,300}|sk-[A-Za-z0-9]{48})(?![A-Za-z0-9_-])/g,
    placeholders: true,
  }),
  Object.freeze({
    // GitLab personal, project and group access tokens: glpat- and 20 characters (newer ones are longer).
    rule_id: "gitlab-token",
    regex: /(?<![A-Za-z0-9_-])(?<secret>glpat-[A-Za-z0-9_-]{20,64})(?![A-Za-z0-9_-])/g,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "anthropic-api-key",
    regex: /(?<![A-Za-z0-9_-])(?<secret>sk-ant-[A-Za-z0-9_-]{32,300})(?![A-Za-z0-9_-])/g,
    placeholders: true,
  }),
  Object.freeze({
    // Bot, user and legacy tokens, app-level tokens (xapp-) and rotating tokens (xoxe.xoxp-, xoxe-).
    rule_id: "slack-token",
    regex: /(?<![A-Za-z0-9_.-])(?<secret>xox[baprs]-[0-9]{6,20}-[A-Za-z0-9-]{10,200}|xapp-[0-9]-[A-Z0-9]{8,20}-[0-9]{6,20}-[A-Za-z0-9]{20,200}|xoxe(?:\.xox[bp])?-[0-9]-[A-Za-z0-9-]{20,300})(?![A-Za-z0-9_-])/g,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "slack-webhook-url",
    regex: /(?<secret>hooks\.slack\.com\/(?:services|workflows|triggers)\/T[A-Z0-9]{6,20}\/[AB][A-Z0-9]{6,20}\/[A-Za-z0-9]{20,64})(?![A-Za-z0-9])/g,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "google-api-key",
    regex: /(?<![A-Za-z0-9_-])(?<secret>AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])/g,
    placeholders: true,
  }),
  Object.freeze({
    // An API key SID (SK + 32 hex) only in a file that names or imports Twilio, since SK + 32 hex alone is too generic.
    rule_id: "twilio-api-key",
    regex: /(?<![A-Za-z0-9])(?<secret>SK[0-9a-fA-F]{32})(?![A-Za-z0-9])/g,
    fileContext: /twilio/i,
    placeholders: true,
  }),
  Object.freeze({
    // The auth token: 32 hex after TWILIO_AUTH_TOKEN, or after authToken / auth_token in a file that names Twilio.
    rule_id: "twilio-auth-token",
    regex: contextValue(String.raw`(?:twilio[_-]?)?auth[_-]?token`, String.raw`[0-9a-f]{32}(?![A-Za-z0-9])`, "gi"),
    fileContext: /twilio/i,
    placeholders: true,
  }),
  Object.freeze({
    rule_id: "sendgrid-api-key",
    regex: /(?<![A-Za-z0-9_-])(?<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/g,
    placeholders: true,
  }),
  Object.freeze({
    // JWT_SECRET, SECRET_KEY, SESSION_SECRET in any case and spelling (jwtSecret, jwt_secret, secretKey), also with a
    // prefix such as APP_JWT_SECRET. Supabase's and AWS's
    // names have their own rules. A fallback: dropped when a specific rule (STRIPE_SECRET_KEY=sk_live_...) found
    // something on the same line.
    rule_id: "generic-app-secret",
    fallback: true,
    fileContext: /secret/i,
    regex: contextValue(String.raw`(?<!SUPABASE_)(?<!AWS_)(?:jwt[_-]?secret|secret[_-]?key|session[_-]?secret)` +
      String.raw`(?![A-Za-z0-9])`, String.raw`[^\s"'#,;]{24,512}`, "gi"),
    // In a config file, or quoted, a value is code only by the password rules' whole-value test: a bracket in
    // it is part of the secret. In source code a capture cut at a quote must still read as code (isCodeReference).
    validate: (secret, ctx) => looksRandom(secret) && !isVariableReference(secret) &&
      !(CONFIG_FILE.test(ctx.path) || /["']/.test(ctx.text[ctx.index - 1] ?? "")
        ? isCodeValue(secret, /["']/.test(ctx.text[ctx.index - 1] ?? "")) : isCodeReference(secret)) &&
      !isClearPlaceholder(secret) && !PLACEHOLDER_PASSWORDS.has(secret.toLowerCase()),
  }),
  // A password key with a literal value in a config file: a quoted value up to its closing quote, or a bare
  // value up to the end of its line (before a comment or a comma). Several words are a passphrase, a finding.
  // A fallback: database-password-config wins on the same line.
  // A quoted value runs to its own closing quote, so it may hold the other kind (it's), after a YAML tag or anchor.
  configPassword(String.raw`(?:${YAML_PROPS_SOURCE}[ \t]{1,40}){0,2}(?<q>["'])(?<secret>(?:(?!\k<q>)[^\r\n]){1,256})(?=\k<q>)`),
  configPassword(String.raw`(?<secret>[^\s"'#,;][^\r\n#;]{0,255}?)(?=[ \t]{0,40}(?:[#;][^\n]{0,2048}|,[ \t]{0,40})?\r?$)`,
    { bare: true }),
  // The same starting with , ; or #, where that is no comment.
  configPassword(String.raw`(?<secret>[#,;][^\r\n#;]{1,255}?)(?=[ \t]{0,40}(?:[#;][^\n]{0,2048}|,[ \t]{0,40})?\r?$)`,
    { bare: true, pathContext: LEADING_PUNCT_FILE }),
  // The same two forms under a YAML key named secret alone, judged on its nested path.
  configPassword(String.raw`(?:${YAML_PROPS_SOURCE}[ \t]{1,40}){0,2}(?<q>["'])(?<secret>(?:(?!\k<q>)[^\r\n]){1,256})(?=\k<q>)`,
    { keySource: YAML_SECRET_KEY, pathContext: YAML_FILE, nested: true }),
  configPassword(String.raw`(?<secret>[^\s"'#,;][^\r\n#;]{0,255}?)(?=[ \t]{0,40}(?:[#;][^\n]{0,2048}|,[ \t]{0,40})?\r?$)`,
    { keySource: YAML_SECRET_KEY, pathContext: YAML_FILE, nested: true, bare: true }),
  // A quoted value longer than the cap, in YAML and TOML: a finding too.
  configPassword(String.raw`(?:${YAML_PROPS_SOURCE}[ \t]{1,40}){0,2}(?<q>["'])(?<secret>(?:(?!\k<q>)[^\r\n]){257})`,
    { overCap: true, pathContext: YAML_OR_TOML_FILE }),
  // A bare value longer than the cap above: its first 257 characters, a finding (the cap must not fail open).
  configPassword(String.raw`(?<secret>[^\s"'#,;][^\r\n#;]{256})`, { bare: true, overCap: true }),
  // A YAML flow map or sequence that holds a quote ({primary: "lit"}, ["lit"]), which the bare form above stops at
  //, after a tag or anchor (!!map).
  configPassword(String.raw`(?:${YAML_PROPS_SOURCE}[ \t]{1,40}){0,2}(?<secret>[{[][^\r\n"']{0,255}["'][^\r\n]{0,255}?[}\]])` +
    String.raw`(?=[ \t]{0,40}(?:#[^\n]{0,2048})?\r?$)`, { bare: true, flow: true }),
  // One-line JSON: a password key after { or , on its line, and its quoted value.
  configPassword(String.raw`"(?<secret>[^"\r\n]{1,256})(?=")`, { keySource: JSON_KEY, pathContext: JSON_FILE }),
  // Dockerfile ENV and ARG: KEY="value" or KEY=value among other pairs, and ENV KEY value.
  configPassword(String.raw`(?<q>["'])(?<secret>(?:(?!\k<q>)[^\r\n]){1,256})(?=\k<q>)`,
    { keySource: DOCKER_KEY, pathContext: DOCKERFILE }),
  configPassword(String.raw`(?<secret>[^\s"'][^\s]{0,255}?)(?=[ \t]|\\?\r?$)`, { keySource: DOCKER_KEY, pathContext: DOCKERFILE }),
  configPassword(String.raw`(?<secret>[^\s="'][^\r\n]{0,255}?)(?=[ \t]{0,40}\\?\r?$)`,
    { keySource: DOCKER_LEGACY_KEY, pathContext: DOCKERFILE, ownDbKeys: true }),
  // The same pairs on a continuation line of an ENV or ARG block.
  configPassword(String.raw`(?<q>["'])(?<secret>(?:(?!\k<q>)[^\r\n]){1,256})(?=\k<q>)`,
    { keySource: DOCKER_CONTINUED_KEY, pathContext: DOCKERFILE, continued: true }),
  configPassword(String.raw`(?<secret>[^\s"'][^\s]{0,255}?)(?=[ \t]|\\?\r?$)`,
    { keySource: DOCKER_CONTINUED_KEY, pathContext: DOCKERFILE, continued: true }),
  // XML: a password element's text, a name or key attribute's value attribute or text, and a password attribute.
  configPassword(String.raw`(?<secret>[^<\r\n]{1,256})(?=</)`, { keySource: XML_ELEMENT_KEY, pathContext: XML_FILE, ownDbKeys: true }),
  configPassword(String.raw`[^<>]{0,200}?(?<![\w.:-])value[ \t]{0,10}=[ \t]{0,10}${XML_VALUE}`,
    { keySource: XML_NAMED_KEY, pathContext: XML_FILE, ownDbKeys: true }),
  configPassword(String.raw`[^<>/]{0,200}>(?<secret>[^<\r\n]{1,256})(?=</)`,
    { keySource: XML_NAMED_KEY, pathContext: XML_FILE, ownDbKeys: true }),
  configPassword(XML_VALUE,
    { keySource: XML_ATTRIBUTE_KEY, pathContext: XML_FILE, ownDbKeys: true }),
  configPassword("", { keySource: XML_VALUE_FIRST, pathContext: XML_FILE, ownDbKeys: true }),
  ...[XML_CDATA, XML_OWN_LINE].map((value) => configPassword(value,
    { keySource: XML_ELEMENT_KEY, pathContext: XML_FILE, ownDbKeys: true })),
  ...[XML_CDATA, XML_OWN_LINE, XML_NESTED_VALUE].map((value) => configPassword(String.raw`[^<>/]{0,200}>${value}`,
    { keySource: XML_NAMED_KEY, pathContext: XML_FILE, ownDbKeys: true })),
  Object.freeze({
    // Password=x; or Pwd=x; in an ADO.NET, SQL Server or Npgsql connection string (Server=, Data Source= or Host= on
    // the line).
    rule_id: "config-password",
    regex: /(?<![A-Za-z0-9_])(?:password|pwd)[ \t]{0,40}=[ \t]{0,40}(?<secret>[^;"'\r\n]{1,256}?)(?=[ \t]{0,40}(?:;|["']|\r?$))/gim,
    pathContext: CONNECTION_FILE,
    fileContext: /(?:server|data[ \t]+source|host)[ \t]*=/i,
    fallback: true,
    location: true,
    inspectorOnly: true,
    validate: (secret, { line, path }) => /(?:^|[;"'\s])(?:server|data[ \t]+source|host)[ \t]*=/i.test(line) &&
      configPasswordIsSecret(secret.trim(), () => connectionHosts(line), path, { slots: true }),
  }),
  Object.freeze({
    // A literal of 20 or more characters under a service-role key name, in any file. A fallback: the JWT and
    // sb_secret_ rules win on the same line.
    rule_id: "supabase-service-role-config",
    regex: contextValue(SERVICE_ROLE_NAMES, String.raw`[^\s"'#,;]{20,2048}(?![^\s"'#,;])`, "gi"),
    fileContext: /service.?role|supabase.?service/i,
    fallback: true,
    location: true,
    inspectorOnly: true,
    // An environment variable's name (SUPABASE_SERVICE_ROLE_KEY) is not a value; a code reference may end with a
    // TypeScript ! or ? (process.env.SUPABASE_SERVICE_ROLE_KEY!).
    validate: (secret) => !isVariableReference(secret) && !isCodeReference(secret.replace(/[!?]+$/, "")) &&
      !isClearPlaceholder(secret) && !/^[A-Z][A-Z0-9_]*$/.test(secret) && !/^sb_publishable_/.test(secret) &&
      !otherRoleJwt(secret),
  }),
  Object.freeze({
    // scheme://user:password@host for schemes the database URL rules don't cover (https, smtp, ftp, ldap, ...).
    rule_id: "url-userinfo-password",
    regex: new RegExp(String.raw`(?<![A-Za-z0-9+.-])(?<scheme>[A-Za-z][A-Za-z0-9+.-]{1,30}):\/\/` +
      atomic("user", String.raw`[^\s:/@'"\`]{1,128}`) + ":" + atomic("secret", String.raw`[^\s@/'"\`]{1,256}`) +
      String.raw`(?=@[A-Za-z0-9[])`, "g"),
    fileContext: /:\/\/[^\s:/@]{1,128}:[^\s@/]{1,256}@/,
    fallback: true,
    location: true,
    inspectorOnly: true,
    validate: (secret, { groups, after }) => !DB_URL_SCHEMES.test(groups.scheme.replace(/^jdbc:/i, "")) &&
      passwordIsSecret(secret, hostsAfterPassword(after)),
  }),
]);
