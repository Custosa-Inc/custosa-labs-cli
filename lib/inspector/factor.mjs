/* The NapiConfig each rule is compiled from, built so that @ast-grep/napi compiles less (the rule files are untouched).
 *
 * @ast-grep/napi (0.45) compiles the whole rule object on every root.findAll(rule) and node.matches(control), and has
 * no compiled-matcher API. Most of that cost is compiling regexes, and the rule files repeat a lot: YAML anchors are
 * expanded on load, so a shared sub-rule (and its regexes) is compiled once per place it is used. ast-grep compiles a
 * `utils` entry once per call, however many `matches` refer to it, so:
 * - A sub-rule used at least twice in one rule (its rule and control together) and at least MIN_BYTES long (as JSON)
 *   becomes a util, referred to by {matches: name} where it stood.
 * - A regex used at least twice becomes a {regex} util, and the rule object that held it refers to it by matches.
 * - Each call gets only the utils it reaches (ast-grep compiles every util it is given).
 * The matches are the same: a util is matched with the environment of the rule that refers to it (metavariables bound
 * before it are seen inside it, and the ones it binds are seen after), and a regex neither reads nor binds one. Only
 * whole rule objects at rule positions are replaced: never a relational rule itself (its stopBy and field belong to
 * it), never a pattern object, never a top-level rule or control.
 *
 * engineConfig(rule) -> {rule: NapiConfig, control: NapiConfig | null, key}; key is the same for rules whose rule
 * object is identical (their findAll can be shared within one file).
 * engineConfigs(rules) -> the same for a whole bundle, key being the id of the first rule with that rule object (the
 * rule loader's thread works these out once per bundle; rules.mjs). */
const isMap = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const RELATIONAL = ["inside", "has", "precedes", "follows"];
export const MIN_BYTES = 40;

/* Visit every rule object at a rule position: the roots, the sub-rules of all, any and not, the stopBy rule of a
 * relational rule, and the rule objects inside a relational rule (but not the relational rule itself). */
function visit(o, fn, relational = false) {
  if (!isMap(o)) return;
  if (!relational) fn(o);
  else if (isMap(o.stopBy)) visit(o.stopBy, fn);
  for (const r of RELATIONAL) if (isMap(o[r])) visit(o[r], fn, true);
  if (isMap(o.not)) visit(o.not, fn);
  for (const c of ["all", "any"]) if (Array.isArray(o[c])) for (const x of o[c]) visit(x, fn);
}

/* roots (rule objects, or null) -> {rewritten, utils}. */
export function factor(roots, { minBytes = MIN_BYTES } = {}) {
  const counts = new Map(), regexCounts = new Map();
  for (const root of roots) {
    visit(root, (o) => {
      const k = JSON.stringify(o);
      counts.set(k, (counts.get(k) ?? 0) + 1);
      if (typeof o.regex === "string") regexCounts.set(o.regex, (regexCounts.get(o.regex) ?? 0) + 1);
    });
  }
  const utils = {}, names = new Map(), regexNames = new Map();
  const regexUtil = (re) => {
    if (!regexNames.has(re)) { const n = `r${regexNames.size}`; regexNames.set(re, n); utils[n] = { regex: re }; }
    return regexNames.get(re);
  };
  const subRuleUtil = (k) => {
    if (!names.has(k)) { const n = `u${names.size}`; names.set(k, n); utils[n] = rewriteObject(JSON.parse(k)); }
    return names.get(k);
  };
  // A rule object below the top: replaced by a reference when it repeats, else rewritten inside.
  const rewrite = (o) => {
    if (!isMap(o)) return o;
    const k = JSON.stringify(o);
    if (counts.get(k) >= 2 && k.length >= minBytes) return { matches: subRuleUtil(k) };
    return rewriteObject(o);
  };
  function rewriteObject(o) {
    const out = {};
    for (const [key, v] of Object.entries(o)) {
      if (key === "regex" && typeof v === "string" && regexCounts.get(v) >= 2 && !("matches" in o)) out.matches = regexUtil(v);
      else if (RELATIONAL.includes(key) && isMap(v)) out[key] = rewriteRelational(v);
      else if (key === "not" && isMap(v)) out[key] = rewrite(v);
      else if ((key === "all" || key === "any") && Array.isArray(v)) out[key] = v.map(rewrite);
      else out[key] = v;
    }
    return out;
  }
  function rewriteRelational(o) {
    const out = rewriteObject(o);
    if (isMap(o.stopBy)) out.stopBy = rewrite(o.stopBy);
    return out;
  }
  return { rewritten: roots.map((r) => (isMap(r) ? rewriteObject(r) : r)), utils };
}

/* The util names a rule object refers to, directly or through other utils. */
function reach(root, utils) {
  const seen = new Set(), stack = [root];
  while (stack.length) {
    const o = stack.pop();
    if (Array.isArray(o)) { stack.push(...o); continue; }
    if (!isMap(o)) continue;
    for (const [k, v] of Object.entries(o)) {
      if (k === "matches" && typeof v === "string") { if (!seen.has(v)) { seen.add(v); stack.push(utils[v]); } }
      else stack.push(v);
    }
  }
  return seen;
}

function napiConfig(root, utils) {
  const used = reach(root, utils);
  if (!used.size) return { rule: root };
  const own = {};
  for (const n of [...used].sort()) own[n] = utils[n];
  return { rule: root, utils: own };
}

/* A rule's {rule, control} NapiConfigs, factored together. */
function configsOf(rule, control) {
  const { rewritten: [r, c], utils } = factor([rule, control ?? null]);
  return { rule: napiConfig(r, utils), control: isMap(c) ? napiConfig(c, utils) : null };
}

export function engineConfig(rule) {
  return { ...configsOf(rule.rule, rule.control), key: JSON.stringify(rule.rule) };
}

export function engineConfigs(rules) {
  const firstWith = new Map();
  return rules.map((rule) => {
    const json = JSON.stringify(rule.rule);
    if (!firstWith.has(json)) firstWith.set(json, rule.id);
    return { ...configsOf(rule.rule, rule.control), key: firstWith.get(json) };
  });
}
