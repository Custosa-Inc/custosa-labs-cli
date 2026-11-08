/* Parse and match one file at a time in a worker thread (node:worker_threads, not a child process), so runRules can
 * enforce a hard per-file deadline by terminating the worker. Matches are posted rule by rule as they are found, so
 * the violations found before a deadline or a failing rule are kept.
 *
 * Protocol: workerData {custosaRules: true, rules, key, factor, contentKey}; the worker posts {type: "ready"}. Each job {path, local, lang,
 * text, ruleIds, softMs} gets {type: "found", matches} per rule, then {type: "done", parseError, recovered, late,
 * ruleError}. {type: "replace", matches} takes the place of every match found so far for the job: a
 * recovered tree was repaired to a clean one and the rules ran again on it to the end (see runJob). Each match carries
 * table (the rule's table.metavariable capture) and handler (the id of the function the match belongs to), both from
 * captures.mjs and null when there is none.
 * softMs: the limit on this thread's CPU time for the file (parse and rules), checked between rules. CPU time, not wall
 * time, so a file on a busy computer isn't cut short for waiting on a core. A single native findAll can't be
 * interrupted; the wall-clock hard deadline in runRules covers it, and a long wait for a core too.
 * factor (default true): each rule runs from its factored NapiConfigs (factor.mjs: rule.engine when the rule loader's
 * thread worked them out, else worked out here on the rule's first file), rules with an identical rule object share one
 * findAll per file, and each prefilter word is looked up once per file. false runs every rule from its rule object as
 * written (the same matches; kept to check the two against each other). */
import { createHmac } from "node:crypto";
import { isMainThread, parentPort, workerData } from "node:worker_threads";
import { Handlers, tableOf } from "./captures.mjs";
import { hasRepair, parseSync, recovered, repairRecovered } from "./parse.mjs";
import { FileText, requirement, satisfied, satisfiedOnce } from "./prefilter.mjs";
import { engineConfig } from "./factor.mjs";
import { sharedFingerprint } from "./walk.mjs";

/* Each rule's prefilter requirement (prefilter.mjs), worked out once per rule object. */
const requirements = new WeakMap();
const requirementOf = (rule, lang) => {
  if (!requirements.has(rule)) requirements.set(rule, requirement(rule.rule, lang));
  return requirements.get(rule);
};

/* Each rule's NapiConfigs (factor.mjs), worked out once per rule object when the loader didn't send them. */
const engines = new WeakMap();
const engineOf = (rule) => {
  if (rule.engine) return rule.engine;
  if (!engines.has(rule)) engines.set(rule, engineConfig(rule));
  return engines.get(rule);
};

/** This thread's CPU time in ms (user and system), or wall time on a Node without process.threadCpuUsage. */
export const threadCpuMs = typeof process.threadCpuUsage === "function"
  ? () => { const u = process.threadCpuUsage(); return (u.user + u.system) / 1000; }
  : () => Date.now();

/** Line breaks as the inspector counts them: \n, \r\n and a lone \r. A lone \r becomes \n, one character for
 * one, so offsets, columns and fingerprints (whitespace collapsed) are unchanged. */
export const normalizeBreaks = (text) => (text.includes("\r") ? text.replace(/\r(?!\n)/g, "\n") : text);

export function fingerprint(key, ruleId, path, text) {
  return createHmac("sha256", key).update(`${ruleId}\n${path}\n${text.replace(/\s+/g, " ")}`, "utf8").digest("hex");
}

function lines(range) {
  const { start, end } = range;
  // A node that ends at column 0 of a later line ends on the line before.
  const last = end.line > start.line && end.column === 0 ? end.line - 1 : end.line;
  return [start.line + 1, last + 1];
}

/* Run the given rules on one parsed root; post each rule's matches. Returns {late, ruleError}. text: the parsed text,
 * when given, lets a rule that can't match it (prefilter.mjs) be skipped without compiling it. clock (default
 * Date.now): what started and softMs are measured on (the worker passes threadCpuMs). factor: see the header.
 * contentKey: when given, each match carries shared_fingerprint, the walk of its node keyed
 * with it, sliced from source (the exact text parsed; without it, null). The field is required on every match: null
 * without a content key. local (default path): the file's local path, which the shared fingerprint takes instead of
 * the sent one, so a path hashed per install still gives the same value on every machine. */
export function matchRoot(root, path, lang, rules, key, { started, softMs, post, text = null, clock = Date.now, factor = false,
  contentKey = null, source = null, local = path }) {
  const handlers = new Handlers(root, lang, path, key);
  const file = typeof text === "string" ? new FileText(text) : null;
  const shared = factor ? new Map() : null; // engine key -> the nodes its rule object found in this file
  const words = factor ? new Map() : null; // prefilter word -> whether this file holds it
  for (const rule of rules) {
    if (clock() - started > softMs) return { late: true, ruleError: false };
    if (file && !(factor ? satisfiedOnce(requirementOf(rule, lang), file, words) : satisfied(requirementOf(rule, lang), file))) continue;
    let found;
    try {
      const engine = factor ? engineOf(rule) : null;
      let nodes;
      if (engine) {
        nodes = shared.get(engine.key);
        if (!nodes) { nodes = root.findAll(engine.rule); shared.set(engine.key, nodes); }
      } else nodes = root.findAll({ rule: rule.rule });
      found = nodes.map((node) => {
        const range = node.range();
        const text = node.text();
        const [line_start, line_end] = lines(range);
        const item = rule.kind === "items";
        return {
          rule_id: rule.id, practice_id: rule.practice_id, kind: item ? "item" : rule.kind, path, line_start, line_end,
          fingerprint: fingerprint(key, rule.id, path, text),
          has_control: item ? node.matches(engine ? engine.control : { rule: rule.control }) : null,
          table: rule.table ? tableOf(node.getMatch(rule.table.metavariable.slice(1)), key, lang, handlers) : null,
          handler: handlers.of(node, range, text),
          shared_fingerprint: contentKey && typeof source === "string"
            ? sharedFingerprint(contentKey, rule.id, local, node, lang, source) : null,
        };
      });
    } catch {
      return { late: false, ruleError: true };
    }
    post(found);
  }
  return { late: false, ruleError: false };
}

/* CUSTOSA_NO_PREFILTER=1 turns the prefilter off: every applicable rule is compiled and run on every file (slower,
 * the same matches; for checking the prefilter against the engine). */
const PREFILTER = process.env.CUSTOSA_NO_PREFILTER !== "1";

/**
 * runJob(job, ctx) -> the done message ({type: "done", parseError, recovered, late, ruleError}); what the worker does
 * for one job. job: {path, local (the local path, for the shared fingerprint; default path), lang, text (line breaks
 * already normalised), softMs}. ctx: {rules (the job's rule objects),
 * key, factor, prefilter, send (posts one message to the parent), clock (default threadCpuMs), match (default
 * matchRoot; a seam for tests), contentKey (the root's content key or null; each pass's shared fingerprints
 * slice that pass's parsedText)}. clock also measures softMs and the repair's deadline.
 *
 * The first pass matches the parsed tree and posts each rule's matches as found, then checks the tree for recovery
 * (after matching, so the violations are already posted if this walk runs into the deadline). A recovered
 * tree in a language with a repair (parse.mjs repairRecovered) whose repair parses cleanly gets a second pass on the
 * clean tree, with these rules:
 * - Budget: the second pass runs on what is left of the same softMs (one clock from the job's start). It is skipped
 *   when less is left than the first pass took (the parse, matching and recovery check), since it does all of that
 *   again; the file then stays parse_error. The repair is bounded by the same deadline (started + softMs): past it,
 *   the repair stops and the file stays parse_error.
 * - Atomic: the second pass's matches are buffered, never posted as they are found. Only a second pass that ends with
 *   late false and ruleError false sends them, in one {type: "replace", matches} message that takes the place of the
 *   first pass's matches; the file is then clean. A second pass that runs late or hits a rule error is dropped whole:
 *   the parent keeps the first pass's matches. Late: the file is parse_error, exactly as if no repair had been tried.
 *   A rule error: rule_error (a rule that ran on the recovered tree failing on the clean one is a defect to report).
 *   If the hard deadline kills the worker during the second pass, no replace was sent, so the first pass's matches
 *   stay too (the file is time_limit).
 */
export function runJob({ path, local = path, lang, text: source, softMs }, { rules, key, factor = true, prefilter = true, send,
  clock = threadCpuMs, match = matchRoot, contentKey = null }) {
  const started = clock();
  const deadline = started + softMs;
  let root;
  try { root = parseSync(lang, source).root(); } catch {
    return { type: "done", parseError: true, recovered: false, late: false, ruleError: false };
  }
  // A pass sees one parse only: its tree and parsedText, the exact string given to parseSync for that tree (the
  // source, or the repaired text). Anything that slices node text or the gaps between nodes slices parsedText, never
  // the source (contract 2.3 section 3.5). The two have the same length (parse.mjs repairRecovered).
  const pass = ({ root: tree, text: parsedText }, post) => match(tree, path, lang, rules, key, { started, softMs, post,
    text: prefilter ? parsedText : null, clock, factor: factor !== false, contentKey, source: parsedText, local });
  const { late, ruleError } = pass({ root, text: source }, (matches) => send({ type: "found", matches }));
  const rec = late || ruleError ? false : recovered(root);
  const firstPass = clock() - started;
  if (!rec || !hasRepair(lang) || softMs - firstPass < firstPass) {
    return { type: "done", parseError: false, recovered: rec, late, ruleError };
  }
  const asFirst = { type: "done", parseError: false, recovered: true, late: false, ruleError: false };
  let repaired = null;
  // The repair itself is bounded by the same budget: past it, the file stays parse_error (see repairRecovered).
  try { repaired = repairRecovered(lang, source, root, { clock, deadline }); } catch { repaired = null; }
  if (!repaired || repaired.recovered) return asFirst;
  const buffered = [];
  const second = pass(repaired, (matches) => { for (const m of matches) buffered.push(m); });
  // A rule that ran on the recovered tree and fails on the clean one is a rule or engine defect: rule_error (the
  // collector says so), with the first pass's matches kept and nothing of the second pass. Late: parse_error.
  if (second.ruleError) return { ...asFirst, recovered: false, ruleError: true };
  if (second.late) return asFirst;
  send({ type: "replace", matches: buffered });
  return { type: "done", parseError: false, recovered: false, late: false, ruleError: false };
}

if (!isMainThread && workerData?.custosaRules) {
  const { rules, key, factor = true, contentKey = null } = workerData;
  const byId = new Map(rules.map((r) => [r.id, r]));
  const send = (message) => parentPort.postMessage(message);
  parentPort.on("message", ({ path, local, lang, text: raw, ruleIds, softMs }) => {
    send(runJob({ path, local: local ?? path, lang, text: normalizeBreaks(raw), softMs },
      { rules: ruleIds.map((id) => byId.get(id)), key, factor, prefilter: PREFILTER, send, contentKey }));
  });
  parentPort.postMessage({ type: "ready" });
}
