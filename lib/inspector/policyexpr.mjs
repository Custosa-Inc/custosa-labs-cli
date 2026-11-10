/* Row-level security policy expressions, read on the person's machine (contract v2.1, rule_bundle.md section 5).
 *
 * The rls_policies query returns pg_get_expr of each policy's USING (polqual) and WITH CHECK (polwithcheck) to the
 * inspector only. This module parses each into a SQL expression tree (a small hand-written parser for the subset
 * pg_get_expr prints; no dependency) and decides the contract's tri-state fields from the tree, never from a text
 * search. The text is never logged, returned or kept: policyFields returns only true, false and "not_read".
 *
 * policyFields({command, using, check}) -> {owner_comparison, tenant_comparison, requires_aal2, owner_using,
 *   owner_with_check, owner_required, owner_source_untrusted, tenant_using, tenant_with_check, tenant_required,
 *   tenant_source_untrusted}
 *
 * How the relation between a column of the row (an unqualified name, as pg_get_expr prints the policy's own table)
 * and a session value is read (contract v2.1, evaluator_api.md section 1.7, enums.COMPARISON_OPERATORS,
 * NOT_READ_RELATIONS, NON_RESTRICTING_OPERATORS):
 *   - true, a comparison: equality only: `=`, IS NOT DISTINCT FROM (pg_get_expr prints it as NOT (a IS DISTINCT FROM
 *     b)) or `= ANY (ARRAY[v])` with exactly one element. Only lossless casts (LOSSLESS_CASTS, with no length or other
 *     modifier, not an array) are looked through, and a cast of the row's column to an integer type
 *     (LOSSY_INTEGER_TARGETS) only when the column's type, from table_columns, is an integer type (an allowlist: any
 *     other type, an unknown one or a domain counts as lossy). When the database has a cast to one of those types that someone defined, no cast
 *     is looked through (casts "none"), and when that cast is implicit every field is not_read (casts "unread"):
 *     pg_get_expr doesn't print implicit casts, so any = could hide one. The same holds when someone defined an = or <>
 *     operator on those types (pg_get_expr prints IS [NOT] DISTINCT FROM without naming the = it resolves to). Known
 *     limit, in the safe direction: extensions that add such casts or operators (citext, for one) make every policy
 *     field not_read.
 *   - not_read: the row's column related to a session value through anything else that may or may not restrict the
 *     rows: IN or = ANY of a subquery or a set, IN of a list, LIKE, @>, &&, a function or a cast that isn't looked
 *     through around either side, a scalar subquery with a FROM. A subquery with a FROM (and EXISTS) is opaque: when
 *     its text names a session value or calls a function outside pg_catalog, it may relate the row to it, so it is
 *     not_read too. Through a subquery or a set (IN, = ANY, EXISTS) it is not_read for owner and tenant alike: a
 *     membership lookup is the standard tenant pattern. A call to a function whose body isn't read (qualified outside
 *     pg_catalog, other than auth.uid() and auth.jwt()) makes owner and tenant not_read wherever it appears: its body
 *     may read the session, so it is never "no relation".
 *   - false: no relation, or an operator that provably doesn't restrict the rows to it: <>, IS DISTINCT FROM, <, >,
 *     <=, >=, NOT IN.
 * The session values (owner: the session's user; tenant: the session's tenant or organization) and their trust
 * (<x>_source_untrusted, the round 4 ruling):
 *   - trusted (false): TRUSTED_OWNER_SOURCES for the owner: auth.uid(), the JWT's top-level 'sub' (auth.jwt() or
 *     current_setting('request.jwt.claims'), through ->>, ->, #>> or #>), current_setting('request.jwt.claim.sub');
 *     for the tenant, a JWT claim whose final key is in TENANT_KEYS, exactly (JSON keys are case-sensitive), or
 *     TRUSTED_SESSION_SETTINGS (request.jwt.claim.<TENANT_KEY>). A scalar subquery with no FROM around one of these,
 *     (SELECT auth.uid() AS uid), is looked through.
 *   - caller-controlled (true): a JWT path through user_metadata or raw_user_meta_data; the request's headers or
 *     cookies (current_setting('request.headers') or 'request.cookies' with a key, or a request.header.<name> or
 *     request.cookie.<name> setting).
 *   - unknown (not_read): CURRENT_USER, CURRENT_ROLE, SESSION_USER and USER (the database role name); any other
 *     request.jwt.claim.<name>; a custom setting (app.tenant_id); a JWT claim naming the user other than the top-level
 *     sub; a value inside an opaque subquery.
 *   A JSON key or setting names the tenant when its final key is in TENANT_KEYS, the user when it is sub, uid,
 *   user_id, userid or current_user_id.
 *   - required: the comparison is the whole expression or an operand of a top-level AND chain; under OR, NOT, CASE, a
 *     function call or another operator it is not.
 *   - requires_aal2: the JWT's top-level 'aal' compared by equality with the literal 'aal2', required, in every
 *     expression the policy's command is judged by.
 * Anything the parser does not know (a construct, an unbalanced bracket, a dollar quote, an E'' string with escapes,
 * input over the size or depth limits, a user-defined operator in its print form OPERATOR(schema.=)) makes that
 * expression not_read, and every field resting on it not_read. */

export const MAX_EXPRESSION_LENGTH = 65536;
export const MAX_TOKENS = 20000;
export const MAX_DEPTH = 200;

class ParseError extends Error {}
const fail = () => { throw new ParseError("not_read"); };

/* ---------------------------------------------------------------- tokens */

const OP_CHARS = new Set("+-*/<>=~!@#%^&|`?");
const isIdentStart = (c) => /[A-Za-z_\u0080-￿]/.test(c);
const isIdentPart = (c) => /[A-Za-z0-9_$\u0080-￿]/.test(c);

export function tokenize(text) {
  if (typeof text !== "string" || text.length > MAX_EXPRESSION_LENGTH) fail();
  const out = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (/\s/.test(c)) { i++; continue; }
    if (out.length >= MAX_TOKENS) fail();
    if (c === "'" || ((c === "E" || c === "e") && text[i + 1] === "'")) {
      const escaped = c !== "'";
      let j = escaped ? i + 2 : i + 1, v = "";
      for (;;) {
        if (j >= n) fail();
        const d = text[j];
        if (escaped && d === "\\") fail(); // escape sequences change what the key says: not read
        if (d === "'") { if (text[j + 1] === "'") { v += "'"; j += 2; continue; } break; }
        v += d; j++;
      }
      out.push({ t: "str", v });
      i = j + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1, v = "";
      for (;;) {
        if (j >= n) fail();
        if (text[j] === '"') { if (text[j + 1] === '"') { v += '"'; j += 2; continue; } break; }
        v += text[j++];
      }
      if (v === "") fail();
      out.push({ t: "id", v, q: true });
      i = j + 1;
      continue;
    }
    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < n && isIdentPart(text[j])) j++;
      const raw = text.slice(i, j);
      out.push({ t: "id", v: raw.toLowerCase(), q: false });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(text[i + 1] || ""))) {
      const m = /^(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
      if (isIdentStart(text[i + m[0].length] || "")) fail(); // 123abc
      out.push({ t: "num", v: m[0] });
      i += m[0].length;
      continue;
    }
    if (c === ":" && text[i + 1] === ":") { out.push({ t: "p", v: "::" }); i += 2; continue; }
    if ("()[],.".includes(c)) { out.push({ t: "p", v: c }); i++; continue; }
    if (OP_CHARS.has(c)) {
      let j = i;
      while (j < n && OP_CHARS.has(text[j])) j++;
      const op = text.slice(i, j);
      if (op.includes("--") || op.includes("/*") || op === "=>") fail(); // no comments; no named arguments
      out.push({ t: "op", v: op });
      i = j;
      continue;
    }
    fail(); // $ (parameters, dollar quotes), ;, :, \ and anything else
  }
  return out;
}

/* ---------------------------------------------------------------- parser */

// Reserved words that never stand as a bare column name (pg_get_expr quotes a column with such a name).
const RESERVED = new Set(["all", "analyse", "analyze", "and", "any", "array", "as", "asc", "asymmetric", "between",
  "both", "case", "cast", "check", "collate", "column", "constraint", "create", "current_catalog", "current_date",
  "current_role", "current_schema", "current_time", "current_timestamp", "current_user", "default", "deferrable",
  "desc", "distinct", "do", "else", "end", "except", "exists", "false", "fetch", "for", "foreign", "from", "grant",
  "group", "having", "ilike", "in", "initially", "intersect", "into", "is", "isnull", "lateral", "leading", "like",
  "limit", "localtime", "localtimestamp", "not", "notnull", "null", "offset", "on", "only", "or", "order", "placing",
  "primary", "references", "returning", "row", "select", "session_user", "similar", "some", "symmetric", "table",
  "then", "to", "trailing", "true", "union", "unique", "user", "using", "values", "variadic", "when", "where",
  "window", "with"]);
const SESSION_KEYWORDS = new Set(["current_user", "current_role", "session_user", "user", "current_catalog",
  "current_schema", "current_date", "current_time", "current_timestamp", "localtime", "localtimestamp"]);
const COMPARISON_OPS = new Set(["=", "<>", "!=", "<", ">", "<=", ">="]);
// Words that continue a type name after `::` (character varying, double precision, timestamp with time zone...).
const TYPE_CONT = new Set(["varying", "precision", "with", "without", "time", "zone"]);

class Parser {
  constructor(tokens) { this.toks = tokens; this.i = 0; this.depth = 0; }
  peek(k = 0) { return this.toks[this.i + k]; }
  next() { const t = this.toks[this.i++]; if (!t) fail(); return t; }
  isP(v, k = 0) { const t = this.peek(k); return !!t && t.t === "p" && t.v === v; }
  isKw(v, k = 0) { const t = this.peek(k); return !!t && t.t === "id" && !t.q && t.v === v; }
  isOp(v, k = 0) { const t = this.peek(k); return !!t && t.t === "op" && t.v === v; }
  expectP(v) { if (!this.isP(v)) fail(); this.i++; }
  expectKw(v) { if (!this.isKw(v)) fail(); this.i++; }
  enter() { if (++this.depth > MAX_DEPTH) fail(); }
  leave() { this.depth--; }

  parseAll() {
    const e = this.expr();
    if (this.i !== this.toks.length) fail();
    return e;
  }

  expr() { this.enter(); try { return this.or(); } finally { this.leave(); } }

  or() {
    const args = [this.and()];
    while (this.isKw("or")) { this.i++; args.push(this.and()); }
    return args.length === 1 ? args[0] : { t: "or", args };
  }

  and() {
    const args = [this.not()];
    while (this.isKw("and")) { this.i++; args.push(this.not()); }
    return args.length === 1 ? args[0] : { t: "and", args };
  }

  not() {
    if (this.isKw("not")) {
      this.i++;
      this.enter();
      try { return { t: "not", arg: this.not() }; } finally { this.leave(); }
    }
    return this.is();
  }

  is() {
    let e = this.comparison();
    for (;;) {
      if (this.isKw("isnull")) { this.i++; e = { t: "is", arg: e, what: "null", neg: false }; continue; }
      if (this.isKw("notnull")) { this.i++; e = { t: "is", arg: e, what: "null", neg: true }; continue; }
      if (!this.isKw("is")) return e;
      this.i++;
      let neg = false;
      if (this.isKw("not")) { this.i++; neg = true; }
      if (this.isKw("distinct")) {
        this.i++; this.expectKw("from");
        e = { t: "distinct", l: e, r: this.comparison(), neg };
        continue;
      }
      const w = this.next();
      if (!(w.t === "id" && !w.q && ["null", "true", "false", "unknown"].includes(w.v))) fail();
      e = { t: "is", arg: e, what: w.v, neg };
    }
  }

  comparison() {
    let l = this.inLevel();
    const t = this.peek();
    if (t && t.t === "op" && COMPARISON_OPS.has(t.v)) {
      this.i++;
      const quant = this.quantifier();
      if (quant) return { t: "quant", op: t.v, quant, l, r: this.quantArg() };
      const r = this.inLevel();
      l = { t: "op", op: t.v, l, r };
      const t2 = this.peek();
      if (t2 && t2.t === "op" && COMPARISON_OPS.has(t2.v)) fail(); // a = b = c: non-associative in Postgres
    }
    return l;
  }

  quantifier() {
    for (const q of ["any", "some", "all"]) if (this.isKw(q) && this.isP("(", 1)) { this.i++; return q === "some" ? "any" : q; }
    return null;
  }

  quantArg() {
    this.expectP("(");
    if (this.startsSubquery()) return { t: "subquery", scalar: null, toks: this.subqueryTokens() };
    const e = this.expr();
    this.expectP(")");
    return e;
  }

  inLevel() {
    let e = this.other();
    for (;;) {
      let neg = false;
      if (this.isKw("not") && this.isKw("in", 1)) { neg = true; this.i++; }
      if (this.isKw("in")) {
        this.i++;
        this.expectP("(");
        let r;
        if (this.startsSubquery()) r = { t: "subquery", scalar: null, toks: this.subqueryTokens() };
        else {
          const items = [this.expr()];
          while (this.isP(",")) { this.i++; items.push(this.expr()); }
          this.expectP(")");
          r = { t: "list", items };
        }
        e = { t: "in", l: e, r, neg };
        continue;
      }
      if (neg) fail();
      if (["between", "like", "ilike", "similar", "overlaps"].some((k) => this.isKw(k))) fail(); // pg_get_expr prints operators
      return e;
    }
  }

  other() {
    let l = this.additive();
    for (;;) {
      const t = this.peek();
      if (!(t && t.t === "op" && !COMPARISON_OPS.has(t.v) && !["+", "-", "*", "/", "%", "^"].includes(t.v))) return l;
      this.i++;
      const quant = this.quantifier();
      if (quant) { l = { t: "quant", op: t.v, quant, l, r: this.quantArg() }; continue; }
      l = { t: "op", op: t.v, l, r: this.additive() };
    }
  }

  additive() {
    let l = this.multiplicative();
    while (this.isOp("+") || this.isOp("-")) { const op = this.next().v; l = { t: "op", op, l, r: this.multiplicative() }; }
    return l;
  }

  multiplicative() {
    let l = this.power();
    while (this.isOp("*") || this.isOp("/") || this.isOp("%")) { const op = this.next().v; l = { t: "op", op, l, r: this.power() }; }
    return l;
  }

  power() {
    let l = this.unary();
    while (this.isOp("^")) { this.i++; l = { t: "op", op: "^", l, r: this.unary() }; }
    return l;
  }

  unary() {
    const t = this.peek();
    if (t && t.t === "op" && !COMPARISON_OPS.has(t.v)) {
      this.i++;
      this.enter();
      try { return { t: "uop", op: t.v, arg: this.unary() }; } finally { this.leave(); }
    }
    return this.postfix();
  }

  postfix() {
    let e = this.primary();
    for (;;) {
      if (this.isP("::")) { this.i++; e = { t: "cast", arg: e, type: this.typeName() }; continue; }
      if (this.isP("[")) {
        this.i++;
        const idx = this.expr();
        this.expectP("]");
        e = { t: "subscript", arg: e, idx };
        continue;
      }
      if (this.isKw("collate")) {
        this.i++;
        const parts = [this.ident()];
        while (this.isP(".")) { this.i++; parts.push(this.ident()); }
        e = { t: "collate", arg: e };
        continue;
      }
      if (this.isKw("at")) fail(); // AT TIME ZONE
      return e;
    }
  }

  ident() {
    const t = this.next();
    if (t.t !== "id") fail();
    return t.v;
  }

  /* {name, modifier, array}: name with its continuation words ("character varying"), modifier when it has (n). */
  typeName() {
    const parts = [this.ident()];
    while (this.isP(".")) { this.i++; parts.push(this.ident()); }
    const words = [parts.join(".")];
    while (this.peek() && this.peek().t === "id" && !this.peek().q && TYPE_CONT.has(this.peek().v)) words.push(this.next().v);
    let modifier = false, array = false;
    if (this.isP("(")) {
      modifier = true;
      this.i++;
      if (!(this.peek() && this.peek().t === "num")) fail();
      this.i++;
      while (this.isP(",")) { this.i++; if (!(this.peek() && this.peek().t === "num")) fail(); this.i++; }
      this.expectP(")");
    }
    while (this.isP("[")) { this.i++; this.expectP("]"); array = true; }
    return { name: words.join(" "), modifier, array };
  }

  startsSubquery() {
    return ["select", "with", "values", "table"].some((k) => this.isKw(k));
  }

  /* The tokens of a parenthesised subquery, up to its closing parenthesis (consumed). The opening one is consumed. */
  subqueryTokens() {
    const start = this.i;
    let level = 0;
    for (;;) {
      const t = this.next();
      if (t.t === "p" && (t.v === "(" || t.v === "[")) level++;
      else if (t.t === "p" && (t.v === ")" || t.v === "]")) {
        if (level === 0) { if (t.v !== ")") fail(); return this.toks.slice(start, this.i - 1); }
        level--;
      }
    }
  }

  /* (SELECT expr [[AS] alias]) with no FROM or anything else: a scalar wrapper, looked through. Otherwise opaque. */
  subquery() {
    const toks = this.subqueryTokens();
    if (!(toks[0] && toks[0].t === "id" && !toks[0].q && toks[0].v === "select")) return { t: "subquery", scalar: null, toks };
    const p = new Parser(toks);
    p.i = 1;
    p.depth = this.depth;
    try {
      const e = p.expr();
      if (p.isKw("as")) { p.i++; p.ident(); }
      else if (p.peek() && p.peek().t === "id" && (p.peek().q || !RESERVED.has(p.peek().v))) p.i++;
      if (p.i !== toks.length) return { t: "subquery", scalar: null, toks };
      return { t: "subquery", scalar: e };
    } catch (err) {
      if (err instanceof ParseError) return { t: "subquery", scalar: null, toks };
      throw err;
    }
  }

  args() {
    // after "(": a call's arguments
    const args = [];
    if (this.isP(")")) { this.i++; return args; }
    if (this.isOp("*") && this.isP(")", 1)) { this.i += 2; return [{ t: "star" }]; }
    if (this.isKw("distinct") || this.isKw("variadic") || this.isKw("all")) fail();
    for (;;) {
      args.push(this.expr());
      if (this.isP(",")) { this.i++; continue; }
      if (this.isP(")")) { this.i++; return args; }
      fail(); // ORDER BY, named arguments (=>), FROM forms...
    }
  }

  primary() {
    this.enter();
    try { return this.primaryInner(); } finally { this.leave(); }
  }

  primaryInner() {
    const t = this.next();
    if (t.t === "str") return { t: "const", kind: "string", v: t.v };
    if (t.t === "num") return { t: "const", kind: "number", v: t.v };
    if (t.t === "p" && t.v === "(") {
      if (this.startsSubquery()) return this.subquery();
      const first = this.expr();
      if (this.isP(",")) {
        const items = [first];
        while (this.isP(",")) { this.i++; items.push(this.expr()); }
        this.expectP(")");
        return { t: "row", items };
      }
      this.expectP(")");
      return first;
    }
    if (t.t !== "id") fail();
    if (!t.q) {
      if (t.v === "true" || t.v === "false") return { t: "const", kind: "bool", v: t.v === "true" };
      if (t.v === "null") return { t: "const", kind: "null" };
      if (SESSION_KEYWORDS.has(t.v)) {
        if (this.isP("(")) { this.i++; if (this.peek()?.t !== "num") fail(); this.i++; this.expectP(")"); }
        return { t: "kw", v: t.v };
      }
      if (t.v === "case") return this.caseExpr();
      if (t.v === "array") return this.arrayExpr();
      if (t.v === "exists") {
        this.expectP("(");
        if (!this.startsSubquery()) fail();
        return { t: "exists", toks: this.subqueryTokens() };
      }
      if (t.v === "row" && this.isP("(")) { this.i++; const items = this.args(); return { t: "row", items }; }
      if (RESERVED.has(t.v)) fail();
    }
    const parts = [t];
    while (this.isP(".")) {
      this.i++;
      const p = this.next();
      if (p.t !== "id") fail(); // .* and the like
      parts.push(p);
    }
    if (this.isP("(")) {
      this.i++;
      const args = this.args();
      if (this.isKw("filter") || this.isKw("over") || this.isKw("within")) fail();
      return { t: "func", name: parts.map((p) => p.v), quoted: parts.some((p) => p.q), args };
    }
    if (parts.length === 1) return { t: "col", name: t.v, quoted: t.q };
    return { t: "qcol", name: parts.map((p) => p.v) };
  }

  caseExpr() {
    const parts = [];
    if (!this.isKw("when")) parts.push(this.expr());
    if (!this.isKw("when")) fail();
    while (this.isKw("when")) {
      this.i++; parts.push(this.expr());
      this.expectKw("then"); parts.push(this.expr());
    }
    if (this.isKw("else")) { this.i++; parts.push(this.expr()); }
    this.expectKw("end");
    return { t: "case", parts };
  }

  arrayExpr() {
    if (this.isP("(")) {
      this.i++;
      if (!this.startsSubquery()) fail();
      return { t: "array", items: null, toks: this.subqueryTokens() };
    }
    return this.arrayBrackets();
  }

  arrayBrackets() {
    this.expectP("[");
    const items = [];
    if (this.isP("]")) { this.i++; return { t: "array", items }; }
    for (;;) {
      items.push(this.isP("[") ? this.arrayBrackets() : this.expr());
      if (this.isP(",")) { this.i++; continue; }
      this.expectP("]");
      return { t: "array", items };
    }
  }
}

/* The expression tree, or null when it can't be parsed. */
export function parseExpression(text) {
  try {
    const toks = tokenize(text);
    if (toks.length === 0) return null;
    return new Parser(toks).parseAll();
  } catch (err) {
    if (err instanceof ParseError || err instanceof RangeError) return null; // RangeError: a stack overflow
    throw err;
  }
}

/* ---------------------------------------------------------------- session values */

/* The published lists (enums.py, contract v2.1), in the contract's order. */
/* The tenant keys (exact, case-sensitive): a JWT claim, request setting or header is the session's tenant only when its
 * final key is one of these. A tenant-like word elsewhere (org_role, tenant_plan, organizations -> role) is not. */
export const TENANT_KEYS = Object.freeze(["tenant_id", "tenant", "org_id", "organization_id", "organisation_id",
  "account_id", "workspace_id", "team_id", "clinic_id", "practice_id"]);
/* The only trusted owner values. */
export const TRUSTED_OWNER_SOURCES = Object.freeze(["auth.uid()", "auth.jwt() ->> 'sub'",
  "current_setting('request.jwt.claim.sub')", "current_setting('request.jwt.claims') ->> 'sub'"]);
/* The database role name: not known to be the user's identity (owner_source_untrusted not_read). */
export const UNTRUSTED_OWNER_SOURCES = Object.freeze(["CURRENT_USER", "CURRENT_ROLE", "SESSION_USER", "USER"]);
/* The session settings read as a trusted source: the verified JWT's claims, and the per-claim settings PostgREST fills
 * from the same token for sub and for a tenant key. */
export const TRUSTED_SESSION_SETTINGS = Object.freeze(["request.jwt.claims", "request.jwt.claim.sub",
  ...TENANT_KEYS.map((k) => `request.jwt.claim.${k}`)]);
/* Casts looked through: they change no value that could make two different ids equal. A length or other modifier
 * (character(1), varchar(3)), character (always a length), name (cut at 63 bytes) and every other type are not looked
 * through: the relation is not_read. */
export const LOSSLESS_CASTS = Object.freeze(["uuid", "text", "varchar", "character varying", "bpchar", "json", "jsonb",
  "bigint", "integer", "int8", "int4"]);
/* A cast of the row's column to one of these from a column of one of LOSSY_INTEGER_SOURCES can merge rows. */
export const LOSSY_INTEGER_TARGETS = Object.freeze(["bigint", "integer", "int8", "int4"]);
export const LOSSY_INTEGER_SOURCES = Object.freeze(["numeric", "decimal", "real", "double precision", "float4", "float8",
  "text", "varchar", "character varying", "bpchar"]);
export const NON_RESTRICTING_OPERATORS = Object.freeze(["<>", "IS DISTINCT FROM", "<", ">", "<=", ">="]);
/* The column types a cast to an integer type can't merge rows of: integer types only (an allowlist). Any other type,
 * an unrecognised one, a domain or a qualified name, is lossy (LOSSY_INTEGER_SOURCES are only the contract's named
 * examples). */
const INTEGER_COLUMN_TYPES = new Set(["smallint", "integer", "bigint", "int2", "int4", "int8"]);
const UNTRUSTED_KEYS = new Set(["user_metadata", "raw_user_meta_data"]);
const OWNER_SETTING_KEYS = new Set(["sub", "uid", "user_id", "userid", "current_user_id"]);
/* Read from the published lists, so the parser can't drift from them. Keywords are lower case after tokenize. IS
 * DISTINCT FROM is its own node (relationSides), not a binary op; != is Postgres's other spelling of <>. */
const ROLE_KEYWORDS = new Set(UNTRUSTED_OWNER_SOURCES.map((s) => s.toLowerCase()));
const NON_RESTRICTING_OPS = new Set([...NON_RESTRICTING_OPERATORS.filter((op) => op !== "IS DISTINCT FROM"), "!="]);
// Operators that build a value rather than relate two: arithmetic, concatenation, and JSON access.
const VALUE_OPS = new Set(["+", "-", "*", "/", "%", "^", "||", "->", "->>", "#>", "#>>"]);

/* Per call (policyFields' options), set only for the synchronous call: whether casts are looked through (false when
 * the database has a cast to one of LOSSLESS_CASTS that someone defined, which could change the value), and the
 * policy's table columns' types (a Map of column name to data_type from table_columns, or null when not read). */
let lookThroughCasts = true;
let columnTypes = null;

/* A data_type as format_type prints it, reduced to the type name: no modifier, character(n) as bpchar. */
function typeName(dataType) {
  if (typeof dataType !== "string") return null;
  const t = dataType.toLowerCase().replace(/\([^)]*\)/g, "").replace(/\s+/g, " ").trim();
  return t === "character" ? "bpchar" : t;
}

const losslessCast = (n) => n.t === "cast" && lookThroughCasts && !n.type.modifier && !n.type.array
  && LOSSLESS_CASTS.includes(n.type.name);

/* Looks through lossless casts (no modifier, not an array) and scalar (SELECT x) wrappers; COLLATE is not looked
 * through (a nondeterministic collation makes = looser). */
function strip(node) {
  let n = node;
  for (let k = 0; k < MAX_DEPTH && n; k++) {
    if (losslessCast(n)) n = n.arg;
    else if (n.t === "subquery" && n.scalar) n = n.scalar;
    else return n;
  }
  return n;
}

/* The row's column under looked-through casts: "col", "lossy" (cast to an integer type from any type but an integer
 * one: unknown, a domain, numeric, text, json...), or null when it isn't a bare row column. */
function rowColumnOf(node) {
  let n = node;
  const casts = [];
  for (let k = 0; k < MAX_DEPTH && n; k++) {
    if (losslessCast(n)) { casts.push(n.type.name); n = n.arg; }
    else if (n.t === "subquery" && n.scalar) n = n.scalar;
    else break;
  }
  if (!n || n.t !== "col") return null;
  let type = columnTypes && columnTypes.has(n.name) ? typeName(columnTypes.get(n.name)) : null;
  for (let i = casts.length - 1; i >= 0; i--) {
    if (LOSSY_INTEGER_TARGETS.includes(casts[i]) && !INTEGER_COLUMN_TYPES.has(type)) return "lossy";
    type = casts[i];
  }
  return "col";
}

/* The name of the row's column a node is, under the same looked-through casts as rowColumnOf, or null. Local only: it
 * names which column a tenant comparison uses (the observed tenancy), and is never sent as policy text. */
function rowColumnName(node) {
  let n = node;
  for (let k = 0; k < MAX_DEPTH && n; k++) {
    if (losslessCast(n)) n = n.arg;
    else if (n.t === "subquery" && n.scalar) n = n.scalar;
    else break;
  }
  return n && n.t === "col" && typeof n.name === "string" ? n.name : null;
}

/* A literal under a cast to text or text[] ('sub'::text, '{a,b}'::text[]): the cast parses the literal with the
 * type's input function, which no user cast can change. Anything else: the node as it is. */
function literal(node) {
  let n = node;
  for (let k = 0; k < MAX_DEPTH && n && n.t === "cast"; k++) {
    if (n.type.modifier || !["text", "character varying", "varchar", "bpchar", "boolean", "bool"].includes(n.type.name)) return n;
    n = n.arg;
  }
  return n;
}

const lastSegment = (name) => name.slice(name.lastIndexOf(".") + 1);

const isFunc = (n, schema, name) => n && n.t === "func" && !n.quoted && n.name.length === 2
  && n.name[0] === schema && n.name[1] === name;

/* current_setting('<literal>'[, <bool>]), as pg_catalog.current_setting or bare: the setting's name, else null. */
function settingName(n) {
  if (!(n && n.t === "func" && !n.quoted)) return null;
  const ok = (n.name.length === 1 && n.name[0] === "current_setting")
    || (n.name.length === 2 && n.name[0] === "pg_catalog" && n.name[1] === "current_setting");
  if (!ok || n.args.length < 1 || n.args.length > 2) return null;
  const a = literal(n.args[0]);
  if (!(a && a.t === "const" && a.kind === "string")) return null;
  if (n.args.length === 2) { const b = literal(n.args[1]); if (!(b && b.t === "const" && b.kind === "bool")) return null; }
  return a.v.toLowerCase(); // setting names are case-insensitive in Postgres
}

/* A JSON value the session carries, followed along literal keys: {base, path} or null. */
function jsonPath(node) {
  const n = strip(node);
  if (!n) return null;
  if (isFunc(n, "auth", "jwt") && n.args.length === 0) return { base: "jwt", path: [] };
  const s = settingName(n);
  if (s === "request.jwt.claims") return { base: "jwt", path: [] };
  if (s === "request.headers" || s === "request.cookies") return { base: "request", path: [] };
  if (n.t === "op" && ["->", "->>", "#>", "#>>"].includes(n.op)) {
    const inner = jsonPath(n.l);
    if (!inner) return null;
    const k = literal(n.r);
    if (!(k && k.t === "const" && k.kind === "string")) return null;
    let keys;
    if (n.op === "->" || n.op === "->>") keys = [k.v];
    else {
      const m = /^\{([A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*)\}$/.exec(k.v);
      if (!m) return null;
      keys = m[1].split(",");
    }
    return { base: inner.base, path: [...inner.path, ...keys] }; // JSON keys are case-sensitive: 'SUB' is not 'sub'
  }
  return null;
}

/* What a session value is: {kind: "user" | "tenant" | "aal", trust: "trusted" | "untrusted" | "unknown"} or null when
 * it isn't one. untrusted: caller-controlled (<x>_source_untrusted true); unknown: not_read. */
export function sessionValue(node) {
  const n = strip(node);
  if (!n) return null;
  if (isFunc(n, "auth", "uid") && n.args.length === 0) return { kind: "user", trust: "trusted" };
  if (n.t === "kw" && ROLE_KEYWORDS.has(n.v)) return { kind: "user", trust: "unknown" };
  const p = jsonPath(n);
  if (p) {
    if (p.path.length === 0) return null;
    const last = p.path[p.path.length - 1];
    if (p.base === "request") { // the request's headers or cookies: the caller sets them
      if (TENANT_KEYS.includes(last)) return { kind: "tenant", trust: "untrusted" };
      if (OWNER_SETTING_KEYS.has(last)) return { kind: "user", trust: "untrusted" };
      return null;
    }
    const metadata = p.path.some((k) => UNTRUSTED_KEYS.has(k));
    if (p.path.length === 1 && last === "aal") return { kind: "aal", trust: "trusted" };
    if (TENANT_KEYS.includes(last)) return { kind: "tenant", trust: metadata ? "untrusted" : "trusted" };
    if (OWNER_SETTING_KEYS.has(last)) {
      if (metadata) return { kind: "user", trust: "untrusted" };
      return { kind: "user", trust: p.path.length === 1 && last === "sub" ? "trusted" : "unknown" };
    }
    return null;
  }
  const s = settingName(n);
  if (s !== null) {
    const key = lastSegment(s);
    if (s === "request.jwt.claim.aal") return { kind: "aal", trust: "trusted" };
    let kind = TENANT_KEYS.includes(key) ? "tenant" : OWNER_SETTING_KEYS.has(key) ? "user" : null;
    if (kind === null) return null;
    if (/^request\.(header|cookie)\./.test(s)) return { kind, trust: "untrusted" }; // a per-header or per-cookie setting
    if (TRUSTED_SESSION_SETTINGS.includes(s) && (kind === "tenant" || s === "request.jwt.claim.sub")) return { kind, trust: "trusted" };
    return { kind, trust: "unknown" }; // another request.jwt.claim.<name>, a custom setting, an unrecognised name
  }
  return null;
}

const isAal2 = (node) => { const n = literal(node); return !!n && n.t === "const" && n.kind === "string" && n.v === "aal2"; };

/* An equality between a and b: {kind, trust} for a bare row column against a session value, {kind: "aal2"} for the
 * JWT's aal against 'aal2', else null. */
function equality(a, b) {
  for (const [x, y] of [[a, b], [b, a]]) {
    const s = sessionValue(y);
    if (!s) continue;
    if (s.kind === "aal") { if (isAal2(x)) return { kind: "aal2", trust: "trusted" }; continue; }
    if (rowColumnOf(x) === "col") return { ...s, column: rowColumnName(x) };
  }
  return null;
}

/* The comparison a node is, if it is one. */
function comparisonOf(n) {
  if (n.t === "op" && n.op === "=") return equality(n.l, n.r);
  if (n.t === "distinct" && n.neg) return equality(n.l, n.r);
  if (n.t === "not" && n.arg.t === "distinct" && !n.arg.neg) return equality(n.arg.l, n.arg.r);
  if (n.t === "quant" && n.op === "=" && n.quant === "any") {
    const arr = strip(n.r);
    if (arr && arr.t === "array" && Array.isArray(arr.items) && arr.items.length === 1 && arr.items[0].t !== "array") {
      return equality(n.l, arr.items[0]);
    }
  }
  return null;
}

function children(n) {
  switch (n.t) {
    case "or": case "and": return n.args;
    case "not": case "cast": case "collate": case "uop": return [n.arg];
    case "is": return [n.arg];
    case "op": case "distinct": case "quant": case "in": return [n.l, n.r];
    case "subscript": return [n.arg, n.idx];
    case "func": return n.args;
    case "case": return n.parts;
    case "array": return n.items || [];
    case "row": case "list": return n.items;
    case "subquery": return n.scalar ? [n.scalar] : [];
    default: return []; // const, col, qcol, kw, star, exists (opaque)
  }
}

/* The session values an opaque subquery's tokens name, as far as a token scan can tell: auth.uid() (a trusted user);
 * auth.jwt(), current_setting (either kind, trust unknown); the role keywords (a user, trust unknown). */
function scanTokens(toks) {
  const out = [];
  const add = (kind, trust) => { if (!out.some((x) => x.kind === kind && x.trust === trust)) out.push({ kind, trust }); };
  const both = (trust) => { add("user", trust); add("tenant", trust); };
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "id") continue;
    // schema.name( with either part quoted or not ("Private".can_see(...) prints quoted).
    const qualifiedCall = toks[i + 1]?.t === "p" && toks[i + 1].v === "." && toks[i + 2]?.t === "id"
      && toks[i + 3]?.t === "p" && toks[i + 3].v === "(";
    const plain = !t.q && !(qualifiedCall && toks[i + 2].q);
    if (qualifiedCall && plain && t.v === "auth" && toks[i + 2].v === "uid") add("user", "trusted");
    else if (qualifiedCall && plain && t.v === "auth" && toks[i + 2].v === "jwt") both("unknown");
    else if (qualifiedCall && !(plain && t.v === "pg_catalog")) both("unknown"); // a function whose body isn't read
    else if (t.q) continue;
    else if (t.v === "current_setting") both("unknown");
    else if (ROLE_KEYWORDS.has(t.v)) add("user", "unknown");
    // A FROM: the subquery reads a table or view whose body or policies aren't read here (ruling on review item 6).
    else if (t.v === "from") both("unknown");
  }
  return out;
}

/* A session value this module doesn't follow to a key: auth.jwt() or the request.jwt.claims setting ("jwt"), the
 * request.headers or request.cookies setting ("request"), or current_setting of a name that isn't a literal ("jwt"),
 * reached through something other than a literal-key path (json_extract_path_text, #>> with a quoted path, a computed
 * key, ...). On a relation with a row column it is read not_read for owner and tenant (true source for request). */
function sessionBase(n) {
  if (isFunc(n, "auth", "jwt") && n.args.length === 0) return "jwt";
  if (n.t === "func" && !n.quoted && (n.name.length === 1 ? n.name[0] === "current_setting"
    : n.name.length === 2 && n.name[0] === "pg_catalog" && n.name[1] === "current_setting")) {
    const name = settingName(n);
    if (name === null) return "jwt"; // a name that isn't a literal: could be any setting
    if (name === "request.jwt.claims") return "jwt";
    if (name === "request.headers" || name === "request.cookies") return "request";
  }
  return null;
}

/* A call to a function whose body the inspector doesn't read: anything qualified outside pg_catalog other than
 * auth.uid() and auth.jwt() (pg_get_expr qualifies every function outside the pinned search_path, pg_catalog). Its body
 * may read the session, so it never reads as "no relation" (coordinator ruling on review concern 6). */
const opaqueFunction = (n) => n.t === "func" && n.name.length >= 2 && !(n.name.length === 2 && !n.quoted && n.name[0] === "pg_catalog")
  && !(isFunc(n, "auth", "uid") || isFunc(n, "auth", "jwt"));

/* What a subtree may hold: a row column (or an opaque subquery, which may refer to one), and its session values (user
 * and tenant; an opaque subquery's from its tokens). set: it holds a subquery or a set. */
function contents(root) {
  const sessions = [];
  let col = false, set = false, subquery = false;
  const stack = [root];
  let steps = 0;
  while (stack.length) {
    if (++steps > MAX_TOKENS * 4) throw new ParseError("not_read");
    const n = stack.pop();
    if (!n) continue;
    if (n.toks) { col = true; set = true; subquery = true; sessions.push(...scanTokens(n.toks)); continue; }
    if (n.t === "col") { col = true; continue; }
    if (n.t === "array" || n.t === "list") set = true;
    const s = sessionValue(n);
    if (s) { if (s.kind !== "aal") sessions.push(s); continue; }
    if (jsonPath(n)?.path.length) continue; // a claim followed to a literal key naming neither the user nor a tenant
    const base = sessionBase(n);
    if (base) {
      const trust = base === "request" ? "untrusted" : "unknown";
      sessions.push({ kind: "user", trust }, { kind: "tenant", trust });
      continue;
    }
    if (opaqueFunction(n)) sessions.push({ kind: "user", trust: "unknown" }, { kind: "tenant", trust: "unknown" });
    stack.push(...children(n));
  }
  return { col, sessions, set, subquery };
}

/* The two sides a relation construct puts the row's column and a session value on, and whether it restricts:
 * {sides, restricting} or null for a node that relates nothing (AND, OR, a function call, arithmetic, ...). */
function relationSides(n) {
  if (n.t === "op") return VALUE_OPS.has(n.op) ? null : { sides: [n.l, n.r], restricting: !NON_RESTRICTING_OPS.has(n.op) };
  if (n.t === "distinct") return { sides: [n.l, n.r], restricting: n.neg };
  if (n.t === "not" && n.arg.t === "distinct" && !n.arg.neg) return { sides: [n.arg.l, n.arg.r], restricting: true };
  if (n.t === "quant") return { sides: [n.l, n.r], restricting: !NON_RESTRICTING_OPS.has(n.op) };
  if (n.t === "in") return { sides: [n.l, n.r], restricting: !n.neg };
  return null;
}

/* A relation that isn't an equality: [] when the operator provably doesn't restrict the rows (no finding), the
 * session values related to the row's column otherwise (each read not_read), or null when the node relates no row
 * column to a session value (look inside it). positive: the node is reached from the root through AND and OR only;
 * under NOT, CASE, a function or another operator a "non-restricting" operator can restrict (NOT (a <> b)), so there
 * it is not_read too. */
function relationOf(n, positive) {
  if (n.t === "exists") return bothKinds(scanTokens(n.toks));
  const r = relationSides(n);
  if (!r) return null;
  const [a, b] = r.sides.map(contents);
  let related = [...(a.col ? b.sessions : []), ...(b.col ? a.sessions : [])];
  if (related.length === 0) return null;
  // Through a subquery or a set (a membership lookup, IN, = ANY, EXISTS): not_read for owner and tenant alike, since
  // org_id IN (SELECT org_id FROM members WHERE user_id = auth.uid()) is the standard tenant pattern (ruling on concern 7).
  if (n.t === "in" || n.t === "quant" || a.set || b.set) related = bothKinds(related);
  // A subquery relation is never "provably non-restricting": <> ALL (SELECT ...) is NOT IN of a subquery.
  return r.restricting || !positive || a.subquery || b.subquery ? related : [];
}

/* Each session value also as the other kind, with its trust. */
function bothKinds(list) {
  const out = [...list];
  for (const s of list) {
    const other = s.kind === "user" ? "tenant" : "user";
    if (!out.some((x) => x.kind === other && x.trust === s.trust)) out.push({ kind: other, trust: s.trust });
  }
  return out;
}

/* The comparisons an expression tree holds: [{kind, trust, relation: "eq" | "not_read", required}]. */
function findings(root) {
  const out = [];
  const stack = [[root, true, true]];
  let steps = 0;
  while (stack.length) {
    if (++steps > MAX_TOKENS * 4) throw new ParseError("not_read");
    const [n, required, positive] = stack.pop();
    if (!n) continue;
    const cmp = comparisonOf(n);
    if (cmp) { out.push({ ...cmp, relation: "eq", required }); continue; }
    const rel = relationOf(n, positive);
    if (rel) { for (const s of rel) out.push({ ...s, relation: "not_read", required }); continue; }
    if (opaqueFunction(n)) {
      for (const kind of ["user", "tenant"]) out.push({ kind, trust: "unknown", relation: "not_read", required });
      continue;
    }
    if (n.t === "func") { // a built-in function relating a row column in one argument to a session value in another
      const args = n.args.map(contents);
      const related = args.flatMap((a, i) => (args.some((b, j) => j !== i && b.col) ? a.sessions : []));
      if (related.length) { for (const x of related) out.push({ ...x, relation: "not_read", required }); continue; }
    }
    const keep = n.t === "and" ? required : false;
    const stillPositive = positive && (n.t === "and" || n.t === "or");
    for (const c of children(n)) stack.push([c, keep, stillPositive]);
  }
  return out;
}

/* The session functions whose bodies are Supabase's and read no row: auth.uid(), auth.jwt(), auth.role(), auth.email(). */
const SESSION_FUNCTIONS = new Set(["uid", "jwt", "role", "email"]);

/* Whether an expression reads a column of the row: true when one is read outside an opaque subquery;
 * "not_read" when it holds an opaque subquery or EXISTS, or a function whose body isn't read (either may read the
 * row, or be a gate of its own); false otherwise: a bare presence or role test, a constant comparison, true. */
function readsRow(root) {
  let opaque = false;
  const stack = [root];
  let steps = 0;
  while (stack.length) {
    if (++steps > MAX_TOKENS * 4) throw new ParseError("not_read");
    const n = stack.pop();
    if (!n) continue;
    if (n.toks) { opaque = true; continue; }
    if (n.t === "col" || n.t === "qcol") return true;
    if (n.t === "func" && !n.quoted && n.name.length === 2 && n.name[0] === "auth" && SESSION_FUNCTIONS.has(n.name[1])
      && n.args.length === 0) continue;
    if (opaqueFunction(n)) opaque = true;
    stack.push(...children(n));
  }
  return opaque ? "not_read" : false;
}

/* One expression: null (absent: Postgres reads it as true), or its text. {read: false} when it can't be parsed. */
export function analyzeExpression(text) {
  if (text === null || text === undefined) return { read: true, found: [], row: false };
  const tree = parseExpression(text);
  if (!tree) return { read: false };
  try { return { read: true, found: findings(tree), row: readsRow(tree) }; } catch (err) {
    if (err instanceof ParseError) return { read: false };
    throw err;
  }
}

/* ---------------------------------------------------------------- the policy's fields */

const triOr = (a, b) => (a === true || b === true ? true : a === false && b === false ? false : "not_read");
const READS = new Set(["select", "update", "delete", "all"]);
const WRITES = new Set(["insert", "update", "all"]);
export const POLICY_FIELDS = Object.freeze(["owner_comparison", "tenant_comparison", "requires_aal2", "owner_using",
  "owner_with_check", "owner_required", "owner_source_untrusted", "tenant_using", "tenant_with_check", "tenant_required",
  "tenant_source_untrusted", "references_row"]);

/* casts: "lossless" (default) looks through LOSSLESS_CASTS; "none" looks through no cast (a user-defined cast to one
 * of them exists, explicit or assignment); "unread" makes every field not_read (a user-defined implicit cast exists:
 * pg_get_expr doesn't print implicit casts, so any = may hide one, or a user-defined = or <> on those types).
 * columns: the policy's table's columns as a Map of name to data_type (table_columns), or null when they weren't read:
 * a cast of a row column to an integer type is then lossy (not_read). */
export function policyFields({ command, using, check }, { casts = "lossless", columns = null } = {}) {
  const notRead = Object.fromEntries(POLICY_FIELDS.map((f) => [f, "not_read"]));
  if (casts === "unread" || !["lossless", "none"].includes(casts)) {
    // Nothing read, but the command still fixes what the schema requires: no write check for select or delete, no
    // USING for insert.
    if (["select", "delete"].includes(command)) Object.assign(notRead, { owner_with_check: false, tenant_with_check: false });
    if (command === "insert") Object.assign(notRead, { owner_using: false, tenant_using: false });
    return notRead;
  }
  lookThroughCasts = casts === "lossless";
  columnTypes = columns instanceof Map ? columns : null;
  try { return decide(command, using, check, notRead); } finally { lookThroughCasts = true; columnTypes = null; }
}

function decide(command, using, check, notRead) {
  if (!READS.has(command) && !WRITES.has(command)) return notRead;
  if (!(using === null || using === undefined || typeof using === "string")) return notRead;
  if (!(check === null || check === undefined || typeof check === "string")) return notRead;
  const u = analyzeExpression(using);
  // The check of written rows: WITH CHECK, or USING for an update or all policy declaring none.
  const hasCheck = check !== null && check !== undefined;
  const w = hasCheck ? analyzeExpression(check) : command === "insert" ? analyzeExpression(null) : u;
  const scope = [];
  if (READS.has(command)) scope.push(u);
  if (WRITES.has(command)) scope.push(w);

  // In one expression: true for an equality, not_read for a relation that may or may not restrict, else false.
  const has = (a, kind) => {
    if (!a.read) return "not_read";
    const mine = a.found.filter((f) => f.kind === kind);
    return mine.some((f) => f.relation === "eq") ? true : mine.length ? "not_read" : false;
  };
  const out = {};
  for (const [x, kind] of [["owner", "user"], ["tenant", "tenant"]]) {
    const inUsing = READS.has(command) ? has(u, kind) : false;
    const inCheck = WRITES.has(command) ? has(w, kind) : false;
    const comparison = triOr(inUsing, inCheck);
    let required, untrusted;
    if (comparison === false) { required = false; untrusted = false; }
    else if (scope.some((a) => !a.read)) { required = "not_read"; untrusted = "not_read"; }
    else {
      // Every expression the command is judged by must require it (an equality on the top-level AND path): one with
      // no comparison at all (USING true beside an owner WITH CHECK) lets every row through, so it is not required
      //. A relation read not_read leaves it not_read unless a required equality settles it.
      const holders = scope.map((a) => a.found.filter((f) => f.kind === kind));
      const each = holders.map((m) => (m.some((f) => f.relation === "eq" && f.required) ? true
        : m.some((f) => f.relation === "not_read") ? "not_read" : false));
      required = each.includes(false) ? false : each.includes("not_read") ? "not_read" : true;
      const all = holders.flat();
      untrusted = all.some((f) => f.trust === "untrusted") ? true : all.some((f) => f.trust === "unknown") ? "not_read" : false;
    }
    Object.assign(out, {
      [`${x}_comparison`]: comparison, [`${x}_using`]: inUsing, [`${x}_with_check`]: inCheck,
      [`${x}_required`]: required, [`${x}_source_untrusted`]: untrusted,
    });
  }
  // requires_aal2: every expression the command is judged by requires the JWT's aal to equal 'aal2'.
  if (scope.some((a) => a.read && !a.found.some((f) => f.kind === "aal2" && f.required))) out.requires_aal2 = false;
  else if (scope.some((a) => !a.read)) out.requires_aal2 = "not_read";
  else out.requires_aal2 = scope.length > 0;
  // references_row: false when a judged expression reads no row column, which lets every row through as
  // true does; not_read when one isn't read, or may read the row only through a gate this module doesn't follow.
  if (scope.some((a) => a.read && a.row === false)) out.references_row = false;
  else if (scope.some((a) => !a.read || a.row !== true)) out.references_row = "not_read";
  else out.references_row = true;
  const result = Object.fromEntries(POLICY_FIELDS.map((f) => [f, out[f]]));
  // The row columns the tenant equalities in the judged expressions use (non-enumerable: never part of the row).
  const tenantColumns = out.tenant_comparison === true && !scope.some((a) => !a.read)
    ? [...new Set(scope.flatMap((a) => a.found.filter((f) => f.kind === "tenant" && f.relation === "eq").map((f) => f.column)))]
    : [];
  Object.defineProperty(result, "tenantColumns", { value: tenantColumns, enumerable: false });
  // The one row column every judged expression requires equal to the session's user from a trusted source, or null
  // (T29-P1-C35: the owner column a fix can scope rows by). Any other user relation in a judged expression (a second
  // column, a not_read relation, an untrusted or unknown source) leaves it null. Non-enumerable, like tenantColumns:
  // catalogfacts sends the name as schema metadata only, in the form table_columns sends it.
  const users = scope.every((a) => a.read) ? scope.flatMap((a) => a.found.filter((f) => f.kind === "user")) : [];
  const ownerNames = [...new Set(users.map((f) => f.column))];
  const ownerColumn = out.owner_required === true && out.owner_source_untrusted === false && users.length > 0
    && users.every((f) => f.relation === "eq" && f.trust === "trusted" && typeof f.column === "string")
    && ownerNames.length === 1 ? ownerNames[0] : null;
  Object.defineProperty(result, "ownerColumn", { value: ownerColumn, enumerable: false });
  return result;
}

/* ---------------------------------------------------------------- T29 h4b: the scope of each OR branch */

/* The words for one top-level OR branch of USING (T29-P3-C215). The evaluator reads them: a branch every caller meets
 * (signed_in, any_member, none) opens every row; owner and member_row tie the row to the caller; member names the
 * caller but not the row (a staff list); row reads the row but not the caller; not_read when this module can't say. */
export const BRANCH_KINDS = Object.freeze(["owner", "member_row", "member", "any_member", "signed_in", "row", "none", "not_read"]);
export const MAX_BRANCHES = 8;

/* Whether a subquery's tokens name the session user: auth.uid(), auth.jwt(), current_setting(...) or a role keyword. */
function tokensNameCaller(toks) {
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "id" || t.q) continue;
    if (t.v === "auth" && toks[i + 1]?.v === "." && ["uid", "jwt"].includes(toks[i + 2]?.v)) return true;
    if (t.v === "current_setting" || ROLE_KEYWORDS.has(t.v)) return true;
  }
  return false;
}

/* Whether a subquery's tokens reach the policy's row: a column qualified by the policy's table name (pg_get_expr
 * prints an outer reference as table.column). */
function tokensTieRow(toks, table) {
  for (let i = 0; i + 2 < toks.length; i++) {
    const t = toks[i];
    if (t.t === "id" && t.v === table && toks[i + 1]?.t === "p" && toks[i + 1].v === "." && toks[i + 2]?.t === "id") return true;
  }
  return false;
}

/* Words that a "(" may follow in a subquery without a function call. */
const NOT_CALLS = new Set(["select", "where", "and", "or", "not", "in", "exists", "from", "on", "join", "any", "all",
  "some", "array", "case", "when", "then", "else", "as", "is", "by", "having", "values", "using", "distinct", "union",
  "except", "intersect", "lateral", "with"]);

/* Whether a subquery's tokens call a function: one this module doesn't read may name the session user
 * (public.current_user_id()), so a membership that calls one and names no caller is not_read, never any_member. */
function tokensCall(toks) {
  for (let i = 0; i + 1 < toks.length; i++) {
    const t = toks[i], n = toks[i + 1];
    if (t.t === "id" && (t.q || !NOT_CALLS.has(t.v)) && n.t === "p" && n.v === "(") return true;
  }
  return false;
}

/* Whether a node holds a session value outside any subquery. */
function namesCaller(root) {
  const stack = [root];
  let steps = 0;
  while (stack.length) {
    if (++steps > MAX_TOKENS * 4) throw new ParseError("not_read");
    const n = stack.pop();
    if (!n) continue;
    if (n.toks) continue;
    if (sessionValue(n) || isSessionCall(n)) return true;
    stack.push(...children(n));
  }
  return false;
}

/* auth.uid(), auth.jwt(), auth.role(), auth.email(), or current_setting(...) of any name: a value of the session. */
const isSessionCall = (n) => n.t === "func" && !n.quoted && ((n.name.length === 2 && n.name[0] === "auth"
  && SESSION_FUNCTIONS.has(n.name[1])) || (n.name.length === 1 && n.name[0] === "current_setting"));

/* Whether a node calls any function outside a subquery (a value this module may not follow). */
function callsAny(root) {
  const stack = [root];
  while (stack.length) {
    const n = stack.pop();
    if (!n || n.toks) continue;
    if (n.t === "func") return true;
    stack.push(...children(n));
  }
  return false;
}

function branchKind(b, table) {
  if (b.t === "exists") {
    const caller = tokensNameCaller(b.toks), tie = tokensTieRow(b.toks, table);
    if (!caller && tokensCall(b.toks)) return "not_read"; // a function it doesn't read may name the caller
    return caller && tie ? "member_row" : caller ? "member" : tie ? "any_member" : "not_read";
  }
  const found = findings(b);
  if (found.some((f) => f.kind === "user" && f.relation === "eq" && f.required)) return "owner";
  const row = readsRow(b);
  if (row === false) return namesCaller(b) ? "signed_in" : "none"; // no row column: every caller who meets it, any row
  if (row === "not_read" || found.length) return "not_read";
  return namesCaller(b) || callsAny(b) ? "not_read" : "row"; // a session value it doesn't follow (app.current_user)
}

/* usingBranches(text, table) -> one BRANCH_KINDS word per top-level OR branch of the USING text (["none"] for no USING,
 * which reads as true), or null when it doesn't parse or has more than MAX_BRANCHES branches. table: the policy's
 * table name, unqualified, as pg_get_expr prints outer references. */
export function usingBranches(text, table, { casts = "lossless", columns = null } = {}) {
  if (text === null || text === undefined) return ["none"];
  if (!["lossless", "none"].includes(casts)) return null; // "unread": a user-defined implicit cast may hide anywhere
  const tree = parseExpression(text);
  if (!tree) return null;
  const flat = (n) => (n.t === "or" ? n.args.flatMap(flat) : [n]);
  lookThroughCasts = casts === "lossless";
  columnTypes = columns instanceof Map ? columns : null;
  try {
    const branches = flat(tree);
    if (branches.length > MAX_BRANCHES) return null;
    return branches.map((b) => branchKind(b, table));
  } catch (err) {
    if (err instanceof ParseError) return null;
    throw err;
  } finally { lookThroughCasts = true; columnTypes = null; }
}
