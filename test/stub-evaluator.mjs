/* A local stub evaluator for the inspector tests (client, sign-in, tool): an HTTP server on 127.0.0.1 with a handler per
 * test. It records every request. Never a real service. */
import { createServer } from "node:http";

export const EVALUATE_OK = Object.freeze({
  goal: "check", status: "in_progress", session: "ps_abcdefghijklmnopqrstuv", ruleset_id: "2026-10-20.0123abcd",
  registry_id: "2026-10-20.89abcdef", headline: "Readiness score: 3 findings.", is_fetch_only: false, charged_units: 0,
  next_step: "Answer the questions.", notice: "", correlation_id: "corr_12345678",
});

/* A stub evaluator: `handler(req, body)` -> {status, json, headers}. Records every request. */
export async function stub(handler) {
  const calls = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const call = { method: req.method, url: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : null };
      calls.push(call);
      const out = handler(call, calls.length) ?? { status: 500, json: { error: "internal_error", next_step: "x", correlation_id: "corr_12345678" } };
      res.writeHead(out.status, { "content-type": "application/json", ...(out.headers ?? {}) });
      res.end(out.raw ?? JSON.stringify(out.json));
    });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { url, calls, close: () => new Promise((ok) => server.close(ok)) };
}

