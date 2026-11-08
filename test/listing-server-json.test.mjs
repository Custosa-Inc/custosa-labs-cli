/* The MCP Registry listing: server.json, beside package.json, describes this npm package as a local stdio
 * server, named com.custosa/phi-schema-check.
 *
 * Who it serves: the registry checks ownership of an npm entry by reading `mcpName` from the published package.json,
 * and clients start the server from the entry's package and arguments. So the name, the package, its version and the
 * command must match this package exactly, or the publish is refused or the listing starts the wrong thing. The
 * description is the one line every directory shows, so it holds to the product's wording rules. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { INSPECT } from "../lib/clients.mjs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const server = JSON.parse(readFileSync(new URL("../server.json", import.meta.url), "utf8"));

test("server.json names this package: mcpName, identifier and version match package.json", () => {
  assert.equal(server.name, "com.custosa/phi-schema-check");
  assert.equal(pkg.mcpName, server.name, "the registry reads mcpName from the published package.json");
  assert.equal(server.version, pkg.version);
  assert.equal(server.packages.length, 1);
  const [p] = server.packages;
  assert.equal(p.registryType, "npm");
  assert.equal(p.identifier, pkg.name);
  assert.equal(p.version, pkg.version);
  assert.deepEqual(p.transport, { type: "stdio" });
  assert.equal(server.remotes, undefined, "the hosted server is gone; the listing is the local package only");
});

test("server.json points at the public CLI repository, at its root", () => {
  assert.deepEqual(
    { url: server.repository.url, source: server.repository.source, subfolder: server.repository.subfolder },
    { url: "https://github.com/Custosa-Inc/custosa-labs-cli", source: "github", subfolder: undefined },
  );
});

test("server.json starts the server the way setup registers it (npx custosa inspect --stdio)", () => {
  const [p] = server.packages;
  assert.equal(p.runtimeHint, INSPECT[0]);
  const args = p.packageArguments.map((a) => (a.type === "named" ? a.name : a.value));
  assert.deepEqual(args, INSPECT.slice(3));
});

test("the listing text keeps the wording rules: at most 100 characters, no compliance claim, no free, no em dash", () => {
  assert.ok(server.description.length <= 100, `${server.description.length} characters`);
  assert.ok(server.title.length <= 100);
  for (const text of [server.title, server.description]) {
    assert.doesNotMatch(text, /HIPAA|complian|certif|\bfree\b|\u2014/i, text);
  }
  assert.match(server.title, /^PHI Schema Check$/);
});
