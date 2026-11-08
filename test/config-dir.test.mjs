/* every part of the CLI picks the same config folder: CUSTOSA_CONFIG_DIR when it is set and not empty, else
   ~/.config/custosa. Setup writes the sign-in and the environment mark there, and the inspector, doctor and the
   platform token read them back, so one rule that drifted would lose them. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { configDir as setupConfigDir } from "../lib/setup.mjs";
import { configDir as platformConfigDir } from "../lib/inspector/platform.mjs";
import { configDirFor } from "../lib/inspector/secrets.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { runDoctor } from "../lib/doctor.mjs";

const TOKEN = `phisc_${"a".repeat(43)}`;
const EVALUATOR = "http://127.0.0.1:9";
const DEFAULT = join(homedir(), ".config", "custosa");

/* runs `body` with process.env.CUSTOSA_CONFIG_DIR set to `value` (undefined unsets it), then puts it back */
function withEnv(value, body) {
  const before = process.env.CUSTOSA_CONFIG_DIR;
  if (value === undefined) delete process.env.CUSTOSA_CONFIG_DIR; else process.env.CUSTOSA_CONFIG_DIR = value;
  try { return body(); } finally {
    if (before === undefined) delete process.env.CUSTOSA_CONFIG_DIR; else process.env.CUSTOSA_CONFIG_DIR = before;
  }
}

test("config folder: setup reads its context's env and home", () => {
  const home = "/home/someone";
  assert.equal(setupConfigDir({ env: {}, home }), join(home, ".config", "custosa"));
  assert.equal(setupConfigDir({ env: { CUSTOSA_CONFIG_DIR: "/elsewhere" }, home }), "/elsewhere");
  assert.equal(setupConfigDir({ env: { CUSTOSA_CONFIG_DIR: "" }, home }), join(home, ".config", "custosa"));
  assert.equal(setupConfigDir({ env: { CUSTOSA_CONFIG_DIR: "relative" }, home }), "relative");
});

test("config folder: the platform token reads the env it is given, else this process's, under the real home", () => {
  assert.equal(platformConfigDir({}), DEFAULT);
  assert.equal(platformConfigDir({ CUSTOSA_CONFIG_DIR: "/elsewhere" }), "/elsewhere");
  assert.equal(platformConfigDir({ CUSTOSA_CONFIG_DIR: "" }), DEFAULT);
  assert.equal(withEnv("/from-process", () => platformConfigDir()), "/from-process");
  assert.equal(withEnv(undefined, () => platformConfigDir()), DEFAULT);
});

test("config folder: the inspector takes a folder it is given, else this process's env, under the real home", () => {
  assert.equal(withEnv("/from-process", () => configDirFor({ configDir: "/given" })), "/given");
  assert.equal(withEnv("/from-process", () => configDirFor({ configDir: "" })), "/from-process");
  assert.equal(withEnv("/from-process", () => configDirFor({})), "/from-process");
  assert.equal(withEnv("/from-process", () => configDirFor()), "/from-process");
  assert.equal(withEnv("", () => configDirFor()), DEFAULT);
  assert.equal(withEnv(undefined, () => configDirFor()), DEFAULT);
});

/* doctor's Sign-in line, with the token saved in `saved` and doctor given `env` and `home` */
async function signIn({ home, saved, env }) {
  if (saved) writeToken(TOKEN, { configDir: saved, host: EVALUATOR });
  const lines = [];
  await runDoctor({ env: { CUSTOSA_EVALUATOR_URL: EVALUATOR, PGSERVICEFILE: "/nonexistent", npm_config_cache: join(home, ".npm"), ...env },
    home, out: (l) => lines.push(l), offline: true, which: () => null, run: () => ({ status: 1, stdout: "" }) });
  return lines.find((l) => /^\w+ +Sign-in:/.test(l));
}

test("config folder: doctor looks in the home it is given, or in CUSTOSA_CONFIG_DIR", async () => {
  const home = mkdtempSync(join(tmpdir(), "custosa-config-dir-"));
  const own = join(home, ".config", "custosa");
  const other = join(home, "other");
  mkdirSync(own, { recursive: true });
  mkdirSync(other, { recursive: true });
  assert.match(await signIn({ home, saved: null, env: {} }), /^FAIL  Sign-in: not signed in/);
  assert.match(await signIn({ home, saved: own, env: {} }), /^PASS  Sign-in: a token is saved for http:\/\/127\.0\.0\.1:9/);
  assert.match(await signIn({ home, saved: null, env: { CUSTOSA_CONFIG_DIR: "" } }), /^PASS  Sign-in/);
  assert.match(await signIn({ home, saved: null, env: { CUSTOSA_CONFIG_DIR: other } }), /^FAIL  Sign-in: not signed in/);
  assert.match(await signIn({ home, saved: other, env: { CUSTOSA_CONFIG_DIR: other } }), /^PASS  Sign-in/);
});
