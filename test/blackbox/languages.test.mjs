// Unsupported languages are counted as not analysed, never as clean; every supported-looking file is either matched
// by the rule that fits it or listed as not analysed.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  tmpdir, rmrf, initRepo, inspectDocument, assertValid, assertNoChildProcess, assertNoNetwork, assertBounded, assertHonest,
  assertPathsInsideRoot,
} from './harness.mjs';

const JS = 'import express from "express";\nconst app = express();\napp.post("/x", (req, res) => {\n  console.log(req.body.ssn);\n  res.json({});\n});\nexport default app;\n';
const TS = 'import express, { Request, Response } from "express";\nconst app = express();\napp.post("/x", (req: Request, res: Response) => {\n  console.log(req.body.ssn);\n  res.json({});\n});\nexport default app;\n';

// Each file here holds patient-data handling a supported rule would flag if it were analysed.
const UNSUPPORTED = {
  'cs/PatientController.cs': 'public class PatientController { public void Post(Patient p) { _logger.LogInformation(p.Ssn); } }\n',
  'rs/main.rs': 'fn main() { let ssn = req.body.ssn; println!("{}", ssn); }\n',
  'swift/App.swift': 'func save(p: Patient) { print(p.ssn) }\n',
  'scala/App.scala': 'object App { def save(p: Patient) = println(p.ssn) }\n',
  'ex/app.ex': 'defmodule App do\n def save(p), do: IO.puts(p.ssn)\nend\n',
  'dart/app.dart': 'void save(Patient p) { print(p.ssn); }\n',
  'c/app.c': 'void save(struct patient *p) { printf("%s", p->ssn); }\n',
  'cpp/app.cpp': 'void save(Patient p) { std::cout << p.ssn; }\n',
  'lua/app.lua': 'function save(p) print(p.ssn) end\n',
  'db/schema.sql': 'CREATE TABLE patients (id serial primary key, ssn text);\nGRANT ALL ON patients TO PUBLIC;\n',
  'infra/main.tf': 'resource "aws_db_instance" "db" { storage_encrypted = false }\n',
  'infra/settings.hcl': 'storage_encrypted = false\n',
  'config/app.toml': '[db]\nssl = false\n',
  'web/App.vue': `<script setup>\nconsole.log(patient.ssn)\n</script>\n<template><div/></template>\n`,
  'web/Page.svelte': '<script>\nconsole.log(patient.ssn)\n</script>\n',
  'views/show.erb': '<%= @patient.ssn %>\n',
  'Dockerfile': 'FROM node:20\n',
  'bin/run': '#!/usr/bin/env python3\nprint(patient["ssn"])\n',
};

const JS_LIKE = {
  'jsv/a.js': JS, 'jsv/a.mjs': JS, 'jsv/a.cjs': JS, 'jsv/a.jsx': JS,
  'tsv/a.ts': TS, 'tsv/a.mts': TS, 'tsv/a.cts': TS, 'tsv/a.tsx': TS,
};

let base; let root; let home; let r; let doc;

before(async () => {
  base = tmpdir('lang');
  root = path.join(base, 'repo');
  home = path.join(base, 'home');
  fs.mkdirSync(home);
  initRepo(root, { 'package.json': '{"dependencies":{"express":"4.19.2"}}', ...UNSUPPORTED, ...JS_LIKE });
  r = await inspectDocument(root, { home });
  doc = r.doc;
});
after(() => rmrf(base));

describe('languages', () => {
  it('produces a valid, bounded document with no child process or network', () => {
    assert.equal(r.code, 0, r.stderr.slice(-1500));
    assertValid(doc);
    assertBounded(r);
    assertHonest(doc);
    assertNoChildProcess(r.events);
    assertNoNetwork(r.events);
    assertPathsInsideRoot(doc, root);
  });

  for (const rel of Object.keys(UNSUPPORTED)) {
    it(`an unsupported file is listed as not analysed: ${rel}`, () => {
      const e = doc.files.not_analyzed.find((x) => x.path === rel);
      assert.ok(e, `${rel} is not in files.not_analyzed: it was counted as analysed (clean)`);
      assert.ok(['unsupported_language', 'unknown_type'].includes(e.reason), `${rel} reason ${e.reason}`);
    });
  }

  it('claims no language it has no grammar for', () => {
    for (const lang of ['csharp', 'sql', 'hcl', 'toml']) {
      assert.ok(!doc.files.languages.includes(lang), `files.languages claims ${lang}, which this package cannot parse`);
    }
  });

  for (const rel of Object.keys(JS_LIKE)) {
    it(`a JavaScript or TypeScript variant is matched or listed, never silently clean: ${rel}`, () => {
      const matched = doc.matches.some((m) => m.path === rel && m.practice_id === 'no-phi-in-app-logs');
      const listed = doc.files.not_analyzed.some((x) => x.path === rel);
      assert.ok(matched || listed, `${rel}: no match for the logged ssn and not listed as not analysed`);
    });
  }

  it('files.analyzed counts only files that are not listed as not analysed', () => {
    const total = Object.keys(UNSUPPORTED).length + Object.keys(JS_LIKE).length + 1; // + package.json
    const listed = doc.files.not_analyzed.filter((x) => x.kind === 'file').length;
    assert.ok(doc.files.analyzed + listed <= total, `analysed ${doc.files.analyzed} + listed ${listed} exceeds the ${total} files`);
  });
});
