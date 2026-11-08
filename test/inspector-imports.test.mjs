/* The import scan. Specifiers in JS, TS and Python source are normalised to
 * their package name and mapped through the manifest SDK tables into files.fingerprints, and files.imports keeps each
 * fingerprint's package and first path and line, as evidence ("openai imported at src/ai.ts:2"). Presence only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { importsIn, PACKAGE_PATTERN, packageOf, pythonPackageOf, scanImports } from "../lib/inspector/imports.mjs";
import { FINGERPRINTS } from "../lib/inspector/frameworks.mjs";
import { FACT_SCHEMA } from "../lib/inspector/schema.mjs";

const pkgs = (text, lang = "typescript") => importsIn(text, lang).filter((h) => h.fingerprints.length).map((h) => h.package); // SDK imports (the framework list adds framework-only hits)

test("the package pattern and fingerprint enum are the contract's", () => {
  const item = FACT_SCHEMA.properties.files.properties.imports.items;
  assert.equal(PACKAGE_PATTERN, item.properties.package.pattern);
  assert.deepEqual(FINGERPRINTS, item.properties.fingerprint.enum);
  assert.equal(FACT_SCHEMA.properties.files.properties.imports.maxItems, FINGERPRINTS.length);
});

test("specifiers are normalised to their package name", () => {
  const cases = [
    ["openai", "openai"], ["openai/resources/chat", "openai"], ["next/server", "next"], ["firebase/app", "firebase"],
    ["@anthropic-ai/sdk", "@anthropic-ai/sdk"], ["@a/b/c", "@a/b"], ["npm:openai@4.20.0", "openai"],
    ["npm:@anthropic-ai/sdk@0.20/x", "@anthropic-ai/sdk"], ["npm:/openai", "openai"], ["jsr:@supabase/supabase-js@2", "@supabase/supabase-js"],
    ["https://esm.sh/openai@4.0.0", "openai"], ["https://esm.sh/v135/@supabase/supabase-js@2?target=deno", "@supabase/supabase-js"],
    ["https://cdn.jsdelivr.net/npm/@sentry/browser@8/+esm", "@sentry/browser"],
    ["./ai", null], ["../lib/openai", null], ["/abs/openai", null], ["#internal", null], ["node:fs", null],
    ["https://example.com/openai.js", null], ["https://deno.land/std/http/server.ts", null], ["@scope", null], ["a b", null],
  ];
  for (const [spec, want] of cases) assert.equal(packageOf(spec), want, spec);
});

test("a Python module is read as its shortest dotted prefix the table knows", () => {
  const cases = [
    ["openai", "openai"], ["anthropic.types", "anthropic"], ["firebase_admin", "firebase-admin"],
    ["google.cloud.firestore", "google-cloud-firestore"], ["google.cloud.storage", "google-cloud-storage"],
    ["google.generativeai", "google-generativeai"], ["langchain.chat_models", "langchain"], ["langchain_openai", "langchain-openai"],
    ["llama_index.core", "llama-index"], ["sentry_sdk", "sentry-sdk"], ["boto3", "boto3"],
    ["google.cloud.pubsub", null], ["os.path", null], ["supabase", null],
  ];
  for (const [mod, want] of cases) assert.equal(pythonPackageOf(mod), want, mod);
});

test("every JS and TS import form, and nothing in a comment", () => {
  const ts = [
    'import OpenAI from "openai";',
    "import {",
    "  S3Client,",
    "  type PutObjectCommand,",
    "} from '@aws-sdk/client-s3';",
    'import type { Message } from "@anthropic-ai/sdk";',
    'import * as Sentry from "@sentry/nextjs";',
    'import "@sentry/browser";',
    'export { initializeApp } from "firebase/app";',
    'export * from "pusher-js";',
    'const ably = require("ably");',
    "const blob = await import(`@vercel/blob`);",
    'const { Capacitor } = await import("@capacitor/core", { with: {} });',
    "// import { x } from 'ai';",
    "/* const r = require('replicate');",
    "   import Groq from 'groq-sdk'; */",
    'const url = "https://example.com/x"; import Cohere from "cohere-ai";',
    'const path = `${base}/openai`; require(`${name}`);',
    "foo.import('ollama'); x.require('ws');",
    'import { helper } from "./openai";',
  ].join("\n");
  assert.deepEqual(pkgs(ts), ["openai", "@aws-sdk/client-s3", "@anthropic-ai/sdk", "@sentry/nextjs", "@sentry/browser", "firebase",
    "pusher-js", "ably", "@vercel/blob", "@capacitor/core", "cohere-ai"]);
  const hits = importsIn(ts, "typescript");
  assert.deepEqual(hits.find((h) => h.package === "firebase").fingerprints, ["firebase_sdk"]);
  assert.deepEqual(hits.find((h) => h.package === "@capacitor/core").fingerprints, ["mobile_hybrid"]);
  // Deno edge functions.
  assert.deepEqual(pkgs('import OpenAI from "npm:openai@4";\nimport { createClient } from "jsr:@supabase/supabase-js@2";\nimport Anthropic from "https://esm.sh/@anthropic-ai/sdk@0.20";\n'),
    ["openai", "@anthropic-ai/sdk"]);
  // JS and TSX read the same way.
  assert.deepEqual(pkgs('const OpenAI = require("openai")\n', "javascript"), ["openai"]);
  // The offset is the statement's keyword, not the character before it or the specifier's line.
  assert.deepEqual(importsIn("x;\nimport {\n  a,\n} from 'openai';\n", "typescript")[0].offset, 3);
  assert.deepEqual(pkgs('import { Analytics } from "@vercel/analytics/react";\nimport * as S from "@sentry/react";\nexport default () => <div/>;\n', "tsx"), ["@sentry/react"]);
});

test("every Python import form, and nothing in a comment or docstring", () => {
  const py = [
    '"""Uses openai.',
    "import anthropic",
    '"""',
    "import os, openai as oa, sys",
    "from google.cloud import firestore",
    "from firebase_admin import credentials",
    "from .openai import helper",
    "# import boto3",
    "def f():",
    "    import sentry_sdk",
    "    mod = importlib.import_module('replicate')",
    "x = 'import ollama'",
  ].join("\n");
  assert.deepEqual(pkgs(py, "python"), ["openai", "google-cloud-firestore", "firebase-admin", "sentry-sdk", "replicate"]);
  // from-import names count when the module alone isn't in the table, and the line is the statement's.
  assert.deepEqual(pkgs("from google import genai\nfrom google.cloud import (pubsub, storage as gcs)\n", "python"), ["google-genai", "google-cloud-storage"]);
  assert.deepEqual(importsIn("x = 1\nfrom google.cloud import firestore\n", "python")[0].offset, 6);
  const fs = importsIn("from google.cloud.firestore import Client\n", "python");
  assert.deepEqual(fs.map((h) => [h.package, h.fingerprints]), [["google-cloud-firestore", ["firebase_sdk"]]]);
});

function repo(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "imp-repo-")));
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(join(root, p, ".."), { recursive: true });
    writeFileSync(join(root, p), t);
  }
  return root;
}
const LANG = { ts: "typescript", tsx: "tsx", js: "javascript", py: "python", md: null, go: "go" };
const walked = (files) => Object.keys(files).map((p) => ({ disk: p, path: p, lang: LANG[p.split(".").pop()] ?? null }));

test("one entry per fingerprint, from the first file in path order and its first line there", async () => {
  const files = {
    "src/ai.ts": "// the model\nimport OpenAI from 'openai';\nimport Anthropic from '@anthropic-ai/sdk';\n",
    "a/early.py": "import os\n\nimport anthropic\n",
    "src/z.ts": "import * as Sentry from '@sentry/node';\r\nimport { App } from '@capacitor/app';\n",
    "README.md": "import OpenAI from 'openai'\n", // not source
    "main.go": 'import "github.com/sashabaranov/go-openai"\n', // the scan reads JS, TS and Python only
  };
  const r = await scanImports(repo(files), walked(files));
  assert.deepEqual(r.imports, [
    { fingerprint: "ai_sdk", package: "anthropic", path: "a/early.py", line: 3 },
    { fingerprint: "error_tracking_sdk", package: "@sentry/node", path: "src/z.ts", line: 1 },
    { fingerprint: "mobile_hybrid", package: "@capacitor/app", path: "src/z.ts", line: 2 },
  ]);
  assert.deepEqual([...r.seen].sort(), ["ai_sdk", "error_tracking_sdk", "mobile_hybrid"]);
});

test("a file it can't read is skipped, and a scan past its time stops with what it has", async () => {
  const files = { "a.ts": "import OpenAI from 'openai';\n", "b.ts": "import * as S from '@sentry/node';\n" };
  const root = repo(files);
  const list = [...walked(files), { disk: "gone.ts", path: "gone.ts", lang: "typescript" }];
  assert.deepEqual((await scanImports(root, list)).imports.map((i) => i.fingerprint), ["ai_sdk", "error_tracking_sdk"]);
  assert.deepEqual((await scanImports(root, list, { until: Date.now() - 1 })).imports, []);
});

// the import scan gives vector_store_sdk through the same tables, JS, TS and Python.
test("a vector-store import gives vector_store_sdk with its first path and line", async () => {
  assert.equal(pythonPackageOf("qdrant_client.models"), "qdrant-client");
  assert.equal(pythonPackageOf("pinecone"), "pinecone");
  assert.equal(pythonPackageOf("faiss"), "faiss");
  assert.equal(pythonPackageOf("langchain_pinecone"), "langchain-pinecone");
  const files = {
    "src/rag.ts": "import { z } from 'zod';\nimport { Pinecone } from '@pinecone-database/pinecone';\n",
    "worker/search.py": "import os\nfrom qdrant_client import QdrantClient\n",
  };
  const r = await scanImports(repo(files), walked(files));
  assert.deepEqual(r.imports, [{ fingerprint: "vector_store_sdk", package: "@pinecone-database/pinecone", path: "src/rag.ts", line: 2 }]);
  assert.deepEqual([...r.seen], ["vector_store_sdk"]);
});

// store modules inside an AI framework package. The longest prefix decides for these (a LangChain or
// LlamaIndex vector-store module is vector_store_sdk as well as the framework's ai_sdk), and the Python weaviate module
// is the weaviate-client package.
test("store modules of LangChain, LlamaIndex and Weaviate give vector_store_sdk by their longest prefix", async () => {
  const pkgs = (text, lang) => importsIn(text, lang).map((h) => [h.package, h.fingerprints]);
  assert.deepEqual(pkgs("import weaviate\n", "python"), [["weaviate-client", ["vector_store_sdk"]]]);
  assert.deepEqual(pkgs("from weaviate.classes.query import Filter\n", "python"), [["weaviate-client", ["vector_store_sdk"]]]);
  assert.deepEqual(pkgs("from llama_index.vector_stores.pinecone import PineconeVectorStore\n", "python"),
    [["llama-index", ["ai_sdk"]], ["llama-index-vector-stores-pinecone", ["ai_sdk", "vector_store_sdk"]]]);
  assert.deepEqual(pkgs("from langchain_community.vectorstores import PGVector\n", "python"),
    [["langchain-community", ["ai_sdk"]], ["langchain-community", ["vector_store_sdk"]]]);
  assert.deepEqual(pkgs("import { PineconeStore } from '@langchain/community/vectorstores/pinecone';\n", "typescript"),
    [["@langchain/community", ["ai_sdk"]], ["@langchain/community", ["vector_store_sdk"]]]);
  // the framework's other modules are not a store
  assert.deepEqual(pkgs("from langchain_community.chat_models import ChatOllama\nfrom llama_index.core import VectorStoreIndex\n", "python"),
    [["langchain-community", ["ai_sdk"]], ["llama-index", ["ai_sdk"]]]);
  assert.deepEqual(pkgs("import { ChatOpenAI } from '@langchain/community/chat_models/openai';\n", "javascript"),
    [["@langchain/community", ["ai_sdk"]]]);
  const files = {
    "src/rag.ts": "import { z } from 'zod';\nimport { PGVectorStore } from '@langchain/community/vectorstores/pgvector';\n",
    "worker/search.py": "import os\nimport weaviate\n",
  };
  const r = await scanImports(repo(files), walked(files));
  assert.deepEqual(r.imports, [
    { fingerprint: "ai_sdk", package: "@langchain/community", path: "src/rag.ts", line: 2 },
    { fingerprint: "vector_store_sdk", package: "@langchain/community", path: "src/rag.ts", line: 2 },
  ]);
});
