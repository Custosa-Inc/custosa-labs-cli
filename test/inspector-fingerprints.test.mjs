/* The SDK and manifest fingerprint (files.fingerprints). Presence comes from a declared dependency or a
 * marker file. The list is null (sent absent) when any manifest couldn't be read, so silence never reads as absence.
 * The frameworks list is unchanged by the new manifests. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectFrameworks, FINGERPRINTS } from "../lib/inspector/frameworks.mjs";
import { FACT_SCHEMA } from "../lib/inspector/schema.mjs";

function repo(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "fp-repo-")));
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(join(root, p, ".."), { recursive: true });
    writeFileSync(join(root, p), t);
  }
  return { root, walk: { files: Object.keys(files).map((path) => ({ path })), notAnalyzed: [] } };
}
async function detect(files, notAnalyzed) {
  const { root, walk } = repo(files);
  if (notAnalyzed) walk.notAnalyzed = notAnalyzed;
  return detectFrameworks(root, walk);
}
const npm = (deps) => JSON.stringify({ dependencies: deps });

test("the enum is the contract's", () => {
  assert.deepEqual(FINGERPRINTS, FACT_SCHEMA.properties.files.properties.fingerprints.items.enum);
});

test("no declared SDK gives an empty list, not null", async () => {
  const r = await detect({ "package.json": npm({ next: "14", "@supabase/supabase-js": "2" }), "app/page.tsx": "x\n" });
  assert.deepEqual(r.fingerprints, []);
  assert.deepEqual(r.frameworks, ["nextjs", "supabase"]);
});

test("npm dependencies", async () => {
  const cases = [
    [{ openai: "4" }, ["ai_sdk"]], [{ "@anthropic-ai/sdk": "1" }, ["ai_sdk"]], [{ ai: "3" }, ["ai_sdk"]],
    [{ "@ai-sdk/openai": "1" }, ["ai_sdk"]], [{ "@langchain/core": "0.3" }, ["ai_sdk"]], [{ langchain: "0.3" }, ["ai_sdk"]],
    [{ "@google/generative-ai": "1" }, ["ai_sdk"]], [{ "@aws-sdk/client-bedrock-runtime": "3" }, ["ai_sdk"]],
    [{ "@aws-sdk/client-s3": "3" }, ["object_storage_sdk"]], [{ "@google-cloud/storage": "7" }, ["object_storage_sdk"]],
    [{ "@azure/storage-blob": "12" }, ["object_storage_sdk"]], [{ "@vercel/blob": "1" }, ["object_storage_sdk"]],
    [{ "aws-sdk": "2" }, ["object_storage_sdk"]],
    [{ "socket.io": "4" }, ["realtime_sdk"]], [{ "pusher-js": "8" }, ["realtime_sdk"]], [{ ably: "2" }, ["realtime_sdk"]],
    [{ "@sentry/nextjs": "8" }, ["error_tracking_sdk"]], [{ "@bugsnag/js": "7" }, ["error_tracking_sdk"]],
    [{ "@datadog/browser-rum": "5" }, ["error_tracking_sdk"]], [{ logrocket: "8" }, ["error_tracking_sdk"]],
    [{ firebase: "10" }, ["firebase_sdk"]], [{ "@react-native-firebase/crashlytics": "20" }, ["error_tracking_sdk", "firebase_sdk"]],
    [{ "@supabase/supabase-js": "2" }, []], // supabase-js carries realtime, but it is not a realtime SDK of its own
    [{ "openai-ish": "1" }, []],
  ];
  for (const [deps, want] of cases) assert.deepEqual((await detect({ "package.json": npm(deps) })).fingerprints, want, JSON.stringify(deps));
  // devDependencies and nested packages count too.
  const r = await detect({ "package.json": npm({}), "apps/web/package.json": JSON.stringify({ devDependencies: { "@sentry/node": "8" } }) });
  assert.deepEqual(r.fingerprints, ["error_tracking_sdk"]);
});

test("Python, Ruby, Go, JVM, .NET and PHP dependencies", async () => {
  const cases = [
    [{ "requirements.txt": "anthropic==0.40\nboto3\n" }, ["ai_sdk", "object_storage_sdk"]],
    [{ "pyproject.toml": '[project]\ndependencies = ["langchain-openai", "sentry-sdk[fastapi]"]\n' }, ["ai_sdk", "error_tracking_sdk"]],
    [{ "requirements.txt": "python-socketio\ngoogle-cloud-storage\n" }, ["object_storage_sdk", "realtime_sdk"]],
    [{ Gemfile: 'gem "ruby-openai"\ngem "aws-sdk-s3"\ngem "sentry-ruby"\n' }, ["ai_sdk", "error_tracking_sdk", "object_storage_sdk"]],
    [{ "go.mod": "module x\nrequire (\n\tgithub.com/sashabaranov/go-openai v1\n\tgithub.com/getsentry/sentry-go v0.1\n)\n" }, ["ai_sdk", "error_tracking_sdk"]],
    [{ "go.mod": "module x\nrequire github.com/aws/aws-sdk-go-v2/service/s3 v1\n" }, ["object_storage_sdk"]],
    [{ "pom.xml": "<groupId>dev.langchain4j</groupId><groupId>software.amazon.awssdk</groupId><artifactId>s3</artifactId>" }, ["ai_sdk", "object_storage_sdk"]],
    [{ "App.csproj": '<PackageReference Include="Azure.AI.OpenAI" /><PackageReference Include="Sentry.AspNetCore" />' }, ["ai_sdk", "error_tracking_sdk"]],
    [{ "composer.json": JSON.stringify({ require: { "openai-php/client": "1", "pusher/pusher-php-server": "7" } }) }, ["ai_sdk", "realtime_sdk"]],
  ];
  for (const [files, want] of cases) assert.deepEqual((await detect(files)).fingerprints, want, JSON.stringify(files));
});

test("native mobile apps from their manifests and marker files", async () => {
  const cases = [
    [{ "android/app/src/main/AndroidManifest.xml": "<manifest/>\n" }, ["android"]],
    [{ "android/app/build.gradle": "apply plugin: 'com.android.application'\napply plugin: 'com.google.gms.google-services'\n" }, ["android", "firebase_sdk"]],
    [{ "android/app/google-services.json": "{}" }, ["firebase_sdk"]],
    [{ "ios/Runner/Info.plist": "<plist/>\n" }, ["ios"]],
    [{ "ios/App.xcodeproj/project.pbxproj": "x\n" }, ["ios"]],
    [{ "ios/Runner/GoogleService-Info.plist": "<plist/>\n" }, ["firebase_sdk", "ios"]],
    [{ "ios/Podfile": "platform :ios, '15.0'\npod 'FirebaseCrashlytics'\npod 'Sentry'\n" }, ["error_tracking_sdk", "firebase_sdk", "ios"]],
    [{ "pubspec.yaml": "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  firebase_core: ^2.0.0\n  supabase_flutter: ^2.0.0\n" }, ["firebase_sdk", "flutter"]],
    [{ "pubspec.yaml": "name: lib\ndependencies:\n  http: ^1.0.0\n" }, []], // a plain Dart package is not a Flutter app
    [{ "pubspec.yaml": "name: app\ndependencies:\n    flutter:\n        sdk: flutter\n    # a comment\n    cloud_firestore: ^5.0.0\n" }, ["firebase_sdk", "flutter"]], // any indent
    [{ "pubspec.yaml": "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  sentry_flutter: ^8.0.0\n  google_generative_ai: ^0.4.0\n" }, ["ai_sdk", "error_tracking_sdk", "flutter"]],
  ];
  for (const [files, want] of cases) assert.deepEqual((await detect(files)).fingerprints, want, JSON.stringify(files));
});

// Firestore server libraries, the Firebase rules and config files,
// Gradle version catalogs and SwiftPM. Presence only: the frameworks never change, and these facts never close an item.
test("Firestore server libraries in every ecosystem give firebase_sdk", async () => {
  const cases = [
    { "package.json": npm({ "@google-cloud/firestore": "7" }) },
    { "requirements.txt": "google-cloud-firestore==2.16\n" },
    { "pyproject.toml": '[project]\ndependencies = ["google_cloud_firestore"]\n' },
    { Gemfile: 'gem "google-cloud-firestore"\n' },
    { "go.mod": "module x\nrequire cloud.google.com/go/firestore v1.15.0\n" },
    { "pom.xml": "<groupId>com.google.cloud</groupId><artifactId>google-cloud-firestore</artifactId>" },
    { "build.gradle.kts": 'implementation("com.google.cloud:google-cloud-firestore:3.20.0")' },
    { "composer.json": JSON.stringify({ require: { "google/cloud-firestore": "1" } }) },
  ];
  for (const files of cases) {
    const r = await detect(files);
    assert.deepEqual(r.fingerprints, ["firebase_sdk"], JSON.stringify(files));
    assert.ok(!r.frameworks.includes("firebase"), "a fingerprint, not a framework");
  }
  // Other Google Cloud libraries are not Firestore.
  assert.deepEqual((await detect({ "go.mod": "module x\nrequire cloud.google.com/go/pubsub v1\n" })).fingerprints, []);
  assert.deepEqual((await detect({ "package.json": npm({ "@google-cloud/pubsub": "4" }) })).fingerprints, []);
});

test("the Firebase rules and config files are markers", async () => {
  for (const marker of ["firestore.rules", "storage.rules", ".firebaserc", "database.rules.json", "firestore.indexes.json"]) {
    for (const path of [marker, `firebase/${marker}`]) {
      assert.deepEqual((await detect({ [path]: "x\n" })).fingerprints, ["firebase_sdk"], path);
      // A marker the walk skipped still counts: presence is enough.
      assert.deepEqual((await detect({ "a.ts": "x\n" }, [{ path, kind: "file", reason: "unknown_type" }])).fingerprints, ["firebase_sdk"], path);
    }
  }
  assert.deepEqual((await detect({ "my-firestore.rules.bak": "x\n", "rules/storage.rules.md": "x\n" })).fingerprints, []);
});

test("a Gradle version catalog is read through the JVM table, for the fingerprint only", async () => {
  const catalog = [
    "[versions]", 'agp = "8.5.0"', "",
    "[libraries]", 'firebase-bom = { module = "com.google.firebase:firebase-bom", version = "33.1.0" }',
    'sentry = { group = "io.sentry", name = "sentry-android", version = "7.0.0" }', "",
    "[plugins]", 'android-application = { id = "com.android.application", version.ref = "agp" }',
    'google-services = { id = "com.google.gms.google-services", version = "4.4.2" }', "",
  ].join("\n");
  let r = await detect({ "gradle/libs.versions.toml": catalog, "app/build.gradle.kts": "plugins { alias(libs.plugins.android.application) }\n" });
  assert.deepEqual(r.fingerprints, ["android", "error_tracking_sdk", "firebase_sdk"]);
  assert.deepEqual(r.frameworks, []);
  r = await detect({ "gradle/libs.versions.toml": '[libraries]\nfirebase-firestore = { module = "dev.gitlive:firebase-firestore", version = "2.1.0" }\n' });
  assert.deepEqual(r.fingerprints, ["firebase_sdk"]);
  r = await detect({ "gradle/libs.versions.toml": '[libraries]\nfs = { group = "com.google.cloud", name = "google-cloud-firestore", version = "3.20.0" }\n' });
  assert.deepEqual(r.fingerprints, ["firebase_sdk"]);
  // A catalog in a subproject's gradle folder counts; a TOML file elsewhere is not a catalog.
  assert.deepEqual((await detect({ "mobile/gradle/libs.versions.toml": '[plugins]\na = { id = "com.android.application" }\n' })).fingerprints, ["android"]);
  assert.deepEqual((await detect({ "config/libs.versions.toml": '[plugins]\na = { id = "com.android.application" }\n' })).fingerprints, []);
  // Spring in a catalog doesn't add a framework: the catalog is read for the fingerprint only.
  r = await detect({ "gradle/libs.versions.toml": '[libraries]\nweb = { module = "org.springframework.boot:spring-boot-starter-web" }\n' });
  assert.deepEqual([r.frameworks, r.fingerprints], [[], []]);
});

test("SwiftPM: Package.swift and Package.resolved give ios, and firebase-ios-sdk gives firebase_sdk", async () => {
  const swift = 'let package = Package(name: "App", dependencies: [\n  .package(url: "https://github.com/firebase/firebase-ios-sdk", from: "10.0.0"),\n])\n';
  assert.deepEqual((await detect({ "Package.swift": swift })).fingerprints, ["firebase_sdk", "ios"]);
  const resolved = JSON.stringify({ pins: [{ identity: "firebase-ios-sdk", location: "https://github.com/firebase/firebase-ios-sdk.git" }], version: 2 });
  assert.deepEqual((await detect({ "App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved": resolved })).fingerprints, ["firebase_sdk", "ios"]);
  assert.deepEqual((await detect({ "Package.swift": 'let package = Package(name: "Lib")\n' })).fingerprints, ["ios"]);
});

test("a Gradle catalog or SwiftPM file the walk didn't keep leaves the fingerprint unknown, not the frameworks", async () => {
  for (const path of ["gradle/libs.versions.toml", "Package.resolved"]) {
    const r = await detect({ "a.ts": "x\n" }, [{ path, kind: "file", reason: "too_large" }]);
    assert.equal(r.fingerprints, null, path);
    assert.deepEqual(r.frameworks, [], path);
  }
});

test("silence is never absence: an unreadable or broken manifest makes the fingerprint unknown", async () => {
  // A package.json that doesn't parse: frameworks and fingerprints both unknown, as before.
  let r = await detect({ "package.json": "{bad", "a.ts": "x\n" });
  assert.equal(r.fingerprints, null);
  assert.equal(r.frameworks, null);
  // A manifest the walk listed but didn't keep.
  r = await detect({ "a.ts": "x\n" }, [{ path: "pubspec.yaml", kind: "file", reason: "too_large" }]);
  assert.equal(r.fingerprints, null);
  assert.deepEqual(r.frameworks, []); // pubspec.yaml is not a frameworks manifest: frameworks stand
  // A Podfile or pubspec.yaml that can't be read: only the fingerprint is unknown, and the problem is listed.
  const { root, walk } = repo({ "a.ts": "x\n" });
  walk.files.push({ path: "ios/Podfile" });
  r = await detectFrameworks(root, walk);
  assert.equal(r.fingerprints, null);
  assert.deepEqual(r.frameworks, []);
  assert.deepEqual(r.problems.map((p) => p.path), ["ios/Podfile"]);
  // A skipped directory that could hold a manifest: unknown.
  r = await detect({ "a.ts": "x\n" }, [{ path: "android", kind: "directory", reason: "time_limit" }]);
  assert.equal(r.fingerprints, null);
});

test("the same input gives the same output, sorted in enum order", async () => {
  const files = { "package.json": npm({ "@sentry/node": "8", openai: "4", "socket.io": "4", firebase: "10", "@vercel/blob": "1" }),
    "ios/Info.plist": "x", "android/AndroidManifest.xml": "x" };
  const a = (await detect(files)).fingerprints, b = (await detect(files)).fingerprints;
  assert.deepEqual(a, b);
  assert.deepEqual(a, FINGERPRINTS.filter((f) => a.includes(f)));
  assert.deepEqual(a, ["ai_sdk", "android", "error_tracking_sdk", "firebase_sdk", "ios", "object_storage_sdk", "realtime_sdk"]);
});

// the frameworks each manifest kind names, and what a manifest that doesn't parse does to them.
test("frameworks from every manifest kind; a broken or skipped manifest leaves them unknown", async () => {
  const cases = [
    [{ "package.json": JSON.stringify({ dependencies: { express: "4", "@prisma/client": "5" }, devDependencies: { "@remix-run/node": "2" },
      peerDependencies: { "react-native": "0" }, optionalDependencies: { nuxt3: "3" } }) }, ["express", "remix", "nuxt", "prisma", "react_native"]],
    [{ "requirements.txt": "Django==5\nFlask\nSQLAlchemy\n" }, ["django", "flask", "sqlalchemy"]],
    [{ "pyproject.toml": '[project]\ndependencies = ["fastapi", "alembic", "supabase", "firebase_admin"]\n' }, ["fastapi", "alembic", "supabase", "firebase"]],
    [{ Gemfile: "gem 'railties'\n" }, ["rails"]],
    [{ "composer.json": JSON.stringify({ "require-dev": { "laravel/framework": "11" } }) }, ["laravel"]],
    [{ "go.mod": "module x\nrequire (\n\tgithub.com/gin-gonic/gin v1\n\tgithub.com/labstack/echo/v4 v4\n)\n" }, ["gin", "echo"]],
    [{ "build.gradle.kts": 'implementation("org.springframework.boot:spring-boot-starter-web")' }, ["spring"]],
    [{ "Api.CSPROJ": '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>' }, ["aspnetcore"]],
    [{ "package.json": "[1, 2]", "go.mod": "module x\n" }, []],
    [{ "main.tf": "", ".github/workflows/ci.yml": "", "supabase/config.toml": "", "firebase.json": "{}" }, ["supabase", "firebase", "terraform", "github_actions"]],
  ];
  for (const [files, want] of cases) assert.deepEqual((await detect(files)).frameworks, want, JSON.stringify(files));
  const broken = await detect({ "composer.json": "{", "main.tf": "" });
  assert.deepEqual([broken.frameworks, broken.fromPaths, broken.problems], [null, ["terraform"], [{ path: "composer.json", reason: "parse_error" }]]);
  const listed = await detect({ "main.tf": "" }, [{ path: "big/pom.xml", kind: "file", reason: "too_large", tracked: null }]);
  assert.deepEqual([listed.frameworks, listed.fromPaths, listed.problems], [null, ["terraform"], []]);
});

// a word in a Python manifest's comment, or in pyproject.toml's description or keywords, is no dependency. A
// framework found there would enable that framework's rules and count the language as covered (_kit.covered), so a
// Starlette app whose requirements say "moved off flask" could be judged by Flask rules that see none of its routes.
test("Python manifests: comments and pyproject metadata name no framework or SDK", async () => {
  const cases = [
    [{ "requirements.txt": "starlette==0.37\n# moved off flask in 2024\nuvicorn  # replaces the django dev server\n" }, [], []],
    [{ "requirements.txt": "flask==3.0  # the web app\n-e git+https://github.com/x/y.git#egg=sentry-sdk\n" }, ["flask"], ["error_tracking_sdk"]],
    [{ "pyproject.toml": '[project]\nname = "notes-api"\ndescription = "A Starlette port of our old Django app, with OpenAI"\nkeywords = ["flask", "fastapi"]\ndependencies = ["starlette"]\n' }, [], []],
    [{ "pyproject.toml": '[project]\nname = "x"\ndependencies = ["fastapi>=0.110", "openai"]\n\n[project.optional-dependencies]\nadmin = ["django"]\n' }, ["django", "fastapi"], ["ai_sdk"]],
    [{ "pyproject.toml": '[tool.poetry]\nname = "flask-notes"\ndescription = "Not flask"\n\n[tool.poetry.dependencies]\npython = "^3.11"\nfastapi = "*"\n\n[tool.poetry.group.dev.dependencies]\nsentry-sdk = "*"\n' }, ["fastapi"], ["error_tracking_sdk"]],
    // A pyproject.toml the strict reader refuses is read as text, as before (comments still dropped).
    [{ "pyproject.toml": '[project]\ndependencies = ["flask"]\ndependencies = ["dup"]\n# django\n' }, ["flask"], []],
    [{ "setup.py": 'from setuptools import setup\n# a port of a django app\nsetup(install_requires=["fastapi"])\n' }, ["fastapi"], []],
    // setup.cfg's [metadata] section and setup.py's descriptive arguments name no dependency either.
    [{ "setup.cfg": "[metadata]\nname = flask-notes\ndescription = A Django port\nkeywords = flask, openai\n\n[options]\ninstall_requires =\n    fastapi\n    sentry-sdk\n" }, ["fastapi"], ["error_tracking_sdk"]],
    [{ "setup.py": 'setup(\n    name="flask-notes",\n    description=\'A Django port, with OpenAI\',\n    keywords=["flask", "django"],\n    classifiers=["Framework :: Django"],\n    install_requires=["fastapi", "openai"],\n)\n' }, ["fastapi"], ["ai_sdk"]],
  ];
  for (const [files, frameworks, fingerprints] of cases) {
    const r = await detect(files);
    assert.deepEqual(r.frameworks, frameworks, JSON.stringify(files));
    assert.deepEqual(r.fingerprints, fingerprints, JSON.stringify(files));
  }
});

// hybrid and cross-platform apps. mobile_hybrid contradicts a no_mobile_client claim; it never closes
// an item.
test("Capacitor, Cordova, Ionic, NativeScript, .NET MAUI and Kotlin Multiplatform give mobile_hybrid", async () => {
  const cases = [
    { "package.json": npm({ "@capacitor/core": "6", "@capacitor/ios": "6" }) },
    { "package.json": npm({ cordova: "12" }) },
    { "package.json": npm({ "cordova-plugin-camera": "7" }) },
    { "package.json": npm({ "@ionic/angular": "8" }) },
    { "package.json": npm({ "@nativescript/core": "8" }) },
    { "App.csproj": '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><UseMaui>true</UseMaui></PropertyGroup></Project>' },
    { "App.csproj": '<PackageReference Include="Microsoft.Maui.Controls" Version="8.0.0" />' },
    { "shared/build.gradle.kts": 'plugins {\n  kotlin("multiplatform")\n}\n' },
    { "build.gradle": "plugins { id 'org.jetbrains.kotlin.multiplatform' version '2.0.0' }\n" },
    { "gradle/libs.versions.toml": '[plugins]\nkotlinMultiplatform = { id = "org.jetbrains.kotlin.multiplatform", version = "2.0.0" }\n' },
  ];
  for (const files of cases) {
    const r = await detect(files);
    assert.deepEqual(r.fingerprints, ["mobile_hybrid"], JSON.stringify(files));
    assert.deepEqual(r.frameworks, [], JSON.stringify(files));
  }
  // Near names are not hybrid apps.
  for (const deps of [{ capacitor: "1" }, { "ionicons": "7" }, { "@ionic-native-mock/x": "1" }, { nativescript: "8" }]) {
    assert.deepEqual((await detect({ "package.json": npm(deps) })).fingerprints, [], JSON.stringify(deps));
  }
  assert.deepEqual((await detect({ "App.csproj": "<UseMaui>false</UseMaui>" })).fingerprints, []);
  assert.deepEqual((await detect({ "build.gradle.kts": 'plugins { kotlin("jvm") }\n' })).fingerprints, []);
});

// vector-store clients. vector_store_sdk is evidence for the contradiction check on rag-retrieval-scoped;
// it never closes an item. A LangChain store package is also an AI SDK.
test("vector-store clients in every ecosystem give vector_store_sdk", async () => {
  const cases = [
    [{ "package.json": npm({ "@pinecone-database/pinecone": "5" }) }, ["vector_store_sdk"]],
    [{ "package.json": npm({ "weaviate-client": "3", "@qdrant/js-client-rest": "1", chromadb: "1" }) }, ["vector_store_sdk"]],
    [{ "package.json": npm({ "@zilliz/milvus2-sdk-node": "2", pgvector: "0.2", "@upstash/vector": "1" }) }, ["vector_store_sdk"]],
    [{ "package.json": npm({ "@lancedb/lancedb": "0.10", "@turbopuffer/turbopuffer": "0.5", "@datastax/astra-db-ts": "1" }) }, ["vector_store_sdk"]],
    [{ "package.json": npm({ "@langchain/pinecone": "0.1" }) }, ["ai_sdk", "vector_store_sdk"]],
    [{ "package.json": npm({ "@llamaindex/qdrant": "0.1" }) }, ["vector_store_sdk"]],
    [{ "requirements.txt": "pinecone\nqdrant-client\nchromadb\npymilvus\n" }, ["vector_store_sdk"]],
    [{ "requirements.txt": "pgvector\nvecs\nfaiss-cpu\nlancedb\nupstash-vector\nredisvl\nastrapy\n" }, ["vector_store_sdk"]],
    [{ "requirements.txt": "langchain-postgres\n" }, ["ai_sdk", "vector_store_sdk"]],
    [{ "requirements.txt": "llama-index-vector-stores-pinecone\n" }, ["ai_sdk", "vector_store_sdk"]],
    [{ Gemfile: 'gem "neighbor"\ngem "pgvector"\n' }, ["vector_store_sdk"]],
    [{ Gemfile: 'gem "qdrant-ruby"\n' }, ["vector_store_sdk"]],
    [{ "composer.json": JSON.stringify({ require: { "probots-io/pinecone-php": "1", "pgvector/pgvector": "0.2" } }) }, ["vector_store_sdk"]],
    [{ "go.mod": "module x\nrequire (\n\tgithub.com/pinecone-io/go-pinecone v1\n\tgithub.com/pgvector/pgvector-go v0.2\n)\n" }, ["vector_store_sdk"]],
    [{ "go.mod": "module x\nrequire github.com/qdrant/go-client v1\n" }, ["vector_store_sdk"]],
    [{ "pom.xml": "<groupId>io.pinecone</groupId><artifactId>pinecone-client</artifactId>" }, ["vector_store_sdk"]],
    [{ "build.gradle": "implementation 'com.pgvector:pgvector:0.1.6'\n" }, ["vector_store_sdk"]],
    [{ "pom.xml": "<groupId>org.springframework.ai</groupId><artifactId>spring-ai-pgvector-store</artifactId>" }, ["ai_sdk", "vector_store_sdk"]],
    [{ "pom.xml": "<groupId>dev.langchain4j</groupId><artifactId>langchain4j-qdrant</artifactId>" }, ["ai_sdk", "vector_store_sdk"]],
    [{ "App.csproj": '<PackageReference Include="Qdrant.Client" /><PackageReference Include="Pgvector" />' }, ["vector_store_sdk"]],
  ];
  for (const [files, want] of cases) assert.deepEqual((await detect(files)).fingerprints, want, JSON.stringify(files));
  // Near names and the plain Postgres drivers are not vector stores.
  for (const deps of [{ pinecone: "1" }, { pg: "8" }, { "pg-vector-tile": "1" }, { "@langchain/core": "0.3" }]) {
    assert.equal((await detect({ "package.json": npm(deps) })).fingerprints.includes("vector_store_sdk"), false, JSON.stringify(deps));
  }
  for (const req of ["psycopg\n", "sqlalchemy\n", "langchain-openai\n", "elasticsearch\n"]) {
    assert.equal((await detect({ "requirements.txt": req })).fingerprints.includes("vector_store_sdk"), false, req);
  }
});

// every requirements file manifests.mjs counts as pip is read for frameworks and fingerprints, not only
// a top-level requirements*.txt. Lockfiles are not read (they name no framework the manifest doesn't).
test("Python requirements in requirements/, requirements.d/, .in files and dev- or test-requirements are read", async () => {
  const cases = [
    [{ "requirements/base.txt": "Django==5\n", "requirements/production.txt": "-r base.txt\n" }, ["django"]],
    [{ "requirements.d/web.txt": "flask\n" }, ["flask"]],
    [{ "requirements.in": "fastapi\n" }, ["fastapi"]],
    [{ "dev-requirements.txt": "sqlalchemy\n" }, ["sqlalchemy"]],
    [{ "test-requirements.txt": "alembic\n" }, ["alembic"]],
    [{ "Requirements.txt": "flask\n" }, ["flask"]],
  ];
  for (const [files, want] of cases) assert.deepEqual((await detect(files)).frameworks, want, JSON.stringify(files));
  assert.deepEqual((await detect({ "requirements/base.txt": "sentry-sdk\n" })).fingerprints.includes("error_tracking_sdk"), true);
});

// a skipped folder that could hold a manifest leaves frameworks unknown, as it already does fingerprints.
test("A skipped folder leaves frameworks unknown, not complete", async () => {
  const r = await detect({ "main.tf": "" }, [{ path: "apps/api", kind: "directory", reason: "unreadable", tracked: "yes" }]);
  assert.deepEqual([r.frameworks, r.fingerprints], [null, null]);
});
